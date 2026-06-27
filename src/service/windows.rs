use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use tokio_util::sync::CancellationToken;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use crate::cli::{
    ClientArgs, ServerArgs, ServiceInstallArgs, ServiceKind, ServiceRunArgs, ServiceUninstallArgs,
};
use crate::{client, config, server};

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;

static RUN_ARGS: OnceLock<ServiceRunArgs> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub fn install(args: ServiceInstallArgs) -> Result<()> {
    let service_name = args
        .name
        .unwrap_or_else(|| default_service_name(args.kind).to_string());
    let display_name = args
        .display_name
        .unwrap_or_else(|| default_display_name(args.kind).to_string());
    let executable_path = std::env::current_exe().context("finding current executable")?;
    let working_dir = resolve_working_dir(args.working_dir)?;
    std::fs::create_dir_all(&working_dir)
        .with_context(|| format!("creating {}", working_dir.display()))?;

    let config_path = match args.config {
        Some(path) => absolutize(path).context("resolving config path")?,
        None => working_dir.join(default_config_file(args.kind)),
    };
    if args.start && !config_path.exists() {
        bail!(
            "can't start the service yet because {} does not exist",
            config_path.display()
        );
    }

    let launch_arguments = vec![
        OsString::from("service"),
        OsString::from("run"),
        OsString::from("--name"),
        OsString::from(&service_name),
        OsString::from("--kind"),
        OsString::from(kind_arg(args.kind)),
        OsString::from("--config"),
        config_path.as_os_str().to_os_string(),
        OsString::from("--working-dir"),
        working_dir.as_os_str().to_os_string(),
    ];

    let service_info = ServiceInfo {
        name: OsString::from(&service_name),
        display_name: OsString::from(&display_name),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable_path.clone(),
        launch_arguments,
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access).context(
        "opening the Windows Service Control Manager; run this from an Administrator shell",
    )?;
    let service = service_manager
        .create_service(
            &service_info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_STATUS | ServiceAccess::START,
        )
        .with_context(|| format!("creating Windows service '{service_name}'"))?;
    service
        .set_description(service_description(args.kind))
        .with_context(|| format!("setting description for Windows service '{service_name}'"))?;

    println!("Installed Windows service '{service_name}'.");
    println!("  display name : {display_name}");
    println!("  executable   : {}", executable_path.display());
    println!("  working dir  : {}", working_dir.display());
    println!("  config       : {}", config_path.display());
    println!("  startup      : automatic");
    if !config_path.exists() {
        println!(
            "  note         : config file does not exist yet; create it before starting the service"
        );
    }

    if args.start {
        service
            .start(&[] as &[&str])
            .with_context(|| format!("starting Windows service '{service_name}'"))?;
        println!("Started Windows service '{service_name}'.");
    } else {
        println!("Start it with: net start {service_name}");
    }

    Ok(())
}

pub fn uninstall(args: ServiceUninstallArgs) -> Result<()> {
    let service_name = args
        .name
        .unwrap_or_else(|| default_service_name(args.kind).to_string());
    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).context(
            "opening the Windows Service Control Manager; run this from an Administrator shell",
        )?;
    let service = service_manager
        .open_service(
            &service_name,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .with_context(|| format!("opening Windows service '{service_name}'"))?;

    service
        .delete()
        .with_context(|| format!("marking Windows service '{service_name}' for deletion"))?;

    if service.query_status()?.current_state != ServiceState::Stopped {
        match service.stop() {
            Ok(_) => {}
            Err(windows_service::Error::Winapi(e))
                if e.raw_os_error() == Some(ERROR_SERVICE_NOT_ACTIVE) => {}
            Err(e) => return Err(e).with_context(|| format!("stopping '{service_name}'")),
        }
    }
    drop(service);

    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        match service_manager.open_service(&service_name, ServiceAccess::QUERY_STATUS) {
            Err(windows_service::Error::Winapi(e))
                if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) =>
            {
                println!("Uninstalled Windows service '{service_name}'.");
                return Ok(());
            }
            _ => sleep(Duration::from_millis(500)),
        }
    }

    println!(
        "Windows service '{service_name}' is marked for deletion and will disappear once Windows releases it."
    );
    Ok(())
}

pub fn run(args: ServiceRunArgs) -> Result<()> {
    let service_name = args.name.clone();
    RUN_ARGS
        .set(args)
        .map_err(|_| anyhow!("Windows service runtime was already initialized"))?;
    service_dispatcher::start(service_name, ffi_service_main)
        .context("starting Windows service dispatcher")
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("porthole Windows service failed: {e:#}");
    }
}

fn run_service() -> Result<()> {
    let args = RUN_ARGS
        .get()
        .context("Windows service runtime arguments were not initialized")?
        .clone();

    std::env::set_current_dir(&args.working_dir).with_context(|| {
        format!(
            "setting working directory to {}",
            args.working_dir.display()
        )
    })?;

    let shutdown = CancellationToken::new();
    let handler_shutdown = shutdown.clone();
    let status_slot = Arc::new(Mutex::new(None::<ServiceStatusHandle>));
    let handler_status = status_slot.clone();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(status_handle) = *handler_status.lock().unwrap() {
                    let _ = status_handle.set_service_status(service_status(
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                        ServiceExitCode::NO_ERROR,
                    ));
                }
                handler_shutdown.cancel();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(&args.name, event_handler)
        .with_context(|| format!("registering Windows service handler '{}'", args.name))?;
    *status_slot.lock().unwrap() = Some(status_handle);

    status_handle.set_service_status(service_status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::NO_ERROR,
    ))?;

    let result = run_target(args, shutdown);
    let exit_code = if result.is_ok() {
        ServiceExitCode::NO_ERROR
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    status_handle.set_service_status(service_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
    ))?;
    result
}

fn run_target(args: ServiceRunArgs, shutdown: CancellationToken) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting Tokio runtime for Windows service")?;

    runtime.block_on(async move {
        match args.kind {
            ServiceKind::Server => {
                let settings = config::load_server(&server_args(args.config))?;
                server::run_with_shutdown(settings, shutdown).await
            }
            ServiceKind::Client => {
                let settings = config::load_client(&client_args(args.config))?;
                client::run_with_shutdown(settings, shutdown).await
            }
        }
    })
}

fn service_status(
    state: ServiceState,
    controls: ServiceControlAccept,
    exit_code: ServiceExitCode,
) -> ServiceStatus {
    let pending = matches!(
        state,
        ServiceState::StartPending | ServiceState::StopPending
    );
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: controls,
        exit_code,
        checkpoint: u32::from(pending),
        wait_hint: if pending {
            Duration::from_secs(10)
        } else {
            Duration::default()
        },
        process_id: None,
    }
}

fn server_args(config_path: PathBuf) -> ServerArgs {
    ServerArgs {
        config: Some(config_path),
        bind: None,
        control_port: None,
        min_port: None,
        max_port: None,
        secret_file: None,
        cert_path: None,
        key_path: None,
        public_host: None,
        show_invite: false,
    }
}

fn client_args(config_path: PathBuf) -> ClientArgs {
    ClientArgs {
        config: Some(config_path),
        code: None,
        server: None,
        fingerprint: None,
        web_bind: None,
        secret_file: None,
        tunnels: Vec::new(),
    }
}

fn resolve_working_dir(path: Option<PathBuf>) -> Result<PathBuf> {
    match path {
        Some(path) => absolutize(path),
        None => std::env::current_exe()
            .context("finding current executable")?
            .parent()
            .map(Path::to_path_buf)
            .context("current executable has no parent directory"),
    }
}

fn absolutize(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()
            .context("finding current directory")?
            .join(path))
    }
}

fn default_service_name(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::Server => "porthole-server",
        ServiceKind::Client => "porthole-client",
    }
}

fn default_display_name(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::Server => "Porthole Server",
        ServiceKind::Client => "Porthole Client",
    }
}

fn service_description(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::Server => "Porthole relay server",
        ServiceKind::Client => "Porthole tunnel client",
    }
}

fn default_config_file(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::Server => "porthole-server.toml",
        ServiceKind::Client => "porthole-client.toml",
    }
}

fn kind_arg(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::Server => "server",
        ServiceKind::Client => "client",
    }
}
