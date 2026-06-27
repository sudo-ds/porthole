//! Process logging setup: console/dashboard output plus optional daily rotating files.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling::{Builder, Rotation};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Layer};

use crate::cli::{Cli, Command, ServiceCommand, ServiceKind};
use crate::config::{self, LogMode, LoggingConfig};
use crate::tui;

pub struct LoggingGuard {
    _file_guard: Option<WorkerGuard>,
}

#[derive(Clone, Copy)]
enum ProcessKind {
    Server,
    Client,
}

impl ProcessKind {
    fn file_prefix(self) -> &'static str {
        match self {
            Self::Server => "porthole-server",
            Self::Client => "porthole-client",
        }
    }
}

/// Initialize logging for ordinary CLI entrypoints.
///
/// Hidden Windows service runs initialize logging inside the service runtime instead, because
/// their working directory comes from the service launch arguments.
pub fn init_cli(cli: &Cli, dashboard: bool) -> Result<Option<LoggingGuard>> {
    let Some((kind, config_path)) = cli_logging_target(cli) else {
        return Ok(None);
    };
    let config = config::load_logging(config_path.as_deref())?;
    init(
        kind,
        config,
        cli.verbose,
        dashboard,
        &std::env::current_dir().context("finding current directory")?,
    )
    .map(Some)
}

#[cfg(windows)]
pub fn init_service(
    kind: ServiceKind,
    config_path: &Path,
    working_dir: &Path,
) -> Result<LoggingGuard> {
    let config = config::load_logging(Some(config_path))?;
    init(
        match kind {
            ServiceKind::Server => ProcessKind::Server,
            ServiceKind::Client => ProcessKind::Client,
        },
        config,
        0,
        false,
        working_dir,
    )
}

fn init(
    kind: ProcessKind,
    config: LoggingConfig,
    verbose: u8,
    dashboard: bool,
    working_dir: &Path,
) -> Result<LoggingGuard> {
    let filter = filter_for(
        verbose,
        std::env::var("RUST_LOG").ok().filter(|v| !v.is_empty()),
        &config.level,
    )?;

    let (file_writer, file_guard) = if config.mode.file_enabled() {
        let directory = resolve_directory(&config, working_dir);
        std::fs::create_dir_all(&directory)
            .with_context(|| format!("creating {}", directory.display()))?;
        let mut builder = Builder::new()
            .rotation(Rotation::DAILY)
            .filename_prefix(kind.file_prefix())
            .filename_suffix("log");
        if config.max_files > 0 {
            builder = builder.max_log_files(config.max_files);
        }
        let appender = builder
            .build(&directory)
            .with_context(|| format!("opening rotating logs in {}", directory.display()))?;
        let (writer, guard) = tracing_appender::non_blocking(appender);
        (Some(writer), Some(guard))
    } else {
        (None, None)
    };
    let guard = LoggingGuard {
        _file_guard: file_guard,
    };

    install_subscriber(filter, config.mode, dashboard, file_writer)?;
    Ok(guard)
}

fn install_subscriber(
    filter: EnvFilter,
    mode: LogMode,
    dashboard: bool,
    file_writer: Option<NonBlocking>,
) -> Result<()> {
    let registry = tracing_subscriber::registry().with(filter);
    match (mode.console_enabled(), file_writer, dashboard) {
        (false, None, _) => registry.try_init(),
        (false, Some(file), _) => registry.with(file_layer(file)).try_init(),
        (true, None, true) => registry.with(dashboard_layer()).try_init(),
        (true, None, false) => registry.with(console_layer()).try_init(),
        (true, Some(file), true) => registry
            .with(dashboard_layer())
            .with(file_layer(file))
            .try_init(),
        (true, Some(file), false) => registry
            .with(console_layer())
            .with(file_layer(file))
            .try_init(),
    }
    .context("initializing logging")
}

fn console_layer<S>() -> impl Layer<S>
where
    S: tracing::Subscriber,
    S: for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(ConsoleMakeWriter::Stdout)
}

fn dashboard_layer<S>() -> impl Layer<S>
where
    S: tracing::Subscriber,
    S: for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .without_time()
        .with_writer(ConsoleMakeWriter::Dashboard(tui::make_writer()))
}

fn file_layer<S>(writer: NonBlocking) -> impl Layer<S>
where
    S: tracing::Subscriber,
    S: for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .with_writer(writer)
}

fn cli_logging_target(cli: &Cli) -> Option<(ProcessKind, Option<PathBuf>)> {
    match &cli.command {
        Command::Server(args) => Some((
            ProcessKind::Server,
            existing_config_path(args.config.clone(), config::default_server_config_path),
        )),
        Command::Client(args) => {
            let path = if args.code.is_some() {
                default_if_exists(config::default_client_config_path)
            } else {
                existing_config_path(args.config.clone(), config::default_client_config_path)
            };
            Some((ProcessKind::Client, path))
        }
        Command::Join(_) => Some((
            ProcessKind::Client,
            default_if_exists(config::default_client_config_path),
        )),
        Command::Service(args) => match args.command {
            ServiceCommand::Run(_) => None,
            ServiceCommand::Install(_) | ServiceCommand::Uninstall(_) => None,
        },
        Command::GenToken => None,
    }
}

fn existing_config_path(
    explicit: Option<PathBuf>,
    default_path: impl FnOnce() -> PathBuf,
) -> Option<PathBuf> {
    explicit.or_else(|| default_if_exists(default_path))
}

fn default_if_exists(default_path: impl FnOnce() -> PathBuf) -> Option<PathBuf> {
    let path = default_path();
    path.exists().then_some(path)
}

pub fn resolve_directory(config: &LoggingConfig, working_dir: &Path) -> PathBuf {
    if config.directory.is_absolute() {
        config.directory.clone()
    } else {
        working_dir.join(&config.directory)
    }
}

fn filter_for(verbose: u8, rust_log: Option<String>, config_level: &str) -> Result<EnvFilter> {
    match verbose {
        0 => {
            if let Some(value) = rust_log {
                EnvFilter::try_new(value).context("parsing RUST_LOG")
            } else {
                EnvFilter::try_new(config_level).context("parsing logging.level")
            }
        }
        1 => EnvFilter::try_new("porthole=debug,info").context("building debug log filter"),
        _ => EnvFilter::try_new("porthole=trace,debug").context("building trace log filter"),
    }
}

#[derive(Clone)]
enum ConsoleMakeWriter {
    Dashboard(tui::LogWriter),
    Stdout,
}

enum ConsoleWriter {
    Dashboard(tui::LogWriter),
    Stdout(io::Stdout),
}

impl Write for ConsoleWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Dashboard(writer) => writer.write(buf),
            Self::Stdout(writer) => writer.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Dashboard(writer) => writer.flush(),
            Self::Stdout(writer) => writer.flush(),
        }
    }
}

impl<'a> MakeWriter<'a> for ConsoleMakeWriter {
    type Writer = ConsoleWriter;

    fn make_writer(&'a self) -> Self::Writer {
        match self {
            Self::Dashboard(writer) => ConsoleWriter::Dashboard(writer.clone()),
            Self::Stdout => ConsoleWriter::Stdout(io::stdout()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_directory_resolves_under_working_dir() {
        let config = LoggingConfig::default();
        let base = std::env::temp_dir().join("porthole-logging-base");
        assert_eq!(resolve_directory(&config, &base), base.join("Logs"));
    }

    #[test]
    fn absolute_directory_is_used_as_is() {
        let directory = std::env::temp_dir().join("porthole-logging-absolute");
        let config = LoggingConfig {
            directory: directory.clone(),
            ..Default::default()
        };
        assert_eq!(resolve_directory(&config, Path::new("ignored")), directory);
    }

    #[test]
    fn invalid_config_level_is_rejected() {
        assert!(filter_for(0, None, "porthole[").is_err());
    }

    #[test]
    fn rust_log_overrides_invalid_config_level() {
        assert!(filter_for(0, Some("info".into()), "porthole[").is_ok());
    }

    #[test]
    fn verbose_overrides_invalid_rust_log_and_config_level() {
        assert!(filter_for(1, Some("porthole[".into()), "porthole[").is_ok());
    }
}
