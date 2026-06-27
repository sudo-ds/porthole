//! Tunnel client: maintains the control connection (with auto-reconnect), registers
//! tunnels, dials data connections on demand, and exposes shared state to the web UI.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use rand::Rng;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::cli::{ClientArgs, JoinArgs};
use crate::config::{self, save_client_file, ClientFile, ClientSettings, TunnelConfig};
use crate::invite;
use crate::protocol::{
    self, ClientMessage, Proto, ServerMessage, Wire, HEARTBEAT_INTERVAL, LIVENESS_TIMEOUT,
    NETWORK_TIMEOUT,
};
use crate::{net, tcp, tls, udp, web};

/// A client-side TLS stream over TCP.
pub type ClientTls = TlsStream<TcpStream>;

#[derive(Default)]
pub struct Counters {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub active: AtomicU32,
}

/// Live status for one tunnel (shared with the web UI).
pub struct TunnelStatus {
    pub proto: Proto,
    pub local_addr: SocketAddr,
    pub remote_port: Option<u16>,
    pub enabled: AtomicBool,
    pub public_addr: Mutex<Option<String>>,
    pub up: AtomicBool,
    /// Last rejection reason from the server, if any (shown in the web UI).
    pub error: Mutex<Option<String>>,
    pub counters: Arc<Counters>,
}

/// State shared between the control loop, data tasks, and the web UI.
pub struct ClientShared {
    pub server_addr: String,
    pub secret: String,
    pub connector: TlsConnector,
    pub server_name: ServerName<'static>,
    pub config_path: Option<PathBuf>,
    pub file: Mutex<ClientFile>,
    /// Sender into the current control connection's writer, if connected.
    pub out: Mutex<Option<mpsc::Sender<ClientMessage>>>,
    pub status: DashMap<String, TunnelStatus>,
    pub connected: AtomicBool,
    /// Allowed public-port range advertised by the server (0 = not yet known).
    pub min_port: AtomicU16,
    pub max_port: AtomicU16,
    pub started: Instant,
    pub shutdown: CancellationToken,
}

/// Mutations requested by the web UI, drained by the single command processor.
pub enum Command {
    Add(TunnelConfig),
    Remove(String),
    SetEnabled(String, bool),
}

pub async fn run(settings: ClientSettings) -> Result<()> {
    let shutdown = CancellationToken::new();
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown.cancel();
        });
    }
    run_with_shutdown(settings, shutdown).await
}

pub async fn run_with_shutdown(
    settings: ClientSettings,
    shutdown: CancellationToken,
) -> Result<()> {
    let connector = tls::client_connector(&settings.server_fingerprint)?;
    let server_name = tls::pinned_server_name();
    let web_bind = settings.web_bind.clone();

    let status: DashMap<String, TunnelStatus> = DashMap::new();
    for t in &settings.file.tunnels {
        status.insert(t.name.clone(), status_from(t));
    }

    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(64);

    let shared = Arc::new(ClientShared {
        server_addr: settings.server_addr.clone(),
        secret: settings.secret.clone(),
        connector,
        server_name,
        config_path: settings.config_path.clone(),
        file: Mutex::new(settings.file.clone()),
        out: Mutex::new(None),
        status,
        connected: AtomicBool::new(false),
        min_port: AtomicU16::new(0),
        max_port: AtomicU16::new(0),
        started: Instant::now(),
        shutdown,
    });

    tokio::spawn(command_processor(shared.clone(), cmd_rx));

    {
        let shared = shared.clone();
        let cmd_tx = cmd_tx.clone();
        let bind = web_bind.clone();
        tokio::spawn(async move {
            if let Err(e) = web::serve(shared, cmd_tx, bind).await {
                tracing::error!("web UI failed: {e:#}");
            }
        });
    }

    tracing::info!("porthole client: web UI at http://{web_bind}");
    if crate::tui::enabled() {
        let supervisor = shared.clone();
        tokio::spawn(async move { reconnect_supervisor(supervisor).await });
        crate::tui::run(shared).await;
    } else {
        reconnect_supervisor(shared).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI entry + onboarding (use a code, an existing config, or the setup wizard)
// ---------------------------------------------------------------------------

/// Entry point for `porthole client`.
pub async fn run_cli(args: ClientArgs) -> Result<()> {
    if let Some(code) = args.code.clone() {
        let settings = settings_from_code(&code, args.web_bind.clone())?;
        save_settings(&settings);
        return run(settings).await;
    }
    match config::load_client(&args) {
        Ok(settings) => run(settings).await,
        Err(_) => {
            let code = wizard_get_code()?;
            let settings = settings_from_code(&code, args.web_bind.clone())?;
            save_settings(&settings);
            run(settings).await
        }
    }
}

/// `porthole join <code>`: configure from a connection code and connect.
pub async fn join(args: JoinArgs) -> Result<()> {
    let settings = settings_from_code(&args.code, args.web_bind.clone())?;
    save_settings(&settings);
    run(settings).await
}

/// Turn a connection code into client settings, preserving any existing tunnels.
fn settings_from_code(code: &str, web_bind: Option<String>) -> Result<ClientSettings> {
    let info = invite::decode(code)?;
    let path = config::default_client_config_path();
    let mut file: ClientFile = if path.exists() {
        toml::from_str(&std::fs::read_to_string(&path).unwrap_or_default()).unwrap_or_default()
    } else {
        ClientFile::default()
    };
    file.server_addr = Some(info.server_addr());
    file.server_fingerprint = Some(info.fingerprint.clone());
    file.secret = Some(info.secret.clone());
    let web = web_bind
        .or_else(|| file.web_bind.clone())
        .unwrap_or_else(|| crate::protocol::DEFAULT_WEB_BIND.to_string());
    file.web_bind = Some(web.clone());

    Ok(ClientSettings {
        server_addr: info.server_addr(),
        server_fingerprint: info.fingerprint,
        web_bind: web,
        secret: info.secret,
        config_path: Some(path),
        file,
    })
}

fn save_settings(settings: &ClientSettings) {
    if let Some(path) = &settings.config_path {
        if let Err(e) = save_client_file(path, &settings.file) {
            tracing::warn!("couldn't save config: {e:#}");
        }
    }
}

fn wizard_get_code() -> Result<String> {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return Err(anyhow!(
            "not configured yet — run `porthole join <code>` with the connection code from the relay operator"
        ));
    }
    println!("\nLet's connect you to a porthole relay.");
    println!("Ask the operator for a connection code (it starts with `porthole1_`).\n");
    loop {
        print!("Paste your connection code: ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let code = line.trim().to_string();
        if code.is_empty() {
            continue;
        }
        match invite::decode(&code) {
            Ok(_) => return Ok(code),
            Err(e) => println!("  Hmm, that code doesn't look right ({e}). Try again.\n"),
        }
    }
}

fn status_from(t: &TunnelConfig) -> TunnelStatus {
    TunnelStatus {
        proto: t.protocol,
        local_addr: t.local_addr,
        remote_port: t.remote_port,
        enabled: AtomicBool::new(t.enabled),
        public_addr: Mutex::new(None),
        up: AtomicBool::new(false),
        error: Mutex::new(None),
        counters: Arc::new(Counters::default()),
    }
}

fn ensure_status(shared: &ClientShared, t: &TunnelConfig) {
    match shared.status.get(&t.name) {
        Some(s) => s.enabled.store(t.enabled, Relaxed),
        None => {
            shared.status.insert(t.name.clone(), status_from(t));
        }
    }
}

async fn reconnect_supervisor(shared: Arc<ClientShared>) {
    let max = Duration::from_secs(30);
    let mut backoff = Duration::from_secs(1);

    loop {
        if shared.shutdown.is_cancelled() {
            break;
        }
        let started = Instant::now();
        match connect_and_run(&shared).await {
            Ok(()) => tracing::info!("control connection closed"),
            Err(e) => tracing::warn!("control connection error: {e:#}"),
        }

        shared.connected.store(false, Relaxed);
        *shared.out.lock().unwrap() = None;
        for s in shared.status.iter() {
            s.up.store(false, Relaxed);
        }

        if shared.shutdown.is_cancelled() {
            break;
        }
        if started.elapsed() > Duration::from_secs(10) {
            backoff = Duration::from_secs(1); // it was a healthy connection
        }
        let jitter = Duration::from_millis(rand::thread_rng().gen_range(0..500));
        let wait = backoff + jitter;
        tracing::info!("reconnecting in {wait:?}");
        tokio::select! {
            _ = shared.shutdown.cancelled() => break,
            _ = tokio::time::sleep(wait) => {}
        }
        backoff = (backoff * 2).min(max);
    }
}

async fn connect_and_run(shared: &Arc<ClientShared>) -> Result<()> {
    tracing::info!("connecting to {}", shared.server_addr);
    let tcp = TcpStream::connect(&shared.server_addr)
        .await
        .with_context(|| {
            format!(
                "couldn't reach {} — check the address and that the relay is running",
                shared.server_addr
            )
        })?;
    net::set_keepalive(&tcp);
    let tls = shared
        .connector
        .connect(shared.server_name.clone(), tcp)
        .await
        .context(
            "TLS handshake failed — the server's certificate may not match your connection code",
        )?;
    let mut wire = protocol::wire(tls);

    protocol::send_msg(
        &mut wire,
        &ClientMessage::Hello {
            token: shared.secret.clone(),
        },
    )
    .await?;

    // The server replies with Welcome (the allowed port range) or an Error if auth fails.
    let welcome: ServerMessage = protocol::recv_msg_timeout(&mut wire, NETWORK_TIMEOUT).await?;
    match welcome {
        ServerMessage::Welcome { min_port, max_port } => {
            shared.min_port.store(min_port, Relaxed);
            shared.max_port.store(max_port, Relaxed);
            tracing::info!("connected (server allows public ports {min_port}-{max_port})");
        }
        ServerMessage::Error { message, .. } => {
            return Err(anyhow!("server refused the connection: {message}"));
        }
        other => return Err(anyhow!("unexpected handshake reply: {other:?}")),
    }
    shared.connected.store(true, Relaxed);

    let conn_cancel = shared.shutdown.child_token();
    let (sink, mut stream) = wire.split();
    let (out_tx, out_rx) = mpsc::channel::<ClientMessage>(128);
    *shared.out.lock().unwrap() = Some(out_tx.clone());

    spawn_writer(sink, out_rx, conn_cancel.clone());

    // Heartbeat.
    {
        let out_tx = out_tx.clone();
        let cancel = conn_cancel.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        if out_tx.send(ClientMessage::Heartbeat).await.is_err() { break; }
                    }
                }
            }
        });
    }

    // Register all enabled tunnels.
    let enabled: Vec<TunnelConfig> = shared
        .file
        .lock()
        .unwrap()
        .tunnels
        .iter()
        .filter(|t| t.enabled)
        .cloned()
        .collect();
    for t in &enabled {
        ensure_status(shared, t);
        let _ = out_tx
            .send(ClientMessage::Register {
                name: t.name.clone(),
                proto: t.protocol,
                remote_port: t.remote_port,
            })
            .await;
    }

    let outcome = loop {
        match tokio::time::timeout(LIVENESS_TIMEOUT, stream.next()).await {
            Err(_) => break Err(anyhow!("liveness timeout")),
            Ok(None) => break Ok(()),
            Ok(Some(Err(e))) => break Err(e.into()),
            Ok(Some(Ok(frame))) => match serde_json::from_slice::<ServerMessage>(&frame) {
                Ok(ServerMessage::Accepted {
                    name,
                    proto,
                    remote_port,
                    token,
                    ..
                }) => {
                    apply_accepted(shared, &conn_cancel, name, proto, remote_port, token);
                }
                Ok(ServerMessage::NewConn { id, tunnel }) => {
                    tokio::spawn(tcp::client_handle_conn(
                        shared.clone(),
                        id,
                        tunnel,
                        conn_cancel.clone(),
                    ));
                }
                Ok(ServerMessage::Rejected { name, reason }) => {
                    tracing::warn!("tunnel '{name}' rejected: {reason}");
                    if let Some(s) = shared.status.get(&name) {
                        *s.error.lock().unwrap() = Some(reason);
                        s.up.store(false, Relaxed);
                    }
                }
                Ok(ServerMessage::Welcome { .. }) => {}
                Ok(ServerMessage::Heartbeat) => {}
                Ok(ServerMessage::Error { message, fatal }) => {
                    tracing::warn!("server: {message}");
                    if fatal {
                        break Err(anyhow!(
                            "the relay refused the connection ({message}) — your code's secret may be wrong or revoked"
                        ));
                    }
                }
                Err(e) => break Err(e.into()),
            },
        }
    };

    conn_cancel.cancel();
    outcome
}

fn apply_accepted(
    shared: &Arc<ClientShared>,
    conn_cancel: &CancellationToken,
    name: String,
    proto: Proto,
    remote_port: u16,
    token: Option<Uuid>,
) {
    let public = format!("{}:{}", host_of(&shared.server_addr), remote_port);
    if let Some(s) = shared.status.get(&name) {
        *s.public_addr.lock().unwrap() = Some(public.clone());
        *s.error.lock().unwrap() = None;
        s.up.store(true, Relaxed);
    }
    tracing::info!("tunnel '{name}' ({proto}) is live at {public}");

    if proto == Proto::Udp {
        if let Some(token) = token {
            let (local, counters) = match shared.status.get(&name) {
                Some(s) => (s.local_addr, s.counters.clone()),
                None => return,
            };
            tokio::spawn(udp::client_channel(
                shared.clone(),
                name,
                local,
                token,
                counters,
                conn_cancel.clone(),
            ));
        }
    }
}

fn spawn_writer(
    mut sink: SplitSink<Wire<ClientTls>, Bytes>,
    mut out_rx: mpsc::Receiver<ClientMessage>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                msg = out_rx.recv() => {
                    let Some(msg) = msg else { break };
                    match serde_json::to_vec(&msg) {
                        Ok(bytes) => {
                            if sink.send(Bytes::from(bytes)).await.is_err() { break; }
                        }
                        Err(e) => tracing::error!("serialize: {e}"),
                    }
                }
            }
        }
        let _ = sink.close().await;
    });
}

/// Open a data connection identified by `id` (a TCP conn id or a UDP tunnel token).
pub async fn connect_data_wire(shared: &ClientShared, id: Uuid) -> Result<Wire<ClientTls>> {
    let tcp = TcpStream::connect(&shared.server_addr).await?;
    net::set_keepalive(&tcp);
    let tls = shared
        .connector
        .connect(shared.server_name.clone(), tcp)
        .await?;
    let mut wire = protocol::wire(tls);
    protocol::send_msg(
        &mut wire,
        &ClientMessage::DataHello {
            token: shared.secret.clone(),
            id,
        },
    )
    .await?;
    Ok(wire)
}

// ---------------------------------------------------------------------------
// Web command processing (the single owner of config write-back)
// ---------------------------------------------------------------------------

async fn command_processor(shared: Arc<ClientShared>, mut cmd_rx: mpsc::Receiver<Command>) {
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            Command::Add(t) => {
                ensure_status(&shared, &t);
                {
                    let mut f = shared.file.lock().unwrap();
                    f.tunnels.retain(|x| x.name != t.name);
                    f.tunnels.push(t.clone());
                    persist(&shared, &f);
                }
                if t.enabled {
                    send_if_connected(
                        &shared,
                        ClientMessage::Register {
                            name: t.name.clone(),
                            proto: t.protocol,
                            remote_port: t.remote_port,
                        },
                    )
                    .await;
                }
                tracing::info!("added tunnel '{}'", t.name);
            }
            Command::Remove(name) => {
                {
                    let mut f = shared.file.lock().unwrap();
                    f.tunnels.retain(|x| x.name != name);
                    persist(&shared, &f);
                }
                shared.status.remove(&name);
                send_if_connected(&shared, ClientMessage::Unregister { name: name.clone() }).await;
                tracing::info!("removed tunnel '{name}'");
            }
            Command::SetEnabled(name, enabled) => {
                let found = {
                    let mut f = shared.file.lock().unwrap();
                    let found = f.tunnels.iter_mut().find(|t| t.name == name).map(|t| {
                        t.enabled = enabled;
                        t.clone()
                    });
                    persist(&shared, &f);
                    found
                };
                if let Some(t) = found {
                    ensure_status(&shared, &t);
                    if enabled {
                        send_if_connected(
                            &shared,
                            ClientMessage::Register {
                                name: name.clone(),
                                proto: t.protocol,
                                remote_port: t.remote_port,
                            },
                        )
                        .await;
                    } else {
                        if let Some(s) = shared.status.get(&name) {
                            s.up.store(false, Relaxed);
                        }
                        send_if_connected(&shared, ClientMessage::Unregister { name }).await;
                    }
                }
            }
        }
    }
}

async fn send_if_connected(shared: &Arc<ClientShared>, msg: ClientMessage) {
    let out = shared.out.lock().unwrap().clone();
    if let Some(out) = out {
        let _ = out.send(msg).await;
    }
}

fn persist(shared: &ClientShared, file: &ClientFile) {
    if let Some(path) = &shared.config_path {
        if let Err(e) = save_client_file(path, file) {
            tracing::warn!("persisting config: {e:#}");
        }
    }
}

fn host_of(addr: &str) -> &str {
    match addr.rfind(':') {
        Some(i) => &addr[..i],
        None => addr,
    }
}
