//! Relay server: accepts TLS connections on one ingress port, authenticates them, and
//! demultiplexes control connections (which register tunnels) from data connections
//! (which fulfil a pending TCP accept or carry a UDP tunnel's datagrams).

use std::io::{IsTerminal, Write as _};
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::cli::ServerArgs;
use crate::config::{self, ServerFile, ServerSettings};
use crate::invite::{self, ConnectionInfo};
use crate::protocol::{
    self, ClientMessage, Proto, ServerMessage, Wire, HEARTBEAT_INTERVAL, LIVENESS_TIMEOUT,
    NETWORK_TIMEOUT,
};
use crate::tcp::{self, PendingMap};
use crate::{auth, net, tls, udp};

/// A server-side TLS stream over TCP.
pub type ServerTls = tokio_rustls::server::TlsStream<TcpStream>;

/// A public tunnel currently bound on the server, keyed by its public port.
struct TunnelHandle {
    name: String,
    session: Uuid,
    cancel: CancellationToken,
}

/// A registered UDP tunnel waiting for its client to open the data channel.
struct PendingUdp {
    socket: Arc<UdpSocket>,
    port: u16,
    session: Uuid,
    cancel: CancellationToken,
}

/// Per-control-connection bookkeeping, used to free resources on disconnect.
struct Session {
    id: Uuid,
    cancel: CancellationToken,
    control_tx: mpsc::Sender<ServerMessage>,
    ports: Vec<u16>,
    udp_tokens: Vec<Uuid>,
}

#[derive(Clone)]
struct Server {
    settings: Arc<ServerSettings>,
    acceptor: TlsAcceptor,
    pending: PendingMap,
    tunnels: Arc<DashMap<u16, TunnelHandle>>,
    udp_pending: Arc<DashMap<Uuid, PendingUdp>>,
}

pub async fn run(settings: ServerSettings) -> Result<()> {
    let shutdown = CancellationToken::new();
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
            shutdown.cancel();
        });
    }
    run_with_shutdown(settings, shutdown).await
}

pub async fn run_with_shutdown(
    settings: ServerSettings,
    shutdown: CancellationToken,
) -> Result<()> {
    let (acceptor, fingerprint) = tls::server_acceptor(&settings)?;
    let ingress = settings.ingress_addr()?;

    let server = Server {
        settings: Arc::new(settings),
        acceptor,
        pending: Arc::new(DashMap::new()),
        tunnels: Arc::new(DashMap::new()),
        udp_pending: Arc::new(DashMap::new()),
    };

    let listener = TcpListener::bind(ingress)
        .await
        .with_context(|| format!("binding ingress {ingress}"))?;

    tracing::info!("porthole server listening on {ingress}");
    tracing::info!(
        "public ports {}-{}",
        server.settings.min_port,
        server.settings.max_port
    );
    tracing::info!("server certificate fingerprint (pin this on the client):");
    tracing::info!("    server_fingerprint = \"{fingerprint}\"");
    tracing::info!("get a shareable connection code with: porthole server --show-invite");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(x) => x,
                    Err(e) => { tracing::warn!("accept error: {e}"); continue; }
                };
                let server = server.clone();
                tokio::spawn(async move {
                    if let Err(e) = server.handle_inbound(stream, peer).await {
                        tracing::debug!("connection {peer} ended: {e:#}");
                    }
                });
            }
        }
    }
    Ok(())
}

impl Server {
    async fn handle_inbound(&self, tcp: TcpStream, peer: SocketAddr) -> Result<()> {
        net::set_keepalive(&tcp);
        let mut first = [0u8; 1];
        let n = tokio::time::timeout(NETWORK_TIMEOUT, tcp.peek(&mut first))
            .await
            .context("timed out waiting for first byte")??;
        if n == 0 {
            bail!("connection closed before first byte from {peer}");
        }
        if first[0] != 0x16 {
            return self.handle_plain_data_conn(tcp, peer).await;
        }

        self.handle_tls_inbound(tcp, peer).await
    }

    async fn handle_tls_inbound(&self, tcp: TcpStream, peer: SocketAddr) -> Result<()> {
        // Bound the TLS handshake: a peer that completes the TCP connect but stalls the
        // handshake would otherwise park this task indefinitely (slowloris-style).
        let tls = tokio::time::timeout(NETWORK_TIMEOUT, self.acceptor.accept(tcp))
            .await
            .context("tls handshake timed out")?
            .context("tls handshake failed")?;
        let mut wire = protocol::wire(tls);

        let first: ClientMessage = protocol::recv_msg_timeout(&mut wire, NETWORK_TIMEOUT)
            .await
            .context("reading handshake frame")?;

        match first {
            ClientMessage::Hello { token } => {
                if !auth::verify_token(&self.settings.secret, &token) {
                    let _ = protocol::send_msg(&mut wire, &auth_error()).await;
                    bail!("authentication failed (control) from {peer}");
                }
                self.handle_control(wire, peer).await
            }
            ClientMessage::DataHello { token, id, .. } => {
                if !auth::verify_token(&self.settings.secret, token.as_deref().unwrap_or_default())
                {
                    let _ = protocol::send_msg(&mut wire, &auth_error()).await;
                    bail!("authentication failed (data) from {peer}");
                }
                self.handle_tls_data_conn(wire, id).await
            }
            _ => bail!("unexpected first frame from {peer}"),
        }
    }

    async fn handle_plain_data_conn(&self, tcp: TcpStream, peer: SocketAddr) -> Result<()> {
        let mut wire = protocol::wire(tcp);
        let first: ClientMessage = protocol::recv_msg_timeout(&mut wire, NETWORK_TIMEOUT)
            .await
            .context("reading plaintext data handshake frame")?;
        let ClientMessage::DataHello {
            token,
            id,
            data_auth,
        } = first
        else {
            bail!("plaintext connection from {peer} did not start with DataHello");
        };
        if token.is_some() {
            bail!("plaintext data connection from {peer} included shared-token auth");
        }
        let data_auth = data_auth.context("plaintext data connection missing data_auth")?;

        let Some(entry) = self.pending.get(&id) else {
            bail!("plaintext data connection for unknown/expired id {id}");
        };
        let encrypted = entry.encrypted;
        let auth_ok = auth::verify_token(&entry.data_auth, &data_auth);
        drop(entry);

        if encrypted {
            bail!("plaintext data connection for encrypted id {id}");
        }
        if !auth_ok {
            bail!("plaintext data authentication failed for id {id}");
        }

        if let Some((_, pending)) = self.pending.remove(&id) {
            let raw: tcp::BoxedRelayIo = Box::new(protocol::into_raw(wire));
            let _ = pending.tx.send(raw);
        }
        Ok(())
    }

    /// A TLS data connection: route it to the waiting TCP accept or the UDP tunnel by id.
    async fn handle_tls_data_conn(&self, wire: Wire<ServerTls>, id: Uuid) -> Result<()> {
        if let Some(entry) = self.pending.get(&id) {
            let encrypted = entry.encrypted;
            drop(entry);
            if !encrypted {
                tracing::debug!("TLS data connection for plaintext id {id}");
                return Ok(());
            }
            if let Some((_, pending)) = self.pending.remove(&id) {
                let raw: tcp::BoxedRelayIo = Box::new(protocol::into_raw(wire));
                let _ = pending.tx.send(raw);
            }
            return Ok(());
        }
        if let Some((_, pending)) = self.udp_pending.remove(&id) {
            let PendingUdp {
                socket,
                port,
                session,
                cancel,
            } = pending;
            let result = udp::server_forward(wire, socket.clone(), cancel.clone()).await;
            // The data connection ended. If the tunnel is still alive (control up and the
            // tunnel not unregistered), keep its public socket bound and the token valid so
            // the client can re-dial the channel instead of losing the tunnel.
            if !cancel.is_cancelled() {
                self.udp_pending.insert(
                    id,
                    PendingUdp {
                        socket,
                        port,
                        session,
                        cancel,
                    },
                );
            }
            return result;
        }
        tracing::debug!("data connection for unknown/expired id {id}");
        Ok(())
    }

    /// A control connection: register tunnels and relay notifications until it drops.
    async fn handle_control(&self, mut wire: Wire<ServerTls>, peer: SocketAddr) -> Result<()> {
        // Advertise the allowed public-port range so the client can validate requests.
        protocol::send_msg(
            &mut wire,
            &ServerMessage::Welcome {
                min_port: self.settings.min_port,
                max_port: self.settings.max_port,
            },
        )
        .await?;

        let session_id = Uuid::new_v4();
        let cancel = CancellationToken::new();
        let (mut sink, mut stream) = wire.split();
        let (tx, mut rx) = mpsc::channel::<ServerMessage>(128);

        // Writer task: the only writer of the control connection.
        let writer_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = writer_cancel.cancelled() => break,
                    msg = rx.recv() => {
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

        // Heartbeat task.
        let hb_tx = tx.clone();
        let hb_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
            loop {
                tokio::select! {
                    _ = hb_cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        if hb_tx.send(ServerMessage::Heartbeat).await.is_err() { break; }
                    }
                }
            }
        });

        tracing::info!("client {peer} connected (session {session_id})");
        let mut session = Session {
            id: session_id,
            cancel: cancel.clone(),
            control_tx: tx,
            ports: Vec::new(),
            udp_tokens: Vec::new(),
        };

        let outcome = loop {
            match tokio::time::timeout(LIVENESS_TIMEOUT, stream.next()).await {
                Err(_) => break Err(anyhow!("liveness timeout")),
                Ok(None) => break Ok(()),
                Ok(Some(Err(e))) => break Err(anyhow::Error::from(e)),
                Ok(Some(Ok(frame))) => match serde_json::from_slice::<ClientMessage>(&frame) {
                    Ok(ClientMessage::Register {
                        name,
                        proto,
                        remote_port,
                        encrypted,
                        udp_mtu,
                    }) => {
                        self.register(&mut session, name, proto, remote_port, encrypted, udp_mtu)
                            .await;
                    }
                    Ok(ClientMessage::Unregister { name }) => self.unregister(&mut session, &name),
                    Ok(ClientMessage::Heartbeat) => {}
                    Ok(_) => {
                        break Err(anyhow!("unexpected handshake frame on control connection"))
                    }
                    Err(e) => break Err(e.into()),
                },
            }
        };

        self.cleanup_session(&session);
        cancel.cancel();
        tracing::info!("client {peer} disconnected (session {session_id})");
        outcome
    }

    async fn register(
        &self,
        session: &mut Session,
        name: String,
        proto: Proto,
        remote_port: Option<u16>,
        encrypted: bool,
        udp_mtu: Option<u16>,
    ) {
        let tx = session.control_tx.clone();
        if let Err(e) = config::validate_udp_mtu(proto, udp_mtu) {
            let _ = tx
                .send(ServerMessage::Rejected {
                    name,
                    reason: e.to_string(),
                })
                .await;
            return;
        }
        let resolved_udp_mtu = config::resolved_udp_mtu(proto, udp_mtu);

        let candidates: Vec<u16> = match remote_port {
            Some(p) => {
                if !self.settings.port_allowed(p) {
                    let _ = tx
                        .send(ServerMessage::Rejected {
                            name,
                            reason: format!(
                                "port {p} is outside the allowed range {}-{}",
                                self.settings.min_port, self.settings.max_port
                            ),
                        })
                        .await;
                    return;
                }
                vec![p]
            }
            None => (self.settings.min_port..=self.settings.max_port).collect(),
        };

        for port in candidates {
            let cancel = session.cancel.child_token();
            let handle = TunnelHandle {
                name: name.clone(),
                session: session.id,
                cancel: cancel.clone(),
            };
            // Reserve the port atomically (drop the entry guard before any await).
            match self.tunnels.entry(port) {
                Entry::Occupied(_) => continue,
                Entry::Vacant(v) => {
                    v.insert(handle);
                }
            }

            let addr: SocketAddr = match format!("{}:{}", self.settings.bind_addr, port).parse() {
                Ok(a) => a,
                Err(_) => {
                    self.tunnels.remove(&port);
                    continue;
                }
            };
            let public_addr = format!("{}:{}", self.settings.bind_addr, port);

            match proto {
                Proto::Tcp => match net::bind_tcp(addr) {
                    Ok(listener) => {
                        tokio::spawn(tcp::server_listener(
                            listener,
                            name.clone(),
                            encrypted,
                            tx.clone(),
                            self.pending.clone(),
                            cancel,
                        ));
                        session.ports.push(port);
                        tracing::info!("tunnel '{name}' (tcp) -> public port {port}");
                        let _ = tx
                            .send(ServerMessage::Accepted {
                                name,
                                proto,
                                public_addr,
                                remote_port: port,
                                encrypted,
                                token: None,
                                udp_auth_key: None,
                                udp_mtu: None,
                            })
                            .await;
                        return;
                    }
                    Err(e) => {
                        self.tunnels.remove(&port);
                        tracing::debug!("bind tcp {addr}: {e}");
                        continue;
                    }
                },
                Proto::Udp => match net::bind_udp(addr) {
                    Ok(socket) => {
                        let token = Uuid::new_v4();
                        let socket = Arc::new(socket);
                        let udp_auth_key = if encrypted {
                            self.udp_pending.insert(
                                token,
                                PendingUdp {
                                    socket: socket.clone(),
                                    port,
                                    session: session.id,
                                    cancel,
                                },
                            );
                            None
                        } else {
                            let mut key = [0u8; 32];
                            rand::thread_rng().fill_bytes(&mut key);
                            tokio::spawn(udp::server_plain_forward(
                                socket.clone(),
                                token,
                                key,
                                resolved_udp_mtu.unwrap_or(protocol::DEFAULT_UDP_MTU),
                                cancel,
                            ));
                            Some(protocol::encode_udp_auth_key(&key))
                        };
                        session.ports.push(port);
                        if encrypted {
                            session.udp_tokens.push(token);
                        }
                        tracing::info!("tunnel '{name}' (udp) -> public port {port}");
                        let _ = tx
                            .send(ServerMessage::Accepted {
                                name,
                                proto,
                                public_addr,
                                remote_port: port,
                                encrypted,
                                token: Some(token),
                                udp_auth_key,
                                udp_mtu: resolved_udp_mtu,
                            })
                            .await;
                        return;
                    }
                    Err(e) => {
                        self.tunnels.remove(&port);
                        tracing::debug!("bind udp {addr}: {e}");
                        continue;
                    }
                },
                Proto::Both => {
                    let listener = match net::bind_tcp(addr) {
                        Ok(listener) => listener,
                        Err(e) => {
                            self.tunnels.remove(&port);
                            cancel.cancel();
                            tracing::debug!("bind tcp {addr}: {e}");
                            continue;
                        }
                    };
                    let socket = match net::bind_udp(addr) {
                        Ok(socket) => Arc::new(socket),
                        Err(e) => {
                            self.tunnels.remove(&port);
                            cancel.cancel();
                            tracing::debug!("bind udp {addr}: {e}");
                            continue;
                        }
                    };

                    let token = Uuid::new_v4();
                    let udp_auth_key = if encrypted {
                        self.udp_pending.insert(
                            token,
                            PendingUdp {
                                socket: socket.clone(),
                                port,
                                session: session.id,
                                cancel: cancel.clone(),
                            },
                        );
                        None
                    } else {
                        let mut key = [0u8; 32];
                        rand::thread_rng().fill_bytes(&mut key);
                        tokio::spawn(udp::server_plain_forward(
                            socket.clone(),
                            token,
                            key,
                            resolved_udp_mtu.unwrap_or(protocol::DEFAULT_UDP_MTU),
                            cancel.clone(),
                        ));
                        Some(protocol::encode_udp_auth_key(&key))
                    };

                    tokio::spawn(tcp::server_listener(
                        listener,
                        name.clone(),
                        encrypted,
                        tx.clone(),
                        self.pending.clone(),
                        cancel.clone(),
                    ));
                    session.ports.push(port);
                    if encrypted {
                        session.udp_tokens.push(token);
                    }
                    tracing::info!("tunnel '{name}' (both) -> public port {port}");
                    let _ = tx
                        .send(ServerMessage::Accepted {
                            name,
                            proto,
                            public_addr,
                            remote_port: port,
                            encrypted,
                            token: Some(token),
                            udp_auth_key,
                            udp_mtu: resolved_udp_mtu,
                        })
                        .await;
                    return;
                }
            }
        }

        let _ = tx
            .send(ServerMessage::Rejected {
                name: name.clone(),
                reason: format!("no public port available for tunnel '{name}'"),
            })
            .await;
    }

    fn unregister(&self, session: &mut Session, name: &str) {
        let ports: Vec<u16> = self
            .tunnels
            .iter()
            .filter(|e| e.value().session == session.id && e.value().name == name)
            .map(|e| *e.key())
            .collect();
        for &port in &ports {
            if let Some((_, handle)) = self.tunnels.remove(&port) {
                handle.cancel.cancel();
            }
            session.ports.retain(|p| *p != port);
        }
        self.udp_pending
            .retain(|_, pu| !(pu.session == session.id && ports_name_match(pu, &ports)));
    }

    fn cleanup_session(&self, session: &Session) {
        for port in &session.ports {
            if let Some((_, handle)) = self.tunnels.remove(port) {
                handle.cancel.cancel();
            }
        }
        for token in &session.udp_tokens {
            self.udp_pending.remove(token);
        }
    }
}

fn ports_name_match(pu: &PendingUdp, ports: &[u16]) -> bool {
    ports.contains(&pu.port)
}

fn auth_error() -> ServerMessage {
    ServerMessage::Error {
        message: "authentication failed".into(),
        fatal: true,
    }
}

// ---------------------------------------------------------------------------
// CLI entry + first-run onboarding
// ---------------------------------------------------------------------------

/// Entry point for `porthole server`: first-run setup if needed, `--show-invite`, then run.
pub async fn run_cli(args: ServerArgs) -> Result<()> {
    let needs_setup = args.config.is_none()
        && !config::default_server_config_path().exists()
        && !config::has_secret_source(args.secret_file.as_deref());

    let settings = if needs_setup {
        first_run_setup(&args).await?
    } else {
        config::load_server(&args)?
    };

    if args.show_invite {
        return print_invite(&settings);
    }
    if needs_setup {
        let _ = print_invite(&settings); // show the code right after first-time setup
    }
    run(settings).await
}

async fn first_run_setup(args: &ServerArgs) -> Result<ServerSettings> {
    println!("Welcome! Setting up your porthole relay for the first time.\n");
    let host = match args.public_host.clone() {
        Some(h) => h,
        None => match detect_public_ip().await {
            Some(ip) => prompt_default("Public address people will use to reach this server", &ip),
            None => prompt_default(
                "Public address people will use to reach this server (domain or IP)",
                "YOUR.SERVER.IP",
            ),
        },
    };

    let file = ServerFile {
        bind_addr: Some("0.0.0.0".into()),
        control_port: Some(protocol::DEFAULT_CONTROL_PORT),
        secret: Some(config::gen_secret()),
        min_port: Some(1024),
        max_port: Some(65535),
        cert_path: Some("porthole.crt".into()),
        key_path: Some("porthole.key".into()),
        public_host: Some(host),
        logging: Default::default(),
    };
    let path = config::default_server_config_path();
    config::save_server_file(&path, &file)?;
    println!("Saved settings to {}\n", path.display());

    config::load_server(args)
}

/// Build and print the connection code clients paste to connect.
fn print_invite(settings: &ServerSettings) -> Result<()> {
    let (_acceptor, fingerprint) = tls::server_acceptor(settings)?;
    let host = settings
        .public_host
        .clone()
        .context("unknown public address — re-run with --public-host <domain-or-ip>")?;
    let code = invite::encode(&ConnectionInfo {
        host,
        port: settings.control_port,
        fingerprint,
        secret: settings.secret.clone(),
    });
    print_invite_box(&code);
    Ok(())
}

fn print_invite_box(code: &str) {
    let color = std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
    let (p, r) = if color {
        ("\x1b[1;38;2;168;85;247m", "\x1b[0m")
    } else {
        ("", "")
    };
    println!();
    println!("  {p}Share this connection code with anyone who should tunnel through you:{r}");
    println!();
    println!("    {p}{code}{r}");
    println!();
    println!("  They run:  porthole join <code>   (or paste it into the porthole window)");
    println!();
}

/// Best-effort public-IP detection via a tiny plain-HTTP request. None on any failure.
async fn detect_public_ip() -> Option<String> {
    let fut = async {
        let mut s = TcpStream::connect("api.ipify.org:80").await.ok()?;
        s.write_all(b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
            .await
            .ok()?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.ok()?;
        let text = String::from_utf8_lossy(&buf);
        let body = text.split("\r\n\r\n").nth(1)?.trim().to_string();
        (!body.is_empty() && body.len() < 64).then_some(body)
    };
    tokio::time::timeout(std::time::Duration::from_secs(4), fut)
        .await
        .ok()
        .flatten()
}

fn prompt_default(question: &str, default: &str) -> String {
    if !std::io::stdin().is_terminal() {
        return default.to_string();
    }
    print!("{question} [{default}]: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_ok() {
        let t = line.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    default.to_string()
}
