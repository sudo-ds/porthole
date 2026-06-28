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

#[derive(Clone, Copy, Debug)]
struct BindingRequest {
    local_port: u16,
    remote_port: u16,
}

struct BoundBinding {
    request: BindingRequest,
    cancel: CancellationToken,
    tcp: Option<TcpListener>,
    udp: Option<Arc<UdpSocket>>,
}

struct RegisterRequest {
    name: String,
    proto: Proto,
    remote_port: Option<u16>,
    local_ports: Option<String>,
    encrypted: bool,
    udp_mtu: Option<u16>,
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
                        local_ports,
                        encrypted,
                        udp_mtu,
                    }) => {
                        self.register(
                            &mut session,
                            RegisterRequest {
                                name,
                                proto,
                                remote_port,
                                local_ports,
                                encrypted,
                                udp_mtu,
                            },
                        )
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

    async fn register(&self, session: &mut Session, request: RegisterRequest) {
        let RegisterRequest {
            name,
            proto,
            remote_port,
            local_ports,
            encrypted,
            udp_mtu,
        } = request;
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

        let (local_ports, contiguous) = match local_ports.as_deref() {
            Some(spec) => match config::parse_local_ports(spec) {
                Ok(selection) => (selection.ports(), selection.is_range()),
                Err(e) => {
                    let _ = tx
                        .send(ServerMessage::Rejected {
                            name,
                            reason: e.to_string(),
                        })
                        .await;
                    return;
                }
            },
            None => (vec![0], false),
        };

        let requests = match self.allocate_requests(&local_ports, contiguous, remote_port) {
            Ok(requests) => requests,
            Err(reason) => {
                let _ = tx.send(ServerMessage::Rejected { name, reason }).await;
                return;
            }
        };

        let bound = match self.try_bind_requests(session, &name, proto, &requests) {
            Ok(bound) => bound,
            Err(reason) => {
                let _ = tx.send(ServerMessage::Rejected { name, reason }).await;
                return;
            }
        };

        let mut bindings = Vec::with_capacity(bound.len());
        for binding in bound {
            let BindingRequest {
                local_port,
                remote_port,
            } = binding.request;
            let public_addr = format!("{}:{}", self.settings.bind_addr, remote_port);
            let mut token = None;
            let mut udp_auth_key = None;

            if let Some(socket) = binding.udp {
                let udp_token = Uuid::new_v4();
                token = Some(udp_token);
                if encrypted {
                    self.udp_pending.insert(
                        udp_token,
                        PendingUdp {
                            socket,
                            port: remote_port,
                            session: session.id,
                            cancel: binding.cancel.clone(),
                        },
                    );
                    session.udp_tokens.push(udp_token);
                } else {
                    let mut key = [0u8; 32];
                    rand::thread_rng().fill_bytes(&mut key);
                    tokio::spawn(udp::server_plain_forward(
                        socket,
                        udp_token,
                        key,
                        resolved_udp_mtu.unwrap_or(protocol::DEFAULT_UDP_MTU),
                        binding.cancel.clone(),
                    ));
                    udp_auth_key = Some(protocol::encode_udp_auth_key(&key));
                }
            }

            if let Some(listener) = binding.tcp {
                tokio::spawn(tcp::server_listener(
                    listener,
                    name.clone(),
                    local_port,
                    encrypted,
                    tx.clone(),
                    self.pending.clone(),
                    binding.cancel.clone(),
                ));
            }

            session.ports.push(remote_port);
            tracing::info!("tunnel '{name}' ({proto}) maps local port {local_port} -> public port {remote_port}");
            bindings.push(protocol::AcceptedBinding {
                local_port,
                remote_port,
                public_addr,
                token,
                udp_auth_key,
                udp_mtu: resolved_udp_mtu,
            });
        }

        let Some(first) = bindings.first().cloned() else {
            let _ = tx
                .send(ServerMessage::Rejected {
                    name,
                    reason: "no public ports requested".into(),
                })
                .await;
            return;
        };
        let _ = tx
            .send(ServerMessage::Accepted {
                name,
                proto,
                public_addr: first.public_addr.clone(),
                remote_port: first.remote_port,
                encrypted,
                token: first.token,
                udp_auth_key: first.udp_auth_key.clone(),
                udp_mtu: resolved_udp_mtu,
                bindings,
            })
            .await;
    }

    fn allocate_requests(
        &self,
        local_ports: &[u16],
        contiguous: bool,
        remote_port: Option<u16>,
    ) -> std::result::Result<Vec<BindingRequest>, String> {
        if local_ports.is_empty() {
            return Err("no local ports requested".into());
        }
        if local_ports.len() > config::MAX_TUNNEL_PORTS {
            return Err(format!(
                "a tunnel can reserve at most {} ports",
                config::MAX_TUNNEL_PORTS
            ));
        }

        let remote_ports = if contiguous && local_ports.len() > 1 {
            self.allocate_contiguous_public_ports(local_ports.len(), remote_port)?
        } else {
            self.allocate_sparse_public_ports(local_ports.len(), remote_port)?
        };
        Ok(local_ports
            .iter()
            .copied()
            .zip(remote_ports)
            .map(|(local_port, remote_port)| BindingRequest {
                local_port,
                remote_port,
            })
            .collect())
    }

    fn allocate_contiguous_public_ports(
        &self,
        count: usize,
        remote_port: Option<u16>,
    ) -> std::result::Result<Vec<u16>, String> {
        let count = u16::try_from(count).map_err(|_| "requested port block is too large")?;
        let max_start = self
            .settings
            .max_port
            .checked_sub(count.saturating_sub(1))
            .ok_or_else(|| "requested port block is larger than the relay range".to_string())?;

        if let Some(start) = remote_port {
            let end_u32 = u32::from(start) + u32::from(count) - 1;
            if end_u32 > u32::from(u16::MAX) {
                return Err(format!(
                    "public port block starting at {start} is too large"
                ));
            }
            let end = end_u32 as u16;
            if start < self.settings.min_port || end > self.settings.max_port {
                return Err(format!(
                    "public port block {start}-{end} is outside the allowed range {}-{}",
                    self.settings.min_port, self.settings.max_port
                ));
            }
            let ports: Vec<u16> = (start..=end).collect();
            if let Some(occupied) = ports.iter().find(|port| self.tunnels.contains_key(port)) {
                return Err(format!(
                    "public port block {start}-{end} is fragmented at {occupied}"
                ));
            }
            return Ok(ports);
        }

        for start in self.settings.min_port..=max_start {
            let end = start + count - 1;
            let ports: Vec<u16> = (start..=end).collect();
            if ports.iter().all(|port| !self.tunnels.contains_key(port)) {
                return Ok(ports);
            }
        }
        Err(format!(
            "no contiguous public block of {count} ports is available in {}-{}",
            self.settings.min_port, self.settings.max_port
        ))
    }

    fn allocate_sparse_public_ports(
        &self,
        count: usize,
        remote_port: Option<u16>,
    ) -> std::result::Result<Vec<u16>, String> {
        let mut ports = Vec::with_capacity(count);
        let mut cursor = self.settings.min_port;
        if let Some(first) = remote_port {
            if !self.settings.port_allowed(first) {
                return Err(format!(
                    "port {first} is outside the allowed range {}-{}",
                    self.settings.min_port, self.settings.max_port
                ));
            }
            if self.tunnels.contains_key(&first) {
                return Err(format!(
                    "requested public port {first} is already allocated"
                ));
            }
            ports.push(first);
            cursor = first.saturating_add(1);
        }

        while ports.len() < count && cursor <= self.settings.max_port {
            if !self.tunnels.contains_key(&cursor) && !ports.contains(&cursor) {
                ports.push(cursor);
            }
            if cursor == u16::MAX {
                break;
            }
            cursor += 1;
        }

        if ports.len() == count {
            Ok(ports)
        } else {
            Err(format!(
                "only {} free public ports are available after allocation constraints; {count} required",
                ports.len()
            ))
        }
    }

    fn try_bind_requests(
        &self,
        session: &Session,
        name: &str,
        proto: Proto,
        requests: &[BindingRequest],
    ) -> std::result::Result<Vec<BoundBinding>, String> {
        let cancel = session.cancel.child_token();
        let mut reserved = Vec::with_capacity(requests.len());
        for request in requests {
            let handle = TunnelHandle {
                name: name.to_string(),
                session: session.id,
                cancel: cancel.clone(),
            };
            match self.tunnels.entry(request.remote_port) {
                Entry::Occupied(_) => {
                    self.release_reserved(&reserved);
                    cancel.cancel();
                    return Err(format!(
                        "requested public port {} became allocated while registering",
                        request.remote_port
                    ));
                }
                Entry::Vacant(v) => {
                    v.insert(handle);
                    reserved.push(request.remote_port);
                }
            }
        }

        let mut bound = Vec::with_capacity(requests.len());
        for request in requests {
            let addr: SocketAddr =
                match format!("{}:{}", self.settings.bind_addr, request.remote_port).parse() {
                    Ok(addr) => addr,
                    Err(_) => {
                        self.release_reserved(&reserved);
                        cancel.cancel();
                        return Err(format!(
                            "invalid bind address for public port {}",
                            request.remote_port
                        ));
                    }
                };
            let mut tcp = None;
            let mut udp = None;
            if proto.has_tcp() {
                match net::bind_tcp(addr) {
                    Ok(listener) => tcp = Some(listener),
                    Err(e) => {
                        self.release_reserved(&reserved);
                        cancel.cancel();
                        return Err(format!(
                            "binding tcp public port {} failed: {e}",
                            request.remote_port
                        ));
                    }
                }
            }
            if proto.has_udp() {
                match net::bind_udp(addr) {
                    Ok(socket) => udp = Some(Arc::new(socket)),
                    Err(e) => {
                        self.release_reserved(&reserved);
                        cancel.cancel();
                        return Err(format!(
                            "binding udp public port {} failed: {e}",
                            request.remote_port
                        ));
                    }
                }
            }
            bound.push(BoundBinding {
                request: *request,
                cancel: cancel.clone(),
                tcp,
                udp,
            });
        }
        Ok(bound)
    }

    fn release_reserved(&self, ports: &[u16]) {
        for port in ports {
            self.tunnels.remove(port);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_paths(tag: &str) -> (PathBuf, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("porthole-server-unit-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("c.crt");
        let key = dir.join("c.key");
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
        (cert, key)
    }

    fn test_server(tag: &str, min_port: u16, max_port: u16) -> Server {
        let _ = crate::install_crypto_provider();
        let (cert, key) = temp_paths(tag);
        let settings = ServerSettings {
            bind_addr: "127.0.0.1".into(),
            control_port: 7835,
            secret: "test-secret".into(),
            min_port,
            max_port,
            cert_path: cert,
            key_path: key,
            public_host: None,
        };
        let (acceptor, _) = tls::server_acceptor(&settings).unwrap();
        Server {
            settings: Arc::new(settings),
            acceptor,
            pending: Arc::new(DashMap::new()),
            tunnels: Arc::new(DashMap::new()),
            udp_pending: Arc::new(DashMap::new()),
        }
    }

    fn occupy(server: &Server, port: u16) {
        server.tunnels.insert(
            port,
            TunnelHandle {
                name: "occupied".into(),
                session: Uuid::nil(),
                cancel: CancellationToken::new(),
            },
        );
    }

    #[test]
    fn contiguous_auto_allocation_skips_fragmented_prefix() {
        let server = test_server("contiguous-auto", 10000, 10010);
        occupy(&server, 10001);

        let requests = server
            .allocate_requests(&[4000, 4001, 4002], true, None)
            .unwrap();
        let remote: Vec<u16> = requests.iter().map(|r| r.remote_port).collect();
        assert_eq!(remote, vec![10002, 10003, 10004]);
    }

    #[test]
    fn fixed_contiguous_allocation_rejects_fragmentation() {
        let server = test_server("contiguous-fixed", 10000, 10010);
        occupy(&server, 10003);

        let err = server
            .allocate_requests(&[4000, 4001, 4002, 4003], true, Some(10000))
            .unwrap_err();
        assert!(err.contains("fragmented at 10003"));
    }

    #[test]
    fn sparse_allocation_uses_first_n_free_ports() {
        let server = test_server("sparse-auto", 10000, 10005);
        occupy(&server, 10000);

        let requests = server
            .allocate_requests(&[1000, 2000], false, None)
            .unwrap();
        let remote: Vec<u16> = requests.iter().map(|r| r.remote_port).collect();
        assert_eq!(remote, vec![10001, 10002]);
    }

    #[test]
    fn sparse_fixed_start_keeps_first_port_and_skips_next_occupied() {
        let server = test_server("sparse-fixed", 10000, 10005);
        occupy(&server, 10003);

        let requests = server
            .allocate_requests(&[1000, 2000], false, Some(10002))
            .unwrap();
        let remote: Vec<u16> = requests.iter().map(|r| r.remote_port).collect();
        assert_eq!(remote, vec![10002, 10004]);
    }

    #[test]
    fn bind_failure_rolls_back_reserved_ports() {
        let mut server = test_server("bind-rollback", 10000, 10001);
        Arc::get_mut(&mut server.settings).unwrap().bind_addr = "not an address".into();
        let session = Session {
            id: Uuid::new_v4(),
            cancel: CancellationToken::new(),
            control_tx: mpsc::channel(1).0,
            ports: Vec::new(),
            udp_tokens: Vec::new(),
        };
        let requests = vec![
            BindingRequest {
                local_port: 4000,
                remote_port: 10000,
            },
            BindingRequest {
                local_port: 4001,
                remote_port: 10001,
            },
        ];

        assert!(server
            .try_bind_requests(&session, "bad", Proto::Tcp, &requests)
            .is_err());
        assert!(!server.tunnels.contains_key(&10000));
        assert!(!server.tunnels.contains_key(&10001));
    }
}
