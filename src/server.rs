//! Relay server: accepts TLS connections on one ingress port, authenticates them, and
//! demultiplexes control connections (which register tunnels) from data connections
//! (which fulfil a pending TCP accept or carry a UDP tunnel's datagrams).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::config::ServerSettings;
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

    let shutdown = CancellationToken::new();
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
            shutdown.cancel();
        });
    }

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
        let tls = self
            .acceptor
            .accept(tcp)
            .await
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
            ClientMessage::DataHello { token, id } => {
                if !auth::verify_token(&self.settings.secret, &token) {
                    let _ = protocol::send_msg(&mut wire, &auth_error()).await;
                    bail!("authentication failed (data) from {peer}");
                }
                self.handle_data_conn(wire, id).await
            }
            _ => bail!("unexpected first frame from {peer}"),
        }
    }

    /// A data connection: route it to the waiting TCP accept or the UDP tunnel by id.
    async fn handle_data_conn(&self, wire: Wire<ServerTls>, id: Uuid) -> Result<()> {
        if let Some((_, tx)) = self.pending.remove(&id) {
            let _ = tx.send(protocol::into_raw(wire));
            return Ok(());
        }
        if let Some((_, pending)) = self.udp_pending.remove(&id) {
            return udp::server_forward(wire, pending.socket, pending.cancel).await;
        }
        tracing::debug!("data connection for unknown/expired id {id}");
        Ok(())
    }

    /// A control connection: register tunnels and relay notifications until it drops.
    async fn handle_control(&self, wire: Wire<ServerTls>, peer: SocketAddr) -> Result<()> {
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
                    }) => {
                        self.register(&mut session, name, proto, remote_port).await;
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
    ) {
        let tx = session.control_tx.clone();

        let candidates: Vec<u16> = match remote_port {
            Some(p) => {
                if !self.settings.port_allowed(p) {
                    let _ = tx
                        .send(reject(format!(
                            "port {p} is outside the allowed range {}-{}",
                            self.settings.min_port, self.settings.max_port
                        )))
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
                                token: None,
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
                        self.udp_pending.insert(
                            token,
                            PendingUdp {
                                socket: Arc::new(socket),
                                port,
                                session: session.id,
                                cancel,
                            },
                        );
                        session.ports.push(port);
                        session.udp_tokens.push(token);
                        tracing::info!("tunnel '{name}' (udp) -> public port {port}");
                        let _ = tx
                            .send(ServerMessage::Accepted {
                                name,
                                proto,
                                public_addr,
                                remote_port: port,
                                token: Some(token),
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
            }
        }

        let _ = tx
            .send(reject(format!(
                "no public port available for tunnel '{name}'"
            )))
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

fn reject(message: String) -> ServerMessage {
    ServerMessage::Error {
        message,
        fatal: false,
    }
}
