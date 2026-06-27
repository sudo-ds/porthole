//! UDP relay, both sides.
//!
//! A UDP tunnel multiplexes every end-user flow over a single data channel, tagging each
//! datagram with the end-user's address. The server keeps no per-flow state (the address
//! tag is authoritative); the client keeps one ephemeral socket per end-user address.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::client::{ClientShared, Counters};
use crate::protocol::{
    decode_plain_udp, decode_udp, encode_plain_udp, encode_udp, PlainUdpKind, Wire,
    UDP_IDLE_TIMEOUT, UDP_PLAINTEXT_KEEPALIVE, UDP_PLAINTEXT_MAX_PACKET,
};
use crate::server::ServerTls;

const MAX_DATAGRAM: usize = 65_535;
/// Bounded outbound queue per UDP tunnel; full => drop (UDP is lossy by contract).
const OUTBOUND_QUEUE: usize = 1024;
/// Cap on concurrent end-user flows per UDP tunnel. End-user source addresses are spoofable,
/// so without a cap a flood of forged sources would create unbounded sockets/tasks/buffers on
/// the client. While at the cap, datagrams from new sources are dropped; idle flows are reaped
/// within `UDP_IDLE_TIMEOUT`. Each flow holds a ~64 KiB read buffer, so this also bounds memory.
const MAX_FLOWS: usize = 4096;

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// Pump datagrams between the public UDP socket and the client's data channel until either
/// side closes or the tunnel is cancelled.
pub async fn server_forward(
    wire: Wire<ServerTls>,
    socket: Arc<UdpSocket>,
    cancel: CancellationToken,
) -> Result<()> {
    server_forward_io(wire, socket, cancel).await
}

trait UdpIo: Send + Sync + 'static {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
    async fn send_to(&self, data: &[u8], dst: SocketAddr) -> std::io::Result<usize>;
}

impl UdpIo for UdpSocket {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }

    async fn send_to(&self, data: &[u8], dst: SocketAddr) -> std::io::Result<usize> {
        self.send_to(data, dst).await
    }
}

async fn server_forward_io<S, W>(
    wire: Wire<W>,
    socket: Arc<S>,
    cancel: CancellationToken,
) -> Result<()>
where
    S: UdpIo,
    W: AsyncRead + AsyncWrite + Unpin,
{
    let (mut sink, mut stream) = wire.split();
    // Couple the two halves: when either ends (the data conn closed, a socket error, or the
    // tunnel was cancelled), tear the other down too. Without this, the public-recv half would
    // park in `recv_from` forever after the client's data conn drops — leaking the socket and
    // its public port until the whole session is torn down. `link` is a child of `cancel`, so
    // a tunnel/session cancellation still propagates to both halves.
    let link = cancel.child_token();

    // Public end-users -> client.
    let recv = {
        let socket = socket.clone();
        let link = link.clone();
        async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                tokio::select! {
                    _ = link.cancelled() => break,
                    r = socket.recv_from(&mut buf) => match r {
                        Ok((n, src)) => {
                            if sink.send(encode_udp(src, &buf[..n])).await.is_err() { break; }
                        }
                        Err(e) => { tracing::debug!("udp recv_from: {e}"); break; }
                    }
                }
            }
            link.cancel();
        }
    };

    // Client -> public end-users.
    let ret = {
        let socket = socket.clone();
        let link = link.clone();
        async move {
            loop {
                tokio::select! {
                    _ = link.cancelled() => break,
                    f = stream.next() => match f {
                        Some(Ok(frame)) => {
                            if let Ok((dst, data)) = decode_udp(&frame) {
                                let _ = socket.send_to(data, dst).await;
                            }
                        }
                        _ => break,
                    }
                }
            }
            link.cancel();
        }
    };

    tokio::join!(recv, ret);
    Ok(())
}

/// Native plaintext UDP data channel. Public datagrams and authenticated client packets share
/// the tunnel's public UDP socket; valid client hello packets pin/update the client endpoint.
pub async fn server_plain_forward(
    socket: Arc<UdpSocket>,
    token: Uuid,
    key: [u8; 32],
    cancel: CancellationToken,
) -> Result<()> {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut client: Option<SocketAddr> = None;
    let mut seq = 0u64;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = socket.recv_from(&mut buf) => {
                let (n, peer) = match r {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::debug!("udp plaintext recv_from: {e}");
                        break;
                    }
                };
                let packet = &buf[..n];
                match decode_plain_udp(packet, &key) {
                    Ok((PlainUdpKind::Hello, _, body)) => {
                        if body == token.as_bytes() {
                            client = Some(peer);
                        }
                    }
                    Ok((PlainUdpKind::Keepalive, _, _)) => {
                        if client != Some(peer) {
                            tracing::trace!("ignored plaintext udp keepalive from unpinned endpoint {peer}");
                        }
                    }
                    Ok((PlainUdpKind::Data, _, body)) => {
                        if client != Some(peer) {
                            tracing::trace!("ignored plaintext udp data from unpinned endpoint {peer}");
                            continue;
                        }
                        if let Ok((dst, data)) = decode_udp(body) {
                            let _ = socket.send_to(data, dst).await;
                        }
                    }
                    Err(_) => {
                        if client == Some(peer) {
                            continue;
                        }
                        let Some(client) = client else {
                            continue;
                        };
                        let body = encode_udp(peer, packet);
                        let Some(out) = encode_plain_udp(PlainUdpKind::Data, next_seq(&mut seq), &body, &key) else {
                            tracing::debug!("dropping udp plaintext datagram that exceeds no-fragment packet limit");
                            continue;
                        };
                        let _ = socket.send_to(&out, client).await;
                    }
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

struct FlowEntry {
    sock: Arc<UdpSocket>,
    cancel: CancellationToken,
    /// Milliseconds since the channel started; updated on each datagram in either direction
    /// (a lock-free store instead of a shared-map write on the per-packet path).
    last_seen: Arc<AtomicU64>,
}

/// Run a UDP tunnel's data channel, re-dialing it if it drops while the tunnel is still live.
///
/// The channel is a single long-lived data connection; an idle one can be reaped by a NAT or
/// firewall even while the control connection stays up via heartbeats. On any drop that isn't
/// a tunnel/shutdown cancellation, we re-dial with the same token (the server keeps the public
/// socket bound for re-dials), so the tunnel self-heals without disturbing other tunnels.
pub async fn client_channel(
    shared: Arc<ClientShared>,
    tunnel: String,
    local: SocketAddr,
    token: Uuid,
    counters: Arc<Counters>,
    cancel: CancellationToken,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let started = Instant::now();
        run_udp_channel(&shared, &tunnel, local, token, &counters, &cancel).await;
        if cancel.is_cancelled() {
            break;
        }
        // A channel that lasted a while was healthy; reset the backoff.
        if started.elapsed() > Duration::from_secs(10) {
            backoff = Duration::from_secs(1);
        }
        tracing::info!("udp channel for '{tunnel}' dropped; re-dialing in {backoff:?}");
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// Run a native UDP data channel for a plaintext UDP tunnel.
pub async fn client_plain_channel(
    tunnel: String,
    local: SocketAddr,
    server_udp: String,
    token: Uuid,
    key: [u8; 32],
    counters: Arc<Counters>,
    cancel: CancellationToken,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let started = Instant::now();
        if let Err(e) =
            run_plain_udp_channel(&tunnel, local, &server_udp, token, key, &counters, &cancel).await
        {
            tracing::warn!("plaintext udp channel for '{tunnel}' failed: {e:#}");
        }
        if cancel.is_cancelled() {
            break;
        }
        if started.elapsed() > Duration::from_secs(10) {
            backoff = Duration::from_secs(1);
        }
        tracing::info!("plaintext udp channel for '{tunnel}' dropped; re-dialing in {backoff:?}");
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// One attempt at a UDP data channel: decode incoming datagrams to per-flow local sockets and
/// forward their replies back over a single bounded writer. Returns when the channel drops or
/// the tunnel is cancelled.
async fn run_udp_channel(
    shared: &Arc<ClientShared>,
    tunnel: &str,
    local: SocketAddr,
    token: Uuid,
    counters: &Arc<Counters>,
    cancel: &CancellationToken,
) {
    let wire = match crate::client::connect_data_wire(shared, token).await {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("udp data channel for '{tunnel}' failed: {e:#}");
            return;
        }
    };
    let (mut sink, mut stream) = wire.split();

    // A token scoped to THIS data connection: it ends the channel's tasks on a drop without
    // cancelling the caller's long-lived tunnel token (which must survive for re-dials). As a
    // child of `cancel`, a tunnel/shutdown cancellation still propagates here.
    let link = cancel.child_token();
    // All flow timestamps are milliseconds relative to this base instant (cheap atomic stores).
    let started = Instant::now();

    let flows: Arc<DashMap<SocketAddr, FlowEntry>> = Arc::new(DashMap::new());
    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(OUTBOUND_QUEUE);

    // Single writer of the data channel.
    let writer_cancel = link.clone();
    let writer = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = writer_cancel.cancelled() => break,
                b = out_rx.recv() => {
                    let Some(b) = b else { break };
                    if sink.send(b).await.is_err() { break; }
                }
            }
        }
        let _ = sink.close().await;
    });

    // Idle-flow janitor: reap flows whose last activity is older than the idle timeout.
    let janitor = {
        let flows = flows.clone();
        let cancel = link.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(10));
            let idle_ms = UDP_IDLE_TIMEOUT.as_millis() as u64;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        let now = epoch_ms(&started);
                        let expired: Vec<SocketAddr> = flows
                            .iter()
                            .filter(|e| now.saturating_sub(e.value().last_seen.load(Relaxed)) > idle_ms)
                            .map(|e| *e.key())
                            .collect();
                        for addr in expired {
                            if let Some((_, entry)) = flows.remove(&addr) {
                                entry.cancel.cancel();
                            }
                        }
                    }
                }
            }
        })
    };

    // Server -> local: fan datagrams out to per-end-user sockets.
    loop {
        tokio::select! {
            _ = link.cancelled() => break,
            f = stream.next() => {
                let frame = match f { Some(Ok(fr)) => fr, _ => break };
                let (src, data) = match decode_udp(&frame) { Ok(x) => x, Err(_) => continue };
                counters.bytes_in.fetch_add(data.len() as u64, Relaxed);
                let now = epoch_ms(&started);

                let sock = match flows.get(&src) {
                    Some(e) => {
                        e.last_seen.store(now, Relaxed);
                        e.sock.clone()
                    }
                    None => {
                        // While at the flow cap, drop datagrams from new sources so a flood of
                        // spoofed addresses can't exhaust sockets/tasks/memory; idle flows are
                        // reaped within UDP_IDLE_TIMEOUT.
                        if flows.len() >= MAX_FLOWS {
                            continue;
                        }
                        let sock = match bind_local_flow(local).await {
                            Ok(s) => Arc::new(s),
                            Err(e) => { tracing::debug!("opening flow socket: {e}"); continue; }
                        };
                        let flow_cancel = link.child_token();
                        let last_seen = Arc::new(AtomicU64::new(now));
                        flows.insert(
                            src,
                            FlowEntry {
                                sock: sock.clone(),
                                cancel: flow_cancel.clone(),
                                last_seen: last_seen.clone(),
                            },
                        );
                        tokio::spawn(flow_reader(
                            src,
                            sock.clone(),
                            out_tx.clone(),
                            last_seen,
                            counters.clone(),
                            flow_cancel,
                            started,
                        ));
                        sock
                    }
                };
                let _ = sock.send(data).await;
            }
        }
    }

    link.cancel();
    let _ = writer.await;
    janitor.abort();
}

async fn run_plain_udp_channel(
    tunnel: &str,
    local: SocketAddr,
    server_udp: &str,
    token: Uuid,
    key: [u8; 32],
    counters: &Arc<Counters>,
    cancel: &CancellationToken,
) -> Result<()> {
    let channel = Arc::new(connect_plain_udp_socket(server_udp).await?);
    let link = cancel.child_token();
    let started = Instant::now();

    let flows: Arc<DashMap<SocketAddr, FlowEntry>> = Arc::new(DashMap::new());
    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(OUTBOUND_QUEUE);
    let seq = Arc::new(AtomicU64::new(0));

    let writer = {
        let channel = channel.clone();
        let writer_cancel = link.clone();
        let seq = seq.clone();
        tokio::spawn(async move {
            let _ =
                send_plain_udp_packet(&channel, PlainUdpKind::Hello, &seq, token.as_bytes(), &key)
                    .await;
            let mut keepalive = tokio::time::interval(UDP_PLAINTEXT_KEEPALIVE);
            loop {
                tokio::select! {
                    _ = writer_cancel.cancelled() => break,
                    _ = keepalive.tick() => {
                        if send_plain_udp_packet(&channel, PlainUdpKind::Keepalive, &seq, &[], &key).await.is_err() {
                            break;
                        }
                    }
                    b = out_rx.recv() => {
                        let Some(body) = b else { break };
                        if send_plain_udp_packet(&channel, PlainUdpKind::Data, &seq, &body, &key).await.is_err() {
                            break;
                        }
                    }
                }
            }
        })
    };

    let janitor = {
        let flows = flows.clone();
        let cancel = link.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(10));
            let idle_ms = UDP_IDLE_TIMEOUT.as_millis() as u64;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        let now = epoch_ms(&started);
                        let expired: Vec<SocketAddr> = flows
                            .iter()
                            .filter(|e| now.saturating_sub(e.value().last_seen.load(Relaxed)) > idle_ms)
                            .map(|e| *e.key())
                            .collect();
                        for addr in expired {
                            if let Some((_, entry)) = flows.remove(&addr) {
                                entry.cancel.cancel();
                            }
                        }
                    }
                }
            }
        })
    };

    let mut buf = vec![0u8; UDP_PLAINTEXT_MAX_PACKET];
    loop {
        tokio::select! {
            _ = link.cancelled() => break,
            r = channel.recv(&mut buf) => {
                let n = match r {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::debug!("plaintext udp channel recv for '{tunnel}': {e}");
                        break;
                    }
                };
                let (kind, _, body) = match decode_plain_udp(&buf[..n], &key) {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::debug!("plaintext udp channel decode for '{tunnel}': {e:#}");
                        continue;
                    }
                };
                if kind != PlainUdpKind::Data {
                    continue;
                }
                let (src, data) = match decode_udp(body) { Ok(x) => x, Err(_) => continue };
                counters.bytes_in.fetch_add(data.len() as u64, Relaxed);
                let now = epoch_ms(&started);

                let sock = match flows.get(&src) {
                    Some(e) => {
                        e.last_seen.store(now, Relaxed);
                        e.sock.clone()
                    }
                    None => {
                        if flows.len() >= MAX_FLOWS {
                            continue;
                        }
                        let sock = match bind_local_flow(local).await {
                            Ok(s) => Arc::new(s),
                            Err(e) => { tracing::debug!("opening plaintext udp flow socket: {e}"); continue; }
                        };
                        let flow_cancel = link.child_token();
                        let last_seen = Arc::new(AtomicU64::new(now));
                        flows.insert(
                            src,
                            FlowEntry {
                                sock: sock.clone(),
                                cancel: flow_cancel.clone(),
                                last_seen: last_seen.clone(),
                            },
                        );
                        tokio::spawn(flow_reader(
                            src,
                            sock.clone(),
                            out_tx.clone(),
                            last_seen,
                            counters.clone(),
                            flow_cancel,
                            started,
                        ));
                        sock
                    }
                };
                let _ = sock.send(data).await;
            }
        }
    }

    link.cancel();
    let _ = writer.await;
    janitor.abort();
    Ok(())
}

/// Per-flow task: read replies from the local service and queue them back to the server.
async fn flow_reader(
    src: SocketAddr,
    sock: Arc<UdpSocket>,
    out_tx: mpsc::Sender<Bytes>,
    last_seen: Arc<AtomicU64>,
    counters: Arc<Counters>,
    cancel: CancellationToken,
    started: Instant,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = sock.recv(&mut buf) => match r {
                Ok(n) => {
                    last_seen.store(epoch_ms(&started), Relaxed);
                    counters.bytes_out.fetch_add(n as u64, Relaxed);
                    // try_send: if the link is backed up, drop rather than block or buffer.
                    let _ = out_tx.try_send(encode_udp(src, &buf[..n]));
                }
                Err(e) => { tracing::debug!("flow recv: {e}"); break; }
            }
        }
    }
}

async fn send_plain_udp_packet(
    channel: &UdpSocket,
    kind: PlainUdpKind,
    seq: &AtomicU64,
    body: &[u8],
    key: &[u8; 32],
) -> Result<()> {
    let Some(packet) = encode_plain_udp(kind, seq.fetch_add(1, Relaxed), body, key) else {
        tracing::debug!("dropping udp plaintext datagram that exceeds no-fragment packet limit");
        return Ok(());
    };
    channel.send(&packet).await?;
    Ok(())
}

async fn connect_plain_udp_socket(server_udp: &str) -> Result<UdpSocket> {
    let server = lookup_host(server_udp)
        .await
        .with_context(|| format!("resolving udp data endpoint {server_udp}"))?
        .next()
        .with_context(|| format!("udp data endpoint {server_udp} resolved to no addresses"))?;
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(server).await?;
    Ok(sock)
}

async fn bind_local_flow(local: SocketAddr) -> std::io::Result<UdpSocket> {
    let bind: SocketAddr = if local.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(local).await?;
    Ok(sock)
}

/// Milliseconds elapsed since `started`; the monotonic timestamp stored per flow.
fn epoch_ms(started: &Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

fn next_seq(seq: &mut u64) -> u64 {
    let out = *seq;
    *seq = (*seq).wrapping_add(1);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::sync::Mutex;
    use tokio::time::{timeout, Duration};

    struct MockUdp {
        incoming: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
        outgoing: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    }

    struct MockUdpHarness {
        socket: Arc<MockUdp>,
        incoming_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
        outgoing_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    }

    impl UdpIo for MockUdp {
        async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            let mut incoming = self.incoming.lock().await;
            let Some((data, src)) = incoming.recv().await else {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            };
            let n = data.len().min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            Ok((n, src))
        }

        async fn send_to(&self, data: &[u8], dst: SocketAddr) -> std::io::Result<usize> {
            self.outgoing
                .send((data.to_vec(), dst))
                .await
                .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
            Ok(data.len())
        }
    }

    fn mock_udp() -> MockUdpHarness {
        let (incoming_tx, incoming_rx) = mpsc::channel(8);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(8);
        MockUdpHarness {
            socket: Arc::new(MockUdp {
                incoming: Mutex::new(incoming_rx),
                outgoing: outgoing_tx,
            }),
            incoming_tx,
            outgoing_rx,
        }
    }

    #[tokio::test]
    async fn server_forward_bridges_mock_udp_and_wire() {
        let MockUdpHarness {
            socket,
            incoming_tx,
            mut outgoing_rx,
        } = mock_udp();
        let (server_io, client_io) = tokio::io::duplex(4096);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(server_forward_io(
            crate::protocol::wire(server_io),
            socket,
            cancel.clone(),
        ));
        let mut client_wire = crate::protocol::wire(client_io);
        let peer: SocketAddr = "198.51.100.10:40000".parse().unwrap();

        incoming_tx.send((b"ping".to_vec(), peer)).await.unwrap();
        let frame = timeout(
            Duration::from_secs(1),
            crate::protocol::recv_frame(&mut client_wire),
        )
        .await
        .unwrap()
        .unwrap();
        let (got_peer, got_data) = decode_udp(&frame).unwrap();
        assert_eq!(got_peer, peer);
        assert_eq!(got_data, b"ping");

        crate::protocol::send_frame(&mut client_wire, encode_udp(peer, b"pong"))
            .await
            .unwrap();
        let (got_data, got_peer) = timeout(Duration::from_secs(1), outgoing_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got_peer, peer);
        assert_eq!(got_data, b"pong");

        cancel.cancel();
        drop(incoming_tx);
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn server_forward_preserves_large_mock_udp_datagram() {
        let MockUdpHarness {
            socket,
            incoming_tx,
            outgoing_rx: _outgoing_rx,
        } = mock_udp();
        let (server_io, client_io) = tokio::io::duplex(128 * 1024);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(server_forward_io(
            crate::protocol::wire(server_io),
            socket,
            cancel.clone(),
        ));
        let mut client_wire = crate::protocol::wire(client_io);
        let peer: SocketAddr = "203.0.113.77:49152".parse().unwrap();
        let payload = vec![0xAB; 60_000];

        incoming_tx.send((payload.clone(), peer)).await.unwrap();
        let frame = timeout(
            Duration::from_secs(1),
            crate::protocol::recv_frame(&mut client_wire),
        )
        .await
        .unwrap()
        .unwrap();
        let (got_peer, got_data) = decode_udp(&frame).unwrap();
        assert_eq!(got_peer, peer);
        assert_eq!(got_data, payload.as_slice());

        cancel.cancel();
        drop(incoming_tx);
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
