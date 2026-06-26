//! UDP relay, both sides.
//!
//! A UDP tunnel multiplexes every end-user flow over a single data channel, tagging each
//! datagram with the end-user's address. The server keeps no per-flow state (the address
//! tag is authoritative); the client keeps one ephemeral socket per end-user address.

use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::client::{ClientShared, Counters};
use crate::protocol::{decode_udp, encode_udp, Wire, UDP_IDLE_TIMEOUT};
use crate::server::ServerTls;

const MAX_DATAGRAM: usize = 65_535;
/// Bounded outbound queue per UDP tunnel; full => drop (UDP is lossy by contract).
const OUTBOUND_QUEUE: usize = 1024;

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
    let (mut sink, mut stream) = wire.split();

    // Public end-users -> client.
    let recv = {
        let socket = socket.clone();
        let cancel = cancel.clone();
        async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    r = socket.recv_from(&mut buf) => match r {
                        Ok((n, src)) => {
                            if sink.send(encode_udp(src, &buf[..n])).await.is_err() { break; }
                        }
                        Err(e) => { tracing::debug!("udp recv_from: {e}"); break; }
                    }
                }
            }
        }
    };

    // Client -> public end-users.
    let ret = {
        let socket = socket.clone();
        let cancel = cancel.clone();
        async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
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
        }
    };

    tokio::join!(recv, ret);
    Ok(())
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

struct FlowEntry {
    sock: Arc<UdpSocket>,
    cancel: CancellationToken,
}

/// Open and run a UDP tunnel's data channel: decode incoming datagrams to per-flow local
/// sockets, and forward their replies back over a single bounded writer.
pub async fn client_channel(
    shared: Arc<ClientShared>,
    tunnel: String,
    local: SocketAddr,
    token: Uuid,
    counters: Arc<Counters>,
    cancel: CancellationToken,
) {
    let wire = match crate::client::connect_data_wire(&shared, token).await {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("udp data channel for '{tunnel}' failed: {e:#}");
            return;
        }
    };
    let (mut sink, mut stream) = wire.split();

    let flows: Arc<DashMap<SocketAddr, FlowEntry>> = Arc::new(DashMap::new());
    let last_seen: Arc<DashMap<SocketAddr, Instant>> = Arc::new(DashMap::new());
    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(OUTBOUND_QUEUE);

    // Single writer of the data channel.
    let writer_cancel = cancel.clone();
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

    // Idle-flow janitor.
    let janitor = {
        let flows = flows.clone();
        let last_seen = last_seen.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(10));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        let now = Instant::now();
                        let expired: Vec<SocketAddr> = last_seen
                            .iter()
                            .filter(|e| now.duration_since(*e.value()) > UDP_IDLE_TIMEOUT)
                            .map(|e| *e.key())
                            .collect();
                        for addr in expired {
                            last_seen.remove(&addr);
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
            _ = cancel.cancelled() => break,
            f = stream.next() => {
                let frame = match f { Some(Ok(fr)) => fr, _ => break };
                let (src, data) = match decode_udp(&frame) { Ok(x) => x, Err(_) => continue };
                last_seen.insert(src, Instant::now());
                counters.bytes_in.fetch_add(data.len() as u64, Relaxed);

                let sock = match flows.get(&src) {
                    Some(e) => e.sock.clone(),
                    None => {
                        let sock = match bind_local_flow(local).await {
                            Ok(s) => Arc::new(s),
                            Err(e) => { tracing::debug!("opening flow socket: {e}"); continue; }
                        };
                        let flow_cancel = cancel.child_token();
                        flows.insert(src, FlowEntry { sock: sock.clone(), cancel: flow_cancel.clone() });
                        tokio::spawn(flow_reader(
                            src,
                            sock.clone(),
                            out_tx.clone(),
                            last_seen.clone(),
                            counters.clone(),
                            flow_cancel,
                        ));
                        sock
                    }
                };
                let _ = sock.send(data).await;
            }
        }
    }

    cancel.cancel();
    let _ = writer.await;
    janitor.abort();
}

/// Per-flow task: read replies from the local service and queue them back to the server.
async fn flow_reader(
    src: SocketAddr,
    sock: Arc<UdpSocket>,
    out_tx: mpsc::Sender<Bytes>,
    last_seen: Arc<DashMap<SocketAddr, Instant>>,
    counters: Arc<Counters>,
    cancel: CancellationToken,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = sock.recv(&mut buf) => match r {
                Ok(n) => {
                    last_seen.insert(src, Instant::now());
                    counters.bytes_out.fetch_add(n as u64, Relaxed);
                    // try_send: if the link is backed up, drop rather than block or buffer.
                    let _ = out_tx.try_send(encode_udp(src, &buf[..n]));
                }
                Err(e) => { tracing::debug!("flow recv: {e}"); break; }
            }
        }
    }
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
