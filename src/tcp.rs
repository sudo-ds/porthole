//! TCP relay, both sides.
//!
//! Server: a public listener accepts an end-user connection, registers a pending accept
//! keyed by a fresh id, tells the client over the control channel, and splices the two
//! sockets once the client dials back the matching data connection.
//!
//! Client: on `NewConn`, dial a data connection (identified by the same id) and the local
//! target, then splice them.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use anyhow::{bail, Result};
use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::client::ClientShared;
use crate::config::ProxyProtocol;
use crate::net;
use crate::protocol::{self, Prefixed, ServerMessage, ACCEPT_TIMEOUT};
use crate::server::ServerTls;

/// Pending TCP accepts awaiting their data connection, keyed by connection id.
pub type PendingMap = PendingMapFor<ServerTls>;
pub type PendingMapFor<S> = Arc<DashMap<Uuid, oneshot::Sender<Prefixed<S>>>>;

/// Per-direction splice buffer size. The default `copy_bidirectional` uses 8 KiB, which caps
/// single-stream throughput on high bandwidth-delay links; 64 KiB lets bulk transfers fill the
/// pipe.
const SPLICE_BUF: usize = 64 * 1024;

/// Server side: accept end-user connections on a public port and pair each with a data conn.
pub async fn server_listener(
    listener: TcpListener,
    tunnel: String,
    control_tx: mpsc::Sender<ServerMessage>,
    pending: PendingMap,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            res = listener.accept() => {
                let (user, peer) = match res {
                    Ok(x) => x,
                    Err(e) => { tracing::debug!("accept on tunnel '{tunnel}': {e}"); break; }
                };
                net::set_keepalive(&user);
                let dst = user.local_addr().ok();

                accept_user_conn(
                    user,
                    tunnel.clone(),
                    Some(peer),
                    dst,
                    control_tx.clone(),
                    pending.clone(),
                    cancel.clone(),
                )
                .await;
            }
        }
    }
}

async fn accept_user_conn<User, Data>(
    user: User,
    tunnel: String,
    src_addr: Option<SocketAddr>,
    dst_addr: Option<SocketAddr>,
    control_tx: mpsc::Sender<ServerMessage>,
    pending: PendingMapFor<Data>,
    cancel: CancellationToken,
) where
    User: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Data: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let id = Uuid::new_v4();
    let (tx, rx) = oneshot::channel::<Prefixed<Data>>();
    pending.insert(id, tx);

    if control_tx
        .send(ServerMessage::NewConn {
            id,
            tunnel,
            src_addr,
            dst_addr,
        })
        .await
        .is_err()
    {
        pending.remove(&id); // control gone
        return;
    }

    let splice_pending = pending.clone();
    let splice_cancel = cancel.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = splice_cancel.cancelled() => {
                splice_pending.remove(&id);
            }
            r = tokio::time::timeout(ACCEPT_TIMEOUT, rx) => {
                match r {
                    Ok(Ok(mut data)) => {
                        let mut user = user;
                        tokio::select! {
                            _ = splice_cancel.cancelled() => {}
                            _ = tokio::io::copy_bidirectional_with_sizes(
                                &mut user, &mut data, SPLICE_BUF, SPLICE_BUF,
                            ) => {}
                        }
                    }
                    _ => {
                        // Timed out or the data conn never came: drop the pending slot.
                        splice_pending.remove(&id);
                    }
                }
            }
        }
    });
}

/// Client side: handle one `NewConn` by splicing a data conn to the local service.
pub async fn client_handle_conn(
    shared: Arc<ClientShared>,
    id: Uuid,
    tunnel: String,
    src_addr: Option<SocketAddr>,
    dst_addr: Option<SocketAddr>,
    cancel: CancellationToken,
) {
    let (local, proxy_protocol, counters) = match shared.status.get(&tunnel) {
        Some(s) => (s.local_addr, s.proxy_protocol, s.counters.clone()),
        None => {
            tracing::warn!("NewConn for unknown tunnel '{tunnel}'");
            return;
        }
    };

    let wire = match crate::client::connect_data_wire(&shared, id).await {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("opening data connection failed: {e:#}");
            return;
        }
    };
    let mut data = protocol::into_raw(wire);

    let mut local_stream = match TcpStream::connect(local).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("dialing local service {local}: {e}");
            return;
        }
    };
    net::set_keepalive(&local_stream);

    if !proxy_protocol.is_off() {
        let (Some(src), Some(dst)) = (src_addr, dst_addr) else {
            tracing::warn!("proxy protocol enabled for '{tunnel}' but source metadata is missing");
            return;
        };
        let header = match proxy_header(proxy_protocol, src, dst) {
            Ok(header) => header,
            Err(e) => {
                tracing::warn!("proxy protocol header for '{tunnel}' could not be built: {e:#}");
                return;
            }
        };
        if let Err(e) = local_stream.write_all(&header).await {
            tracing::warn!("writing proxy protocol header to local service {local}: {e}");
            return;
        }
    }

    counters.active.fetch_add(1, Relaxed);
    tokio::select! {
        _ = cancel.cancelled() => {}
        r = tokio::io::copy_bidirectional_with_sizes(&mut data, &mut local_stream, SPLICE_BUF, SPLICE_BUF) => {
            if let Ok((into_local, out_remote)) = r {
                counters.bytes_in.fetch_add(into_local, Relaxed);
                counters.bytes_out.fetch_add(out_remote, Relaxed);
            }
        }
    }
    counters.active.fetch_sub(1, Relaxed);
}

fn proxy_header(mode: ProxyProtocol, src: SocketAddr, dst: SocketAddr) -> Result<Vec<u8>> {
    match mode {
        ProxyProtocol::Off => Ok(Vec::new()),
        ProxyProtocol::V1 => proxy_header_v1(src, dst),
        ProxyProtocol::V2 => proxy_header_v2(src, dst),
    }
}

fn proxy_header_v1(src: SocketAddr, dst: SocketAddr) -> Result<Vec<u8>> {
    let family = match (src.ip(), dst.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) => "TCP4",
        (IpAddr::V6(_), IpAddr::V6(_)) => "TCP6",
        _ => bail!("source and destination address families differ"),
    };
    Ok(format!(
        "PROXY {family} {} {} {} {}\r\n",
        src.ip(),
        dst.ip(),
        src.port(),
        dst.port()
    )
    .into_bytes())
}

fn proxy_header_v2(src: SocketAddr, dst: SocketAddr) -> Result<Vec<u8>> {
    const SIG: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

    let mut out = Vec::with_capacity(52);
    out.extend_from_slice(SIG);
    out.push(0x21); // version 2, PROXY command
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
            out.push(0x11); // AF_INET, STREAM
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&src_ip.octets());
            out.extend_from_slice(&dst_ip.octets());
        }
        (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
            out.push(0x21); // AF_INET6, STREAM
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&src_ip.octets());
            out.extend_from_slice(&dst_ip.octets());
        }
        _ => bail!("source and destination address families differ"),
    }
    out.extend_from_slice(&src.port().to_be_bytes());
    out.extend_from_slice(&dst.port().to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::BytesMut;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn accepted_user_conn_splices_to_matching_data_conn_in_memory() {
        let cancel = CancellationToken::new();
        let pending: PendingMapFor<DuplexStream> = Arc::new(DashMap::new());
        let (control_tx, mut control_rx) = mpsc::channel(1);
        let (mut public_side, server_side) = duplex(4096);

        accept_user_conn(
            server_side,
            "mock-tunnel".into(),
            Some("203.0.113.7:51820".parse().unwrap()),
            Some("198.51.100.10:25565".parse().unwrap()),
            control_tx,
            pending.clone(),
            cancel.clone(),
        )
        .await;

        let ServerMessage::NewConn {
            id,
            tunnel,
            src_addr,
            dst_addr,
        } = control_rx.recv().await.unwrap()
        else {
            panic!("expected NewConn");
        };
        assert_eq!(tunnel, "mock-tunnel");
        assert_eq!(src_addr, Some("203.0.113.7:51820".parse().unwrap()));
        assert_eq!(dst_addr, Some("198.51.100.10:25565".parse().unwrap()));
        assert!(pending.contains_key(&id));

        let (mut client_data, server_data) = duplex(4096);
        let (_, pending_tx) = pending.remove(&id).unwrap();
        assert!(pending_tx
            .send(Prefixed::new(BytesMut::new(), server_data))
            .is_ok());

        public_side.write_all(b"from-public").await.unwrap();
        let mut buf = [0u8; 11];
        timeout(Duration::from_secs(1), client_data.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"from-public");

        client_data.write_all(b"from-data").await.unwrap();
        let mut buf = [0u8; 9];
        timeout(Duration::from_secs(1), public_side.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"from-data");

        cancel.cancel();
    }

    #[tokio::test]
    async fn accepted_user_conn_removes_pending_when_cancelled_before_data_conn() {
        let cancel = CancellationToken::new();
        let pending: PendingMapFor<DuplexStream> = Arc::new(DashMap::new());
        let (control_tx, mut control_rx) = mpsc::channel(1);
        let (_public_side, server_side) = duplex(4096);

        accept_user_conn(
            server_side,
            "mock-tunnel".into(),
            None,
            None,
            control_tx,
            pending.clone(),
            cancel.clone(),
        )
        .await;

        let ServerMessage::NewConn { id, .. } = control_rx.recv().await.unwrap() else {
            panic!("expected NewConn");
        };
        assert!(pending.contains_key(&id));

        cancel.cancel();
        timeout(Duration::from_secs(1), async {
            while pending.contains_key(&id) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn proxy_v1_header_ipv4_is_exact() {
        let src = "203.0.113.7:51820".parse().unwrap();
        let dst = "198.51.100.10:25565".parse().unwrap();
        let header = proxy_header(ProxyProtocol::V1, src, dst).unwrap();
        assert_eq!(
            header,
            b"PROXY TCP4 203.0.113.7 198.51.100.10 51820 25565\r\n"
        );
    }

    #[test]
    fn proxy_v1_header_ipv6_is_exact() {
        let src = "[2001:db8::1]:51820".parse().unwrap();
        let dst = "[2001:db8::2]:25565".parse().unwrap();
        let header = proxy_header(ProxyProtocol::V1, src, dst).unwrap();
        assert_eq!(
            header,
            b"PROXY TCP6 2001:db8::1 2001:db8::2 51820 25565\r\n"
        );
    }

    #[test]
    fn proxy_v2_header_ipv4_is_exact() {
        let src = "203.0.113.7:51820".parse().unwrap();
        let dst = "198.51.100.10:25565".parse().unwrap();
        let header = proxy_header(ProxyProtocol::V2, src, dst).unwrap();
        assert_eq!(
            header,
            vec![
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11,
                0x00, 0x0c, 203, 0, 113, 7, 198, 51, 100, 10, 0xca, 0x6c, 0x63, 0xdd,
            ]
        );
    }

    #[test]
    fn proxy_v2_header_ipv6_is_exact() {
        let src = "[2001:db8::1]:51820".parse().unwrap();
        let dst = "[2001:db8::2]:25565".parse().unwrap();
        let header = proxy_header(ProxyProtocol::V2, src, dst).unwrap();
        assert_eq!(
            header,
            vec![
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x21,
                0x00, 0x24, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x20, 0x01,
                0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0xca, 0x6c, 0x63, 0xdd,
            ]
        );
    }
}
