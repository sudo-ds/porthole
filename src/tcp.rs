//! TCP relay, both sides.
//!
//! Server: a public listener accepts an end-user connection, registers a pending accept
//! keyed by a fresh id, tells the client over the control channel, and splices the two
//! sockets once the client dials back the matching data connection.
//!
//! Client: on `NewConn`, dial a data connection (identified by the same id) and the local
//! target, then splice them.

use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::client::ClientShared;
use crate::net;
use crate::protocol::{self, Prefixed, ServerMessage, ACCEPT_TIMEOUT};
use crate::server::ServerTls;

/// Pending TCP accepts awaiting their data connection, keyed by connection id.
pub type PendingMap = Arc<DashMap<Uuid, oneshot::Sender<Prefixed<ServerTls>>>>;

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
                let (user, _peer) = match res {
                    Ok(x) => x,
                    Err(e) => { tracing::debug!("accept on tunnel '{tunnel}': {e}"); break; }
                };
                net::set_keepalive(&user);

                let id = Uuid::new_v4();
                let (tx, rx) = oneshot::channel::<Prefixed<ServerTls>>();
                pending.insert(id, tx);

                if control_tx
                    .send(ServerMessage::NewConn { id, tunnel: tunnel.clone() })
                    .await
                    .is_err()
                {
                    pending.remove(&id); // control gone
                    break;
                }

                let pending = pending.clone();
                let splice_cancel = cancel.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = splice_cancel.cancelled() => {
                            pending.remove(&id);
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
                                    pending.remove(&id);
                                }
                            }
                        }
                    }
                });
            }
        }
    }
}

/// Client side: handle one `NewConn` by splicing a data conn to the local service.
pub async fn client_handle_conn(
    shared: Arc<ClientShared>,
    id: Uuid,
    tunnel: String,
    cancel: CancellationToken,
) {
    let (local, counters) = match shared.status.get(&tunnel) {
        Some(s) => (s.local_addr, s.counters.clone()),
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
