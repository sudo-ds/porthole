//! Wire protocol shared by client and server.
//!
//! Every connection is a TLS stream carrying length-delimited frames (4-byte big-endian
//! length prefix). Control frames are JSON-encoded [`ClientMessage`]/[`ServerMessage`];
//! UDP data frames are the compact binary encoding produced by [`encode_udp`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{bail, ensure, Context as _, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants (defaults; several are overridable via config)
// ---------------------------------------------------------------------------

pub const DEFAULT_CONTROL_PORT: u16 = 7835;
pub const DEFAULT_WEB_BIND: &str = "127.0.0.1:4040";
/// Max length-delimited frame. Must exceed the largest UDP datagram (`udp::MAX_DATAGRAM`,
/// 65535) plus the 19-byte address header, or a maximum-size datagram would be rejected by
/// the codec and tear down the whole channel. 64 KiB + slack covers it; control JSON is tiny.
pub const MAX_FRAME: usize = 64 * 1024 + 256;
pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(3);
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub const LIVENESS_TIMEOUT: Duration = Duration::from_secs(15);
pub const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
pub const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Protocol type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl std::fmt::Display for Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Proto::Tcp => write!(f, "tcp"),
            Proto::Udp => write!(f, "udp"),
        }
    }
}

impl std::str::FromStr for Proto {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Proto::Tcp),
            "udp" => Ok(Proto::Udp),
            other => bail!("invalid protocol {other:?} (expected `tcp` or `udp`)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Control messages
// ---------------------------------------------------------------------------

/// Sent client -> server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMessage {
    /// First frame on a control connection: bearer token (compared in constant time).
    Hello {
        token: String,
    },
    /// First frame on a data connection: bearer token + the id this connection fulfils
    /// (a pending TCP accept's conn id, or a UDP tunnel's token).
    DataHello {
        token: String,
        id: Uuid,
    },
    /// Request a public tunnel.
    Register {
        name: String,
        proto: Proto,
        remote_port: Option<u16>,
    },
    /// Remove a previously registered tunnel.
    Unregister {
        name: String,
    },
    Heartbeat,
}

/// Sent server -> client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMessage {
    /// First frame after a successful control `Hello`: the allowed public-port range.
    Welcome {
        min_port: u16,
        max_port: u16,
    },
    /// A tunnel was granted. `token` (UDP only) is the capability for its data channel.
    Accepted {
        name: String,
        proto: Proto,
        public_addr: String,
        remote_port: u16,
        token: Option<Uuid>,
    },
    /// A registration was refused (port out of range, already in use, ...).
    Rejected {
        name: String,
        reason: String,
    },
    /// A public TCP connection arrived; dial back a data connection with this id.
    NewConn {
        id: Uuid,
        tunnel: String,
    },
    Heartbeat,
    Error {
        message: String,
        fatal: bool,
    },
}

// ---------------------------------------------------------------------------
// Length-delimited framing
// ---------------------------------------------------------------------------

pub type Wire<S> = Framed<S, LengthDelimitedCodec>;

/// Wrap an IO stream in the standard length-delimited framing.
pub fn wire<S: AsyncRead + AsyncWrite>(io: S) -> Wire<S> {
    LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME)
        .length_field_type::<u32>()
        .new_framed(io)
}

/// Serialize and send one JSON control message.
pub async fn send_msg<S, M>(w: &mut Wire<S>, msg: &M) -> Result<()>
where
    S: AsyncWrite + Unpin,
    M: Serialize,
{
    let bytes = serde_json::to_vec(msg)?;
    ensure!(
        bytes.len() <= MAX_FRAME,
        "outgoing message exceeds MAX_FRAME"
    );
    w.send(Bytes::from(bytes)).await?;
    Ok(())
}

/// Receive and decode one JSON control message.
pub async fn recv_msg<S, M>(w: &mut Wire<S>) -> Result<M>
where
    S: AsyncRead + Unpin,
    M: DeserializeOwned,
{
    let frame = w.next().await.context("connection closed")??;
    Ok(serde_json::from_slice(&frame)?)
}

/// Like [`recv_msg`] but fails if no frame arrives within `dur`.
pub async fn recv_msg_timeout<S, M>(w: &mut Wire<S>, dur: Duration) -> Result<M>
where
    S: AsyncRead + Unpin,
    M: DeserializeOwned,
{
    tokio::time::timeout(dur, recv_msg(w))
        .await
        .context("timed out waiting for frame")?
}

/// Send one raw binary frame (a UDP datagram payload).
pub async fn send_frame<S: AsyncWrite + Unpin>(w: &mut Wire<S>, bytes: Bytes) -> Result<()> {
    w.send(bytes).await?;
    Ok(())
}

/// Receive one raw binary frame.
pub async fn recv_frame<S: AsyncRead + Unpin>(w: &mut Wire<S>) -> Result<BytesMut> {
    Ok(w.next().await.context("connection closed")??)
}

// ---------------------------------------------------------------------------
// Binary UDP datagram codec: [family u8 (4|6)][ip 4|16][port u16 BE][payload..]
// ---------------------------------------------------------------------------

pub fn encode_udp(peer: SocketAddr, data: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(19 + data.len());
    match peer.ip() {
        IpAddr::V4(ip) => {
            buf.put_u8(4);
            buf.put_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.put_u8(6);
            buf.put_slice(&ip.octets());
        }
    }
    buf.put_u16(peer.port());
    buf.put_slice(data);
    buf.freeze()
}

pub fn decode_udp(buf: &[u8]) -> Result<(SocketAddr, &[u8])> {
    let (&family, rest) = buf.split_first().context("empty udp frame")?;
    match family {
        4 => {
            ensure!(rest.len() >= 6, "short ipv4 udp frame");
            let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            Ok((SocketAddr::new(IpAddr::V4(ip), port), &rest[6..]))
        }
        6 => {
            ensure!(rest.len() >= 18, "short ipv6 udp frame");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rest[..16]);
            let port = u16::from_be_bytes([rest[16], rest[17]]);
            Ok((
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port),
                &rest[18..],
            ))
        }
        other => bail!("invalid udp address family {other}"),
    }
}

// ---------------------------------------------------------------------------
// Prefixed: hand a framed stream off to a raw byte splice without losing bytes
// the codec already read past the last frame.
// ---------------------------------------------------------------------------

pub struct Prefixed<S> {
    prefix: BytesMut,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: BytesMut, inner: S) -> Self {
        Self { prefix, inner }
    }
}

/// Convert a framed connection back into a raw byte stream after the handshake frames,
/// preserving any already-buffered bytes (the start of the tunneled payload).
pub fn into_raw<S>(w: Wire<S>) -> Prefixed<S> {
    let parts = w.into_parts();
    Prefixed::new(parts.read_buf, parts.io)
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let n = std::cmp::min(this.prefix.len(), buf.remaining());
            buf.put_slice(&this.prefix[..n]);
            this.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_roundtrip_v4() {
        let peer: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let data = b"hello world";
        let frame = encode_udp(peer, data);
        let (got_peer, got_data) = decode_udp(&frame).unwrap();
        assert_eq!(got_peer, peer);
        assert_eq!(got_data, data);
    }

    #[test]
    fn udp_roundtrip_v6() {
        let peer: SocketAddr = "[2001:db8::1]:9999".parse().unwrap();
        let data = b"\x00\x01\x02\xff";
        let frame = encode_udp(peer, data);
        let (got_peer, got_data) = decode_udp(&frame).unwrap();
        assert_eq!(got_peer, peer);
        assert_eq!(got_data, data);
    }

    #[test]
    fn udp_zero_length_payload() {
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let frame = encode_udp(peer, b"");
        let (got_peer, got_data) = decode_udp(&frame).unwrap();
        assert_eq!(got_peer, peer);
        assert!(got_data.is_empty());
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(decode_udp(b"").is_err());
        assert!(decode_udp(&[4, 1, 2, 3]).is_err()); // v4 needs 6 trailing bytes
        assert!(decode_udp(&[9]).is_err()); // bad family
    }

    #[test]
    fn message_json_roundtrip() {
        let msgs = vec![
            ClientMessage::Hello {
                token: "secret".into(),
            },
            ClientMessage::DataHello {
                token: "secret".into(),
                id: Uuid::nil(),
            },
            ClientMessage::Register {
                name: "mc".into(),
                proto: Proto::Tcp,
                remote_port: Some(25565),
            },
            ClientMessage::Register {
                name: "g".into(),
                proto: Proto::Udp,
                remote_port: None,
            },
            ClientMessage::Unregister { name: "mc".into() },
            ClientMessage::Heartbeat,
        ];
        for m in msgs {
            let j = serde_json::to_vec(&m).unwrap();
            let back: ClientMessage = serde_json::from_slice(&j).unwrap();
            assert_eq!(m, back);
        }

        let s = ServerMessage::Accepted {
            name: "mc".into(),
            proto: Proto::Udp,
            public_addr: "203.0.113.7:25565".into(),
            remote_port: 25565,
            token: Some(Uuid::nil()),
        };
        let j = serde_json::to_vec(&s).unwrap();
        let back: ServerMessage = serde_json::from_slice(&j).unwrap();
        assert_eq!(s, back);
    }

    #[tokio::test]
    async fn framed_message_roundtrip() {
        let (a, b) = tokio::io::duplex(4096);
        let mut wa = wire(a);
        let mut wb = wire(b);
        let sent = ServerMessage::NewConn {
            id: Uuid::nil(),
            tunnel: "mc".into(),
        };
        send_msg(&mut wa, &sent).await.unwrap();
        let got: ServerMessage = recv_msg(&mut wb).await.unwrap();
        assert_eq!(sent, got);
    }

    #[tokio::test]
    async fn oversized_message_rejected() {
        let (a, _b) = tokio::io::duplex(4096);
        let mut wa = wire(a);
        let big = ClientMessage::Hello {
            token: "x".repeat(MAX_FRAME + 1),
        };
        assert!(send_msg(&mut wa, &big).await.is_err());
    }
}
