//! Wire protocol shared by client and server.
//!
//! Control and encrypted data connections use length-delimited frames (4-byte big-endian
//! length prefix). Control frames are JSON-encoded [`ClientMessage`]/[`ServerMessage`];
//! UDP data frames are the compact binary encoding produced by [`encode_udp`]. Plaintext
//! UDP data channels use authenticated `PTHU` packets with optional fragmentation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{bail, ensure, Context as _, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
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
pub const UDP_PLAINTEXT_KEEPALIVE: Duration = Duration::from_secs(5);
/// Default native UDP relay packet size, excluding outer IP/UDP headers.
pub const DEFAULT_UDP_MTU: u16 = 1200;
pub const MIN_UDP_MTU: u16 = 256;
/// Maximum UDP payload size for an IPv4 datagram.
pub const MAX_UDP_MTU: u16 = 65_507;
pub const UDP_PLAINTEXT_MAX_PACKET: usize = MAX_UDP_MTU as usize;
pub const UDP_PLAINTEXT_OVERHEAD: usize = 4 + 1 + 1 + 8 + 16;
pub const UDP_PLAINTEXT_MAX_BODY: usize = UDP_PLAINTEXT_MAX_PACKET - UDP_PLAINTEXT_OVERHEAD;
pub const UDP_PLAINTEXT_FRAGMENT_HEADER: usize = 8 + 2 + 2 + 4;
pub const UDP_PLAINTEXT_MAX_ENCAPSULATED: usize = 65_535 + 19;

// ---------------------------------------------------------------------------
// Protocol type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    Both,
}

impl Proto {
    pub fn has_tcp(self) -> bool {
        matches!(self, Proto::Tcp | Proto::Both)
    }

    pub fn has_udp(self) -> bool {
        matches!(self, Proto::Udp | Proto::Both)
    }
}

impl std::fmt::Display for Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Proto::Tcp => write!(f, "tcp"),
            Proto::Udp => write!(f, "udp"),
            Proto::Both => write!(f, "both"),
        }
    }
}

impl std::str::FromStr for Proto {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Proto::Tcp),
            "udp" => Ok(Proto::Udp),
            "both" => Ok(Proto::Both),
            other => bail!("invalid protocol {other:?} (expected `tcp`, `udp`, or `both`)"),
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
    /// (a pending TCP accept's conn id, or a UDP-capable tunnel's token).
    DataHello {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data_auth: Option<String>,
    },
    /// Request a public tunnel.
    Register {
        name: String,
        proto: Proto,
        remote_port: Option<u16>,
        #[serde(default)]
        encrypted: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_mtu: Option<u16>,
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
    /// A tunnel was granted. `token` (UDP-capable tunnels only) is the capability for its data channel.
    Accepted {
        name: String,
        proto: Proto,
        public_addr: String,
        remote_port: u16,
        #[serde(default)]
        encrypted: bool,
        token: Option<Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_auth_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_mtu: Option<u16>,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        src_addr: Option<SocketAddr>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dst_addr: Option<SocketAddr>,
        #[serde(default)]
        encrypted: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data_auth: Option<String>,
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
// Authenticated plaintext UDP data packets.
// [magic "PTHU"][version u8][kind u8][seq u64 BE][body..][hmac16]
// ---------------------------------------------------------------------------

type HmacSha256 = Hmac<Sha256>;

const UDP_PLAINTEXT_MAGIC: &[u8; 4] = b"PTHU";
const UDP_PLAINTEXT_VERSION: u8 = 1;
const UDP_PLAINTEXT_TAG: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlainUdpKind {
    Hello,
    Data,
    Keepalive,
    Fragment,
}

impl PlainUdpKind {
    fn code(self) -> u8 {
        match self {
            Self::Hello => 1,
            Self::Data => 2,
            Self::Keepalive => 3,
            Self::Fragment => 4,
        }
    }

    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Data),
            3 => Ok(Self::Keepalive),
            4 => Ok(Self::Fragment),
            other => bail!("invalid plaintext udp packet kind {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainUdpFragment<'a> {
    pub fragment_id: u64,
    pub fragment_index: u16,
    pub fragment_count: u16,
    pub total_len: u32,
    pub chunk: &'a [u8],
}

pub fn encode_udp_auth_key(key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(key)
}

pub fn decode_udp_auth_key(s: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s.trim().as_bytes())
        .context("udp auth key is not valid base64url")?;
    ensure!(bytes.len() == 32, "udp auth key must be 32 bytes");
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn encode_udp_fragment_body(
    fragment_id: u64,
    fragment_index: u16,
    fragment_count: u16,
    total_len: u32,
    chunk: &[u8],
) -> Option<Bytes> {
    if fragment_count == 0 || fragment_index >= fragment_count || total_len == 0 || chunk.is_empty()
    {
        return None;
    }
    if total_len as usize > UDP_PLAINTEXT_MAX_ENCAPSULATED {
        return None;
    }
    let mut out = BytesMut::with_capacity(UDP_PLAINTEXT_FRAGMENT_HEADER + chunk.len());
    out.put_u64(fragment_id);
    out.put_u16(fragment_index);
    out.put_u16(fragment_count);
    out.put_u32(total_len);
    out.put_slice(chunk);
    Some(out.freeze())
}

pub fn decode_udp_fragment_body(body: &[u8]) -> Result<PlainUdpFragment<'_>> {
    ensure!(
        body.len() > UDP_PLAINTEXT_FRAGMENT_HEADER,
        "short plaintext udp fragment"
    );
    let fragment_id = u64::from_be_bytes(body[0..8].try_into().unwrap());
    let fragment_index = u16::from_be_bytes(body[8..10].try_into().unwrap());
    let fragment_count = u16::from_be_bytes(body[10..12].try_into().unwrap());
    let total_len = u32::from_be_bytes(body[12..16].try_into().unwrap());
    let chunk = &body[UDP_PLAINTEXT_FRAGMENT_HEADER..];
    ensure!(fragment_count > 0, "zero plaintext udp fragment count");
    ensure!(
        fragment_index < fragment_count,
        "plaintext udp fragment index out of range"
    );
    ensure!(total_len > 0, "zero plaintext udp fragment total length");
    ensure!(
        total_len as usize <= UDP_PLAINTEXT_MAX_ENCAPSULATED,
        "plaintext udp fragment total length is too large"
    );
    ensure!(!chunk.is_empty(), "empty plaintext udp fragment chunk");
    ensure!(
        fragment_count as usize <= total_len as usize,
        "plaintext udp fragment count exceeds total length"
    );
    ensure!(
        chunk.len() <= total_len as usize,
        "plaintext udp fragment chunk exceeds total length"
    );
    Ok(PlainUdpFragment {
        fragment_id,
        fragment_index,
        fragment_count,
        total_len,
        chunk,
    })
}

pub fn encode_plain_udp(
    kind: PlainUdpKind,
    seq: u64,
    body: &[u8],
    key: &[u8; 32],
) -> Option<Bytes> {
    if body.len() > UDP_PLAINTEXT_MAX_BODY {
        return None;
    }

    let mut out = BytesMut::with_capacity(UDP_PLAINTEXT_OVERHEAD + body.len());
    out.put_slice(UDP_PLAINTEXT_MAGIC);
    out.put_u8(UDP_PLAINTEXT_VERSION);
    out.put_u8(kind.code());
    out.put_u64(seq);
    out.put_slice(body);

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&out);
    let tag = mac.finalize().into_bytes();
    out.put_slice(&tag[..UDP_PLAINTEXT_TAG]);
    Some(out.freeze())
}

pub fn decode_plain_udp<'a>(
    packet: &'a [u8],
    key: &[u8; 32],
) -> Result<(PlainUdpKind, u64, &'a [u8])> {
    ensure!(
        packet.len() >= UDP_PLAINTEXT_OVERHEAD,
        "short plaintext udp packet"
    );
    ensure!(
        &packet[..4] == UDP_PLAINTEXT_MAGIC,
        "bad plaintext udp magic"
    );
    ensure!(
        packet[4] == UDP_PLAINTEXT_VERSION,
        "bad plaintext udp version"
    );

    let tag_start = packet.len() - UDP_PLAINTEXT_TAG;
    let (signed, tag) = packet.split_at(tag_start);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(signed);
    let expected = mac.finalize().into_bytes();
    ensure!(
        bool::from(expected[..UDP_PLAINTEXT_TAG].ct_eq(tag)),
        "bad plaintext udp auth tag"
    );

    let kind = PlainUdpKind::from_code(packet[5])?;
    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&packet[6..14]);
    Ok((kind, u64::from_be_bytes(seq_bytes), &packet[14..tag_start]))
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
    fn proto_both_parses_displays_and_serializes() {
        let proto: Proto = "both".parse().unwrap();
        assert_eq!(proto, Proto::Both);
        assert!(proto.has_tcp());
        assert!(proto.has_udp());
        assert_eq!(proto.to_string(), "both");

        let json = serde_json::to_string(&proto).unwrap();
        assert_eq!(json, "\"both\"");
        assert_eq!(serde_json::from_str::<Proto>(&json).unwrap(), Proto::Both);
    }

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
    fn plaintext_udp_packet_roundtrip_and_auth_rejects_tamper() {
        let key = [7u8; 32];
        let packet = encode_plain_udp(PlainUdpKind::Data, 42, b"hello", &key).unwrap();
        let (kind, seq, body) = decode_plain_udp(&packet, &key).unwrap();
        assert_eq!(kind, PlainUdpKind::Data);
        assert_eq!(seq, 42);
        assert_eq!(body, b"hello");

        let mut tampered = packet.to_vec();
        tampered[14] ^= 0x01;
        assert!(decode_plain_udp(&tampered, &key).is_err());
    }

    #[test]
    fn plaintext_udp_rejects_bad_magic_version_and_oversize() {
        let key = [9u8; 32];
        let packet = encode_plain_udp(PlainUdpKind::Keepalive, 0, b"", &key).unwrap();

        let mut bad_magic = packet.to_vec();
        bad_magic[0] = b'X';
        assert!(decode_plain_udp(&bad_magic, &key).is_err());

        let mut bad_version = packet.to_vec();
        bad_version[4] = 2;
        assert!(decode_plain_udp(&bad_version, &key).is_err());

        let too_big = vec![0u8; UDP_PLAINTEXT_MAX_BODY + 1];
        assert!(encode_plain_udp(PlainUdpKind::Data, 0, &too_big, &key).is_none());
    }

    #[test]
    fn plaintext_udp_fragment_body_roundtrip_and_rejects_bad_metadata() {
        let body = encode_udp_fragment_body(99, 1, 3, 12, b"abcd").unwrap();
        let got = decode_udp_fragment_body(&body).unwrap();
        assert_eq!(got.fragment_id, 99);
        assert_eq!(got.fragment_index, 1);
        assert_eq!(got.fragment_count, 3);
        assert_eq!(got.total_len, 12);
        assert_eq!(got.chunk, b"abcd");

        assert!(encode_udp_fragment_body(1, 0, 0, 4, b"x").is_none());
        assert!(encode_udp_fragment_body(1, 2, 2, 4, b"x").is_none());
        assert!(encode_udp_fragment_body(1, 0, 1, 0, b"x").is_none());
        assert!(encode_udp_fragment_body(1, 0, 1, 4, b"").is_none());

        let short = [0u8; UDP_PLAINTEXT_FRAGMENT_HEADER];
        assert!(decode_udp_fragment_body(&short).is_err());
        let bad_count = encode_udp_fragment_body(1, 0, 5, 4, b"x").unwrap();
        assert!(decode_udp_fragment_body(&bad_count).is_err());
    }

    #[test]
    fn udp_auth_key_roundtrip() {
        let key = [3u8; 32];
        let text = encode_udp_auth_key(&key);
        assert_eq!(decode_udp_auth_key(&text).unwrap(), key);
        assert!(decode_udp_auth_key("nope").is_err());
    }

    #[test]
    fn message_json_roundtrip() {
        let msgs = vec![
            ClientMessage::Hello {
                token: "secret".into(),
            },
            ClientMessage::DataHello {
                token: Some("secret".into()),
                id: Uuid::nil(),
                data_auth: None,
            },
            ClientMessage::Register {
                name: "mc".into(),
                proto: Proto::Tcp,
                remote_port: Some(25565),
                encrypted: false,
                udp_mtu: None,
            },
            ClientMessage::Register {
                name: "g".into(),
                proto: Proto::Udp,
                remote_port: None,
                encrypted: false,
                udp_mtu: Some(DEFAULT_UDP_MTU),
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
            encrypted: false,
            token: Some(Uuid::nil()),
            udp_auth_key: None,
            udp_mtu: Some(DEFAULT_UDP_MTU),
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
            src_addr: Some("203.0.113.7:51820".parse().unwrap()),
            dst_addr: Some("198.51.100.10:25565".parse().unwrap()),
            encrypted: false,
            data_auth: None,
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
