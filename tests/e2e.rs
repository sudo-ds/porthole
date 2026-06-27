//! End-to-end tests: spin up a server + client in-process against localhost echo targets
//! and push real bytes through the relay.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use porthole::config::{ClientFile, ClientSettings, ServerSettings, TunnelConfig};
use porthole::protocol::{self, ClientMessage, Proto, ServerMessage};
use porthole::{client, server, tls};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn install() {
    let _ = porthole::install_crypto_provider();
}

/// Grab a likely-free port (small reuse race is acceptable for tests).
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn temp_paths(tag: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("porthole-e2e-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let _ = std::fs::remove_file(dir.join("c.crt"));
    let _ = std::fs::remove_file(dir.join("c.key"));
    (dir.join("c.crt"), dir.join("c.key"))
}

async fn tcp_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        while let Ok((n, peer)) = s.recv_from(&mut buf).await {
            let _ = s.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

fn server_settings(ingress: u16, public: u16, cert: PathBuf, key: PathBuf) -> ServerSettings {
    ServerSettings {
        bind_addr: "127.0.0.1".into(),
        control_port: ingress,
        secret: "test-secret".into(),
        min_port: public,
        max_port: public,
        cert_path: cert,
        key_path: key,
        public_host: None,
    }
}

fn client_settings(ingress: u16, fingerprint: String, tunnel: TunnelConfig) -> ClientSettings {
    ClientSettings {
        server_addr: format!("127.0.0.1:{ingress}"),
        server_fingerprint: fingerprint,
        web_bind: "127.0.0.1:0".into(),
        secret: "test-secret".into(),
        config_path: None,
        file: ClientFile {
            tunnels: vec![tunnel],
            ..Default::default()
        },
    }
}

/// Start the server, generating its cert first so we can pin the fingerprint on the client.
fn start_relay(ingress: u16, public: u16, tag: &str, tunnel: TunnelConfig) {
    let (cert, key) = temp_paths(tag);
    let ss = server_settings(ingress, public, cert, key);
    let (_acceptor, fingerprint) = tls::server_acceptor(&ss).expect("generate cert");
    tokio::spawn(server::run(ss));
    tokio::spawn(client::run(client_settings(ingress, fingerprint, tunnel)));
}

async fn connect_retry(addr: SocketAddr) -> TcpStream {
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(addr).await {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("relay never came up at {addr}");
}

#[tokio::test]
async fn tcp_tunnel_roundtrip() {
    install();
    let echo = tcp_echo().await;
    let (ingress, public) = (free_port(), free_port());
    let tunnel = TunnelConfig {
        name: "t".into(),
        protocol: Proto::Tcp,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
    };
    start_relay(ingress, public, "tcp", tunnel);

    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();

    // Two sequential connections, to confirm the listener keeps serving.
    for msg in [
        b"hello porthole".as_slice(),
        b"second connection".as_slice(),
    ] {
        let mut conn = connect_retry(public_addr).await;
        conn.write_all(msg).await.unwrap();
        let mut buf = vec![0u8; msg.len()];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, msg);
    }
}

#[tokio::test]
async fn udp_tunnel_roundtrip() {
    install();
    let echo = udp_echo().await;
    let (ingress, public) = (free_port(), free_port());
    let tunnel = TunnelConfig {
        name: "u".into(),
        protocol: Proto::Udp,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
    };
    start_relay(ingress, public, "udp", tunnel);

    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Retry until the relay + UDP data channel are up and a datagram echoes back.
    let mut buf = [0u8; 64];
    let mut got: Option<Vec<u8>> = None;
    for _ in 0..100 {
        let _ = sock.send_to(b"ping", public_addr).await;
        match tokio::time::timeout(Duration::from_millis(150), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                got = Some(buf[..n].to_vec());
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    assert_eq!(got.as_deref(), Some(b"ping".as_slice()));
}

#[tokio::test]
async fn udp_large_datagram_roundtrip() {
    install();
    let echo = udp_echo().await;
    let (ingress, public) = (free_port(), free_port());
    let tunnel = TunnelConfig {
        name: "u".into(),
        protocol: Proto::Udp,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
    };
    start_relay(ingress, public, "udp-large", tunnel);

    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // A large datagram exercises the framing path near MAX_FRAME (payload + address header);
    // it must survive the round trip rather than tripping the codec's frame-length limit.
    let payload = vec![0xABu8; 60_000];
    let mut buf = vec![0u8; 65_535];
    let mut got: Option<Vec<u8>> = None;
    for _ in 0..100 {
        let _ = sock.send_to(&payload, public_addr).await;
        match tokio::time::timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                got = Some(buf[..n].to_vec());
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    assert_eq!(got.as_deref(), Some(payload.as_slice()));
}

#[tokio::test]
async fn client_reconnects_when_server_starts_late() {
    install();
    let echo = tcp_echo().await;
    let (ingress, public) = (free_port(), free_port());
    let (cert, key) = temp_paths("reconnect");
    let ss = server_settings(ingress, public, cert, key);
    // Generate the cert up front so the client can pin it before the server is running.
    let (_acceptor, fingerprint) = tls::server_acceptor(&ss).expect("generate cert");

    // Client starts first: the server isn't up, so it must back off and retry.
    let tunnel = TunnelConfig {
        name: "t".into(),
        protocol: Proto::Tcp,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
    };
    tokio::spawn(client::run(client_settings(ingress, fingerprint, tunnel)));

    tokio::time::sleep(Duration::from_millis(500)).await;
    tokio::spawn(server::run(ss));

    // Once the client reconnects and re-registers, the relay should carry bytes.
    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    let mut conn = connect_retry(public_addr).await;
    let msg = b"after reconnect";
    conn.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, msg);
}

#[tokio::test]
async fn out_of_range_register_is_rejected() {
    install();
    let (ingress, public) = (free_port(), free_port());
    let (cert, key) = temp_paths("range");
    // The allowed range is exactly [public, public].
    let ss = server_settings(ingress, public, cert, key);
    let (_acceptor, fingerprint) = tls::server_acceptor(&ss).expect("cert");
    tokio::spawn(server::run(ss));

    // A raw TLS client (not the full porthole client) so we can inspect the handshake.
    let connector = tls::client_connector(&fingerprint).unwrap();
    let stream = loop {
        match TcpStream::connect(("127.0.0.1", ingress)).await {
            Ok(s) => break s,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    };
    let tls = connector
        .connect(tls::pinned_server_name(), stream)
        .await
        .unwrap();
    let mut wire = protocol::wire(tls);

    protocol::send_msg(
        &mut wire,
        &ClientMessage::Hello {
            token: "test-secret".into(),
        },
    )
    .await
    .unwrap();

    // The server advertises its allowed range first.
    let welcome: ServerMessage = protocol::recv_msg_timeout(&mut wire, Duration::from_secs(5))
        .await
        .unwrap();
    match welcome {
        ServerMessage::Welcome { min_port, max_port } => {
            assert_eq!((min_port, max_port), (public, public));
        }
        other => panic!("expected Welcome, got {other:?}"),
    }

    // Request a port that is out of range and expect a tunnel-scoped rejection.
    let bad = if public == u16::MAX {
        public - 1
    } else {
        public + 1
    };
    protocol::send_msg(
        &mut wire,
        &ClientMessage::Register {
            name: "x".into(),
            proto: Proto::Tcp,
            remote_port: Some(bad),
        },
    )
    .await
    .unwrap();

    let reply: ServerMessage = protocol::recv_msg_timeout(&mut wire, Duration::from_secs(5))
        .await
        .unwrap();
    match reply {
        ServerMessage::Rejected { name, reason } => {
            assert_eq!(name, "x");
            assert!(reason.contains("range"), "reason was: {reason}");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn join_via_connection_code() {
    install();
    let echo = tcp_echo().await;
    let (ingress, public) = (free_port(), free_port());
    let (cert, key) = temp_paths("invite");
    let ss = server_settings(ingress, public, cert, key);
    let (_acceptor, fingerprint) = tls::server_acceptor(&ss).expect("cert");
    tokio::spawn(server::run(ss));

    // Build the connection code the server would print, then decode it on the client side.
    let code = porthole::invite::encode(&porthole::invite::ConnectionInfo {
        host: "127.0.0.1".into(),
        port: ingress,
        fingerprint,
        secret: "test-secret".into(),
    });
    let info = porthole::invite::decode(&code).unwrap();
    assert_eq!(info.server_addr(), format!("127.0.0.1:{ingress}"));

    let tunnel = TunnelConfig {
        name: "t".into(),
        protocol: Proto::Tcp,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
    };
    let settings = ClientSettings {
        server_addr: info.server_addr(),
        server_fingerprint: info.fingerprint,
        web_bind: "127.0.0.1:0".into(),
        secret: info.secret,
        config_path: None,
        file: ClientFile {
            tunnels: vec![tunnel],
            ..Default::default()
        },
    };
    tokio::spawn(client::run(settings));

    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    let mut conn = connect_retry(public_addr).await;
    let msg = b"hello via code";
    conn.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, msg);
}
