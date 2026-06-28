//! End-to-end tests: spin up a server + client in-process against localhost echo targets
//! and push real bytes through the relay.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use porthole::config::{ClientFile, ClientSettings, ProxyProtocol, ServerSettings, TunnelConfig};
use porthole::protocol::{self, ClientMessage, Proto, ServerMessage};
use porthole::{client, server, tls};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};

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

fn temp_client_config(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("porthole-e2e-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("client.toml");
    let _ = std::fs::remove_file(&path);
    path
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

async fn tcp_proxy_echo(
    mode: ProxyProtocol,
    expected_public_port: u16,
) -> (
    SocketAddr,
    oneshot::Receiver<std::result::Result<(), String>>,
) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (report_tx, report_rx) = oneshot::channel();
    tokio::spawn(async move {
        let Ok((mut s, _)) = l.accept().await else {
            let _ = report_tx.send(Err("proxy test server accept failed".into()));
            return;
        };
        let result = verify_proxy_header(&mut s, mode, expected_public_port).await;
        let ok = result.is_ok();
        let _ = report_tx.send(result);
        if !ok {
            return;
        }

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
    (addr, report_rx)
}

async fn verify_proxy_header(
    s: &mut TcpStream,
    mode: ProxyProtocol,
    expected_public_port: u16,
) -> std::result::Result<(), String> {
    match mode {
        ProxyProtocol::V1 => verify_proxy_v1(s, expected_public_port).await,
        ProxyProtocol::V2 => verify_proxy_v2(s, expected_public_port).await,
        ProxyProtocol::Off => Err("proxy mode must be v1 or v2".into()),
    }
}

async fn verify_proxy_v1(
    s: &mut TcpStream,
    expected_public_port: u16,
) -> std::result::Result<(), String> {
    let mut line = Vec::new();
    let mut one = [0u8; 1];
    loop {
        s.read_exact(&mut one).await.map_err(|e| e.to_string())?;
        line.push(one[0]);
        if line.ends_with(b"\r\n") {
            break;
        }
        if line.len() > 108 {
            return Err("PROXY v1 header too long".into());
        }
    }
    let text = String::from_utf8(line).map_err(|e| e.to_string())?;
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() != 6 {
        return Err(format!("expected 6 PROXY v1 parts, got {parts:?}"));
    }
    if parts[0] != "PROXY" || parts[1] != "TCP4" {
        return Err(format!("unexpected PROXY v1 prefix: {parts:?}"));
    }
    if parts[2] != "127.0.0.1" || parts[3] != "127.0.0.1" {
        return Err(format!("unexpected PROXY v1 addresses: {parts:?}"));
    }
    let src_port: u16 = parts[4].parse::<u16>().map_err(|e| e.to_string())?;
    let dst_port: u16 = parts[5].parse::<u16>().map_err(|e| e.to_string())?;
    if src_port == 0 || dst_port != expected_public_port {
        return Err(format!("unexpected PROXY v1 ports: {parts:?}"));
    }
    Ok(())
}

async fn verify_proxy_v2(
    s: &mut TcpStream,
    expected_public_port: u16,
) -> std::result::Result<(), String> {
    let mut header = [0u8; 16];
    s.read_exact(&mut header).await.map_err(|e| e.to_string())?;
    let sig = b"\r\n\r\n\0\r\nQUIT\n";
    if &header[..12] != sig {
        return Err(format!("bad PROXY v2 signature: {header:?}"));
    }
    if header[12] != 0x21 || header[13] != 0x11 {
        return Err(format!("unexpected PROXY v2 command/family: {header:?}"));
    }
    let len = u16::from_be_bytes([header[14], header[15]]) as usize;
    if len != 12 {
        return Err(format!("unexpected PROXY v2 IPv4 length: {len}"));
    }
    let mut addr = vec![0u8; len];
    s.read_exact(&mut addr).await.map_err(|e| e.to_string())?;
    if addr[..4] != [127, 0, 0, 1] || addr[4..8] != [127, 0, 0, 1] {
        return Err(format!("unexpected PROXY v2 addresses: {addr:?}"));
    }
    let src_port = u16::from_be_bytes([addr[8], addr[9]]);
    let dst_port = u16::from_be_bytes([addr[10], addr[11]]);
    if src_port == 0 || dst_port != expected_public_port {
        return Err(format!(
            "unexpected PROXY v2 ports: src={src_port} dst={dst_port}"
        ));
    }
    Ok(())
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

async fn udp_peer_report_echo() -> (SocketAddr, mpsc::Receiver<SocketAddr>) {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        while let Ok((n, peer)) = s.recv_from(&mut buf).await {
            let _ = tx.send(peer).await;
            let _ = s.send_to(&buf[..n], peer).await;
        }
    });
    (addr, rx)
}

async fn both_echo() -> SocketAddr {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).await.unwrap();

    tokio::spawn(async move {
        while let Ok((mut s, _)) = tcp.accept().await {
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

    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
            let _ = udp.send_to(&buf[..n], peer).await;
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
    client_settings_with(
        ingress,
        fingerprint,
        vec![tunnel],
        "127.0.0.1:0".into(),
        None,
        false,
    )
}

fn client_settings_with(
    ingress: u16,
    fingerprint: String,
    tunnels: Vec<TunnelConfig>,
    web_bind: String,
    config_path: Option<PathBuf>,
    tunnels_paused: bool,
) -> ClientSettings {
    ClientSettings {
        server_addr: format!("127.0.0.1:{ingress}"),
        server_fingerprint: fingerprint,
        web_bind,
        public_addr: None,
        secret: "test-secret".into(),
        config_path,
        file: ClientFile {
            tunnels_paused,
            tunnels,
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

async fn assert_udp_roundtrip(public_addr: SocketAddr, payload: &[u8]) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = vec![0u8; 65_535];
    let mut got: Option<Vec<u8>> = None;
    for _ in 0..100 {
        let _ = sock.send_to(payload, public_addr).await;
        match tokio::time::timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                got = Some(buf[..n].to_vec());
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    assert_eq!(got.as_deref(), Some(payload));
}

async fn connect_fails_for(addr: SocketAddr, attempts: usize) -> bool {
    for _ in 0..attempts {
        if TcpStream::connect(addr).await.is_ok() {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    true
}

async fn http_request(addr: SocketAddr, method: &str, path: &str) -> Option<String> {
    let mut s = TcpStream::connect(addr).await.ok()?;
    let req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.ok()?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(String::from_utf8_lossy(&buf).to_string())
}

async fn post_ok(addr: SocketAddr, path: &str) {
    let resp = http_request(addr, "POST", path)
        .await
        .expect("web response");
    assert!(resp.starts_with("HTTP/1.1 200"), "response was: {resp}");
}

async fn post_json(addr: SocketAddr, path: &str, body: serde_json::Value) -> String {
    let mut s = TcpStream::connect(addr).await.expect("web connect");
    let body = body.to_string();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8_lossy(&buf).to_string()
}

async fn wait_for_status(
    addr: SocketAddr,
    pred: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    for _ in 0..100 {
        if let Some(resp) = http_request(addr, "GET", "/api/status").await {
            if let Some((_, body)) = resp.split_once("\r\n\r\n") {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
                    if pred(&value) {
                        return value;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("web status did not reach expected state");
}

async fn wait_for_config_paused(path: &Path, paused: bool) {
    for _ in 0..100 {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(file) = toml::from_str::<ClientFile>(&text) {
                if file.tunnels_paused == paused {
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("config did not persist tunnels_paused = {paused}");
}

async fn assert_tcp_dropped(mut conn: TcpStream) {
    let mut one = [0u8; 1];
    for _ in 0..30 {
        match tokio::time::timeout(Duration::from_millis(100), conn.read(&mut one)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return,
            Ok(Ok(_)) => {}
            Err(_) => {
                if conn.write_all(b"x").await.is_err() {
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("active TCP connection stayed open after pause");
}

#[tokio::test]
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
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
        encrypted: false,
        udp_mtu: None,
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::Off,
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
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
async fn tcp_tunnel_encrypted_roundtrip() {
    install();
    let echo = tcp_echo().await;
    let (ingress, public) = (free_port(), free_port());
    let tunnel = TunnelConfig {
        name: "t".into(),
        protocol: Proto::Tcp,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
        encrypted: true,
        udp_mtu: None,
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::Off,
    };
    start_relay(ingress, public, "tcp-encrypted", tunnel);

    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    let mut conn = connect_retry(public_addr).await;
    conn.write_all(b"encrypted").await.unwrap();
    let mut buf = [0u8; 9];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"encrypted");
}

#[tokio::test]
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
async fn tcp_tunnel_proxy_protocol_v1_forwards_source_metadata() {
    install();
    let (ingress, public) = (free_port(), free_port());
    let (echo, report) = tcp_proxy_echo(ProxyProtocol::V1, public).await;
    let tunnel = TunnelConfig {
        name: "proxy-v1".into(),
        protocol: Proto::Tcp,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
        encrypted: false,
        udp_mtu: None,
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::V1,
    };
    start_relay(ingress, public, "proxy-v1", tunnel);

    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    let mut conn = connect_retry(public_addr).await;
    conn.write_all(b"hello-v1").await.unwrap();
    let mut buf = [0u8; 8];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello-v1");
    assert_eq!(report.await.unwrap(), Ok(()));
}

#[tokio::test]
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
async fn tcp_tunnel_proxy_protocol_v2_forwards_source_metadata() {
    install();
    let (ingress, public) = (free_port(), free_port());
    let (echo, report) = tcp_proxy_echo(ProxyProtocol::V2, public).await;
    let tunnel = TunnelConfig {
        name: "proxy-v2".into(),
        protocol: Proto::Tcp,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
        encrypted: false,
        udp_mtu: None,
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::V2,
    };
    start_relay(ingress, public, "proxy-v2", tunnel);

    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    let mut conn = connect_retry(public_addr).await;
    conn.write_all(b"hello-v2").await.unwrap();
    let mut buf = [0u8; 8];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello-v2");
    assert_eq!(report.await.unwrap(), Ok(()));
}

#[tokio::test]
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
async fn paused_client_does_not_register_enabled_tunnels() {
    install();
    let echo = tcp_echo().await;
    let (ingress, public, web) = (free_port(), free_port(), free_port());
    let (cert, key) = temp_paths("paused-start");
    let ss = server_settings(ingress, public, cert, key);
    let (_acceptor, fingerprint) = tls::server_acceptor(&ss).expect("generate cert");
    tokio::spawn(server::run(ss));

    let tunnel = TunnelConfig {
        name: "t".into(),
        protocol: Proto::Tcp,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
        encrypted: false,
        udp_mtu: None,
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::Off,
    };
    tokio::spawn(client::run(client_settings_with(
        ingress,
        fingerprint,
        vec![tunnel],
        format!("127.0.0.1:{web}"),
        None,
        true,
    )));

    let web_addr: SocketAddr = format!("127.0.0.1:{web}").parse().unwrap();
    wait_for_status(web_addr, |st| {
        st["connected"].as_bool() == Some(true) && st["paused"].as_bool() == Some(true)
    })
    .await;

    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    assert!(connect_fails_for(public_addr, 10).await);
}

#[tokio::test]
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
async fn web_pause_persists_drops_active_tcp_and_unpause_restores_enabled_only() {
    install();
    let echo = tcp_echo().await;
    let (ingress, enabled_port, disabled_port, web) =
        (free_port(), free_port(), free_port(), free_port());
    let (cert, key) = temp_paths("web-pause");
    let min_port = enabled_port.min(disabled_port);
    let max_port = enabled_port.max(disabled_port);
    let ss = ServerSettings {
        bind_addr: "127.0.0.1".into(),
        control_port: ingress,
        secret: "test-secret".into(),
        min_port,
        max_port,
        cert_path: cert,
        key_path: key,
        public_host: None,
    };
    let (_acceptor, fingerprint) = tls::server_acceptor(&ss).expect("generate cert");
    tokio::spawn(server::run(ss));

    let enabled = TunnelConfig {
        name: "enabled".into(),
        protocol: Proto::Tcp,
        local_addr: echo,
        remote_port: Some(enabled_port),
        enabled: true,
        encrypted: false,
        udp_mtu: None,
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::Off,
    };
    let disabled = TunnelConfig {
        name: "disabled".into(),
        protocol: Proto::Tcp,
        local_addr: echo,
        remote_port: Some(disabled_port),
        enabled: false,
        encrypted: false,
        udp_mtu: None,
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::Off,
    };
    let config_path = temp_client_config("web-pause");
    tokio::spawn(client::run(client_settings_with(
        ingress,
        fingerprint,
        vec![enabled, disabled],
        format!("127.0.0.1:{web}"),
        Some(config_path.clone()),
        false,
    )));

    let web_addr: SocketAddr = format!("127.0.0.1:{web}").parse().unwrap();
    wait_for_status(web_addr, |st| {
        st["connected"].as_bool() == Some(true) && st["paused"].as_bool() == Some(false)
    })
    .await;

    let enabled_addr: SocketAddr = format!("127.0.0.1:{enabled_port}").parse().unwrap();
    let disabled_addr: SocketAddr = format!("127.0.0.1:{disabled_port}").parse().unwrap();
    let mut active = connect_retry(enabled_addr).await;
    active.write_all(b"before").await.unwrap();
    let mut buf = [0u8; 6];
    active.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"before");
    assert!(connect_fails_for(disabled_addr, 5).await);

    post_ok(web_addr, "/api/tunnels/pause").await;
    wait_for_config_paused(&config_path, true).await;
    assert_tcp_dropped(active).await;
    assert!(connect_fails_for(enabled_addr, 10).await);

    post_ok(web_addr, "/api/tunnels/unpause").await;
    wait_for_config_paused(&config_path, false).await;
    let mut conn = connect_retry(enabled_addr).await;
    conn.write_all(b"after").await.unwrap();
    let mut buf = [0u8; 5];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"after");
    assert!(connect_fails_for(disabled_addr, 10).await);
}

#[tokio::test]
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
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
        encrypted: false,
        udp_mtu: None,
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::Off,
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
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
async fn plaintext_udp_diagnostics_appear_in_web_status() {
    install();
    let echo = udp_echo().await;
    let (ingress, public, web) = (free_port(), free_port(), free_port());
    let (cert, key) = temp_paths("udp-diagnostics");
    let ss = server_settings(ingress, public, cert, key);
    let (_acceptor, fingerprint) = tls::server_acceptor(&ss).expect("generate cert");
    tokio::spawn(server::run(ss));

    let tunnel = TunnelConfig {
        name: "u".into(),
        protocol: Proto::Udp,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
        encrypted: false,
        udp_mtu: None,
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::Off,
    };
    tokio::spawn(client::run(client_settings_with(
        ingress,
        fingerprint,
        vec![tunnel],
        format!("127.0.0.1:{web}"),
        None,
        false,
    )));

    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    assert_udp_roundtrip(public_addr, b"diag").await;

    let web_addr: SocketAddr = format!("127.0.0.1:{web}").parse().unwrap();
    wait_for_status(web_addr, |st| {
        let Some(tunnel) = st["tunnels"]
            .as_array()
            .and_then(|tunnels| tunnels.iter().find(|t| t["name"].as_str() == Some("u")))
        else {
            return false;
        };
        let diagnostics = &tunnel["diagnostics"];
        diagnostics["rtt_ms"].is_number()
            && diagnostics["network_floor_ms"].is_number()
            && diagnostics["relay_overhead_ms"].is_number()
            && diagnostics["server_public_to_client_ms"].is_number()
    })
    .await;
}

#[tokio::test]
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
async fn udp_source_pool_presents_distinct_loopback_sources() {
    install();
    let (local, mut seen) = udp_peer_report_echo().await;
    let (ingress, public) = (free_port(), free_port());
    let tunnel = TunnelConfig {
        name: "u".into(),
        protocol: Proto::Udp,
        local_addr: local,
        remote_port: Some(public),
        enabled: true,
        encrypted: false,
        udp_mtu: None,
        udp_source_pool: Some("127.64.0.0/16".parse().unwrap()),
        proxy_protocol: ProxyProtocol::Off,
    };
    start_relay(ingress, public, "udp-source-pool", tunnel);

    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0u8; 64];

    let mut first_ok = false;
    for _ in 0..100 {
        let _ = first.send_to(b"one", public_addr).await;
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(150), first.recv_from(&mut buf)).await
        {
            first_ok = &buf[..n] == b"one";
            if first_ok {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(first_ok, "first UDP source did not roundtrip");

    let mut second_ok = false;
    for _ in 0..100 {
        let _ = second.send_to(b"two", public_addr).await;
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(150), second.recv_from(&mut buf)).await
        {
            second_ok = &buf[..n] == b"two";
            if second_ok {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(second_ok, "second UDP source did not roundtrip");

    let mut ips = HashSet::new();
    for _ in 0..16 {
        let peer = tokio::time::timeout(Duration::from_secs(1), seen.recv())
            .await
            .unwrap()
            .unwrap();
        ips.insert(peer.ip());
        if ips.len() >= 2 {
            break;
        }
    }
    assert_eq!(ips.len(), 2, "local service saw peers {ips:?}");
    for ip in ips {
        let octets = match ip {
            std::net::IpAddr::V4(ip) => ip.octets(),
            std::net::IpAddr::V6(ip) => panic!("unexpected IPv6 source {ip}"),
        };
        assert_eq!(octets[0], 127);
        assert_eq!(octets[1], 64);
    }
}

#[tokio::test]
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
async fn udp_plaintext_large_safe_datagram_roundtrip() {
    install();
    let echo = udp_echo().await;
    let (ingress, public) = (free_port(), free_port());
    let tunnel = TunnelConfig {
        name: "u".into(),
        protocol: Proto::Udp,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
        encrypted: false,
        udp_mtu: None,
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::Off,
    };
    start_relay(ingress, public, "udp-plain-large-safe", tunnel);

    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = vec![0xCDu8; 1000];
    let mut buf = vec![0u8; 1200];
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
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
async fn udp_plaintext_fragmented_datagram_roundtrip() {
    install();
    let echo = udp_echo().await;
    let (ingress, public) = (free_port(), free_port());
    let tunnel = TunnelConfig {
        name: "u".into(),
        protocol: Proto::Udp,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
        encrypted: false,
        udp_mtu: Some(512),
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::Off,
    };
    start_relay(ingress, public, "udp-plain-fragmented", tunnel);

    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = vec![0xEFu8; 4_000];
    let mut buf = vec![0u8; 8_000];
    let mut got: Option<Vec<u8>> = None;
    for _ in 0..100 {
        let _ = sock.send_to(&payload, public_addr).await;
        match tokio::time::timeout(Duration::from_millis(300), sock.recv_from(&mut buf)).await {
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
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
async fn udp_encrypted_large_datagram_roundtrip() {
    install();
    let echo = udp_echo().await;
    let (ingress, public) = (free_port(), free_port());
    let tunnel = TunnelConfig {
        name: "u".into(),
        protocol: Proto::Udp,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
        encrypted: true,
        udp_mtu: None,
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::Off,
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
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
async fn both_tunnel_roundtrip() {
    install();
    let echo = both_echo().await;
    let (ingress, public) = (free_port(), free_port());
    let tunnel = TunnelConfig {
        name: "both".into(),
        protocol: Proto::Both,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
        encrypted: false,
        udp_mtu: None,
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::Off,
    };
    start_relay(ingress, public, "both", tunnel);

    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    let mut tcp = connect_retry(public_addr).await;
    tcp.write_all(b"both-tcp").await.unwrap();
    let mut buf = [0u8; 8];
    tcp.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"both-tcp");

    assert_udp_roundtrip(public_addr, b"both-udp").await;
}

#[tokio::test]
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
async fn both_tunnel_encrypted_roundtrip() {
    install();
    let echo = both_echo().await;
    let (ingress, public) = (free_port(), free_port());
    let tunnel = TunnelConfig {
        name: "both".into(),
        protocol: Proto::Both,
        local_addr: echo,
        remote_port: Some(public),
        enabled: true,
        encrypted: true,
        udp_mtu: None,
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::Off,
    };
    start_relay(ingress, public, "both-encrypted", tunnel);

    let public_addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    let mut tcp = connect_retry(public_addr).await;
    tcp.write_all(b"both-tls").await.unwrap();
    let mut buf = [0u8; 8];
    tcp.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"both-tls");

    assert_udp_roundtrip(public_addr, b"both-udp-tls").await;
}

#[tokio::test]
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
async fn web_add_tunnel_preserves_encryption_choices() {
    install();
    let echo = tcp_echo().await;
    let udp_local = udp_echo().await;
    let (ingress, p1, p2, p3, web) = (
        free_port(),
        free_port(),
        free_port(),
        free_port(),
        free_port(),
    );
    let (cert, key) = temp_paths("web-encryption");
    let config_path = temp_client_config("web-encryption");
    let ss = ServerSettings {
        bind_addr: "127.0.0.1".into(),
        control_port: ingress,
        secret: "test-secret".into(),
        min_port: p1.min(p2).min(p3),
        max_port: p1.max(p2).max(p3),
        cert_path: cert,
        key_path: key,
        public_host: None,
    };
    let (_acceptor, fingerprint) = tls::server_acceptor(&ss).expect("generate cert");
    tokio::spawn(server::run(ss));
    tokio::spawn(client::run(client_settings_with(
        ingress,
        fingerprint,
        Vec::new(),
        format!("127.0.0.1:{web}"),
        Some(config_path.clone()),
        false,
    )));

    let web_addr: SocketAddr = format!("127.0.0.1:{web}").parse().unwrap();
    wait_for_status(web_addr, |st| st["connected"].as_bool() == Some(true)).await;

    let r1 = post_json(
        web_addr,
        "/api/tunnels",
        serde_json::json!({
            "name": "tls",
            "proto": "tcp",
            "local": echo.to_string(),
            "remote_port": p1,
            "encrypted": true
        }),
    )
    .await;
    assert!(r1.starts_with("HTTP/1.1 200"), "response was: {r1}");

    let r2 = post_json(
        web_addr,
        "/api/tunnels",
        serde_json::json!({
            "name": "plain",
            "proto": "tcp",
            "local": echo.to_string(),
            "remote_port": p2,
            "encrypted": false
        }),
    )
    .await;
    assert!(r2.starts_with("HTTP/1.1 200"), "response was: {r2}");

    let r3 = post_json(
        web_addr,
        "/api/tunnels",
        serde_json::json!({
            "name": "udp-mtu",
            "proto": "udp",
            "local": udp_local.to_string(),
            "remote_port": p3,
            "encrypted": false,
            "udp_mtu": 900,
            "udp_source_pool": "127.64.0.0/16"
        }),
    )
    .await;
    assert!(r3.starts_with("HTTP/1.1 200"), "response was: {r3}");

    wait_for_status(web_addr, |st| {
        let Some(tunnels) = st["tunnels"].as_array() else {
            return false;
        };
        let tls = tunnels
            .iter()
            .any(|t| t["name"] == "tls" && t["encrypted"].as_bool() == Some(true));
        let plain = tunnels
            .iter()
            .any(|t| t["name"] == "plain" && t["encrypted"].as_bool() == Some(false));
        let udp_mtu = tunnels.iter().any(|t| {
            t["name"] == "udp-mtu"
                && t["encrypted"].as_bool() == Some(false)
                && t["udp_mtu"].as_u64() == Some(900)
                && t["udp_source_pool"].as_str() == Some("127.64.0.0/16")
        });
        tls && plain && udp_mtu
    })
    .await;

    let persisted: ClientFile =
        toml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    let persisted_pool = persisted
        .tunnels
        .iter()
        .find(|t| t.name == "udp-mtu")
        .and_then(|t| t.udp_source_pool)
        .map(|p| p.to_string());
    assert_eq!(persisted_pool.as_deref(), Some("127.64.0.0/16"));
}

#[tokio::test]
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
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
        encrypted: false,
        udp_mtu: None,
        udp_source_pool: None,
        proxy_protocol: ProxyProtocol::Off,
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
#[ignore = "uses real loopback sockets; run explicitly for relay smoke testing"]
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
            encrypted: false,
            udp_mtu: None,
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
