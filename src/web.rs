//! Client-only local web UI: a status page plus a small JSON API. Mutations are pushed as
//! commands to the control loop (which owns config write-back); handlers never touch sockets
//! or the config file directly.

use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::client::{ClientShared, Command};
use crate::config::{self, TunnelConfig};
use crate::diagnostics::{LatencySnapshot, PlainUdpDiagnostics};
use crate::protocol::Proto;

#[derive(Clone)]
struct AppState {
    shared: Arc<ClientShared>,
    cmd_tx: mpsc::Sender<Command>,
}

pub async fn serve(
    shared: Arc<ClientShared>,
    cmd_tx: mpsc::Sender<Command>,
    bind: String,
) -> Result<()> {
    let state = AppState { shared, cmd_tx };
    let app = Router::new()
        .route("/", get(index))
        .route("/api/status", get(status))
        .route("/api/tunnels", post(add_tunnel))
        .route("/api/tunnels/pause", post(pause_tunnels))
        .route("/api/tunnels/unpause", post(unpause_tunnels))
        .route("/api/tunnels/{name}", delete(remove_tunnel))
        .route("/api/tunnels/{name}/toggle", post(toggle_tunnel))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding web UI on {bind}"))?;
    axum::serve(listener, app).await.context("web UI server")?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("static/index.html"))
}

#[derive(Serialize)]
struct StatusResponse {
    connected: bool,
    paused: bool,
    server: String,
    uptime_secs: u64,
    min_port: u16,
    max_port: u16,
    metrics: MetricsView,
    tunnels: Vec<TunnelView>,
}

#[derive(Serialize)]
struct MetricsView {
    in_bps: u64,
    out_bps: u64,
    active: u32,
    latency_ms: Option<f64>,
    history: Vec<MetricSampleView>,
}

#[derive(Serialize)]
struct MetricSampleView {
    uptime_secs: u64,
    in_bps: u64,
    out_bps: u64,
    active: u32,
    latency_ms: Option<f64>,
}

#[derive(Serialize)]
struct TunnelView {
    name: String,
    proto: String,
    local: String,
    remote_port: Option<u16>,
    local_ports: Option<String>,
    encrypted: bool,
    udp_mtu: Option<u16>,
    udp_source_pool: Option<String>,
    proxy_protocol: String,
    public: Option<String>,
    bindings: Vec<BindingView>,
    enabled: bool,
    up: bool,
    error: Option<String>,
    bytes_in: u64,
    bytes_out: u64,
    rate_in_bps: u64,
    rate_out_bps: u64,
    active: u32,
    latency_ms: Option<f64>,
    diagnostics: Option<DiagnosticsView>,
}

#[derive(Serialize)]
struct BindingView {
    local_port: u16,
    remote_port: u16,
    public: String,
}

#[derive(Serialize)]
struct DiagnosticsView {
    rtt_ms: Option<f64>,
    network_floor_ms: Option<f64>,
    excess_ms: Option<f64>,
    relay_overhead_ms: Option<f64>,
    server_public_to_client_ms: Option<f64>,
    server_client_to_public_ms: Option<f64>,
    client_server_to_local_ms: Option<f64>,
    client_local_to_server_ms: Option<f64>,
}

async fn status(State(st): State<AppState>) -> Json<StatusResponse> {
    let shared = &st.shared;
    let mut tunnels: Vec<TunnelView> = shared
        .status
        .iter()
        .map(|e| {
            let s = e.value();
            TunnelView {
                name: e.key().clone(),
                proto: s.proto.to_string(),
                local: s.local_addr.to_string(),
                remote_port: s.remote_port,
                local_ports: s.local_ports.clone(),
                encrypted: s.encrypted,
                udp_mtu: s.udp_mtu,
                udp_source_pool: s.udp_source_pool.map(|p| p.to_string()),
                proxy_protocol: s.proxy_protocol.to_string(),
                public: s.public_addr.lock().unwrap().clone(),
                bindings: s
                    .bindings
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|binding| BindingView {
                        local_port: binding.local_port,
                        remote_port: binding.remote_port,
                        public: binding.public.clone(),
                    })
                    .collect(),
                enabled: s.enabled.load(Relaxed),
                up: s.up.load(Relaxed),
                error: s.error.lock().unwrap().clone(),
                bytes_in: s.counters.bytes_in.load(Relaxed),
                bytes_out: s.counters.bytes_out.load(Relaxed),
                rate_in_bps: s.rate_in_bps.load(Relaxed),
                rate_out_bps: s.rate_out_bps.load(Relaxed),
                active: s.counters.active.load(Relaxed),
                latency_ms: tunnel_latency_ms(s),
                diagnostics: (s.proto.has_udp() && !s.encrypted)
                    .then(|| diagnostics_view(&s.diagnostics)),
            }
        })
        .collect();
    tunnels.sort_by(|a, b| a.name.cmp(&b.name));

    Json(StatusResponse {
        connected: shared.connected.load(Relaxed),
        paused: shared.tunnels_paused.load(Relaxed),
        server: shared.server_addr.clone(),
        uptime_secs: shared.started.elapsed().as_secs(),
        min_port: shared.min_port.load(Relaxed),
        max_port: shared.max_port.load(Relaxed),
        metrics: metrics_view(shared),
        tunnels,
    })
}

fn metrics_view(shared: &ClientShared) -> MetricsView {
    let metrics = shared.metrics.lock().unwrap();
    let last = metrics.samples.back().cloned().unwrap_or_default();
    MetricsView {
        in_bps: last.bytes_in_per_sec,
        out_bps: last.bytes_out_per_sec,
        active: last.active,
        latency_ms: last.latency_ms,
        history: metrics
            .samples
            .iter()
            .map(|sample| MetricSampleView {
                uptime_secs: sample.uptime_secs,
                in_bps: sample.bytes_in_per_sec,
                out_bps: sample.bytes_out_per_sec,
                active: sample.active,
                latency_ms: sample.latency_ms,
            })
            .collect(),
    }
}

fn tunnel_latency_ms(s: &crate::client::TunnelStatus) -> Option<f64> {
    s.diagnostics
        .rtt
        .snapshot()
        .map(|snapshot| us_to_ms(snapshot.last_us))
        .or_else(|| {
            s.counters
                .tcp_setup_latency
                .snapshot()
                .map(|snapshot| us_to_ms(snapshot.last_us))
        })
}

fn diagnostics_view(d: &PlainUdpDiagnostics) -> DiagnosticsView {
    let rtt = d.rtt.snapshot();
    let floor = rtt.map(|s| s.min_us);
    let last = rtt.map(|s| s.last_us);
    let server_public_to_client = d.server_public_to_client.snapshot();
    let server_client_to_public = d.server_client_to_public.snapshot();
    let client_server_to_local = d.client_server_to_local.snapshot();
    let client_local_to_server = d.client_local_to_server.snapshot();
    let relay_samples = [
        server_public_to_client,
        server_client_to_public,
        client_server_to_local,
        client_local_to_server,
    ];

    DiagnosticsView {
        rtt_ms: last.map(us_to_ms),
        network_floor_ms: floor.map(us_to_ms),
        excess_ms: last
            .zip(floor)
            .map(|(last, floor)| us_to_ms(last.saturating_sub(floor))),
        relay_overhead_ms: mean_avg_ms(&relay_samples),
        server_public_to_client_ms: avg_ms(server_public_to_client),
        server_client_to_public_ms: avg_ms(server_client_to_public),
        client_server_to_local_ms: avg_ms(client_server_to_local),
        client_local_to_server_ms: avg_ms(client_local_to_server),
    }
}

fn avg_ms(snapshot: Option<LatencySnapshot>) -> Option<f64> {
    snapshot.map(|s| us_to_ms(s.avg_us))
}

fn mean_avg_ms(snapshots: &[Option<LatencySnapshot>]) -> Option<f64> {
    let mut total = 0u64;
    let mut count = 0u64;
    for snapshot in snapshots.iter().flatten() {
        total = total.saturating_add(snapshot.avg_us);
        count += 1;
    }
    (count > 0).then(|| us_to_ms(total / count))
}

fn us_to_ms(us: u64) -> f64 {
    us as f64 / 1000.0
}

#[derive(Deserialize)]
struct AddRequest {
    name: String,
    proto: String,
    local: String,
    remote_port: Option<u16>,
    local_ports: Option<String>,
    encrypted: Option<bool>,
    udp_mtu: Option<u16>,
    udp_source_pool: Option<String>,
    proxy_protocol: Option<String>,
}

async fn add_tunnel(State(st): State<AppState>, Json(req): Json<AddRequest>) -> impl IntoResponse {
    if req.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "name is required").into_response();
    }
    let proto: Proto = match req.proto.parse() {
        Ok(p) => p,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "proto must be tcp, udp, or both").into_response()
        }
    };
    let (local_addr, parsed_local_ports) = match parse_local_endpoint(&req.local) {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "local must be HOST:PORT, PORT, PORT-PORT, or PORT,PORT",
            )
                .into_response();
        }
    };
    let local_ports = req.local_ports.or(parsed_local_ports);
    let proxy_protocol = match req.proxy_protocol.as_deref().unwrap_or("off").parse() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "proxy_protocol must be off, v1, or v2",
            )
                .into_response();
        }
    };
    let udp_source_pool = match req
        .udp_source_pool
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(pool) => match pool.parse() {
            Ok(pool) => Some(pool),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "udp_source_pool must be an IPv4 loopback CIDR such as 127.64.0.0/16",
                )
                    .into_response();
            }
        },
        None => None,
    };
    // Validate the requested public port against the server's advertised range.
    if let Some(p) = req.remote_port.filter(|p| *p != 0) {
        let (min, max) = (
            st.shared.min_port.load(Relaxed),
            st.shared.max_port.load(Relaxed),
        );
        if max != 0 && (p < min || p > max) {
            return (
                StatusCode::BAD_REQUEST,
                format!("public port {p} is outside the server's allowed range {min}-{max}"),
            )
                .into_response();
        }
    }
    let tunnel = TunnelConfig {
        name: req.name.trim().to_string(),
        protocol: proto,
        local_addr,
        remote_port: req.remote_port.filter(|p| *p != 0),
        local_ports,
        enabled: true,
        encrypted: req.encrypted.unwrap_or(false),
        udp_mtu: req.udp_mtu,
        udp_source_pool,
        proxy_protocol,
    };
    if let Err(e) = config::validate_tunnel_config(&tunnel) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    let _ = st.cmd_tx.send(Command::Add(tunnel)).await;
    (StatusCode::OK, "ok").into_response()
}

async fn remove_tunnel(State(st): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
    let _ = st.cmd_tx.send(Command::Remove(name)).await;
    StatusCode::OK
}

async fn toggle_tunnel(State(st): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
    let enabled = st
        .shared
        .status
        .get(&name)
        .map(|s| s.enabled.load(Relaxed))
        .unwrap_or(false);
    let _ = st.cmd_tx.send(Command::SetEnabled(name, !enabled)).await;
    StatusCode::OK
}

async fn pause_tunnels(State(st): State<AppState>) -> impl IntoResponse {
    let _ = st.cmd_tx.send(Command::SetPaused(true)).await;
    StatusCode::OK
}

async fn unpause_tunnels(State(st): State<AppState>) -> impl IntoResponse {
    let _ = st.cmd_tx.send(Command::SetPaused(false)).await;
    StatusCode::OK
}

fn parse_local_endpoint(local: &str) -> Result<(SocketAddr, Option<String>)> {
    let local = local.trim();
    if let Ok(port) = local.parse::<u16>() {
        return Ok((SocketAddr::from(([127, 0, 0, 1], port)), None));
    }
    if !local.contains(':') {
        return config::parse_local_endpoint(&format!("127.0.0.1:{local}"));
    }
    config::parse_local_endpoint(local)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_local_endpoint_keeps_explicit_addr() {
        assert_eq!(
            parse_local_endpoint("192.0.2.10:4040").unwrap(),
            ("192.0.2.10:4040".parse::<SocketAddr>().unwrap(), None)
        );
    }

    #[test]
    fn parse_local_endpoint_defaults_bare_port_to_loopback() {
        assert_eq!(
            parse_local_endpoint("4040").unwrap(),
            ("127.0.0.1:4040".parse::<SocketAddr>().unwrap(), None)
        );
    }

    #[test]
    fn parse_local_endpoint_accepts_range() {
        assert_eq!(
            parse_local_endpoint("127.0.0.1:4000-4002").unwrap(),
            (
                "127.0.0.1:4000".parse::<SocketAddr>().unwrap(),
                Some("4000-4002".into())
            )
        );
    }

    #[test]
    fn parse_local_endpoint_defaults_bare_range_to_loopback() {
        assert_eq!(
            parse_local_endpoint("4000-4002").unwrap(),
            (
                "127.0.0.1:4000".parse::<SocketAddr>().unwrap(),
                Some("4000-4002".into())
            )
        );
    }

    #[test]
    fn parse_local_endpoint_defaults_bare_list_to_loopback() {
        assert_eq!(
            parse_local_endpoint("4000,4002").unwrap(),
            (
                "127.0.0.1:4000".parse::<SocketAddr>().unwrap(),
                Some("4000,4002".into())
            )
        );
    }

    #[test]
    fn parse_local_endpoint_rejects_garbage() {
        assert!(parse_local_endpoint("badaddr").is_err());
    }
}
