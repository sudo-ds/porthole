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
    tunnels: Vec<TunnelView>,
}

#[derive(Serialize)]
struct TunnelView {
    name: String,
    proto: String,
    local: String,
    remote_port: Option<u16>,
    encrypted: bool,
    udp_mtu: Option<u16>,
    proxy_protocol: String,
    public: Option<String>,
    enabled: bool,
    up: bool,
    error: Option<String>,
    bytes_in: u64,
    bytes_out: u64,
    active: u32,
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
                encrypted: s.encrypted,
                udp_mtu: s.udp_mtu,
                proxy_protocol: s.proxy_protocol.to_string(),
                public: s.public_addr.lock().unwrap().clone(),
                enabled: s.enabled.load(Relaxed),
                up: s.up.load(Relaxed),
                error: s.error.lock().unwrap().clone(),
                bytes_in: s.counters.bytes_in.load(Relaxed),
                bytes_out: s.counters.bytes_out.load(Relaxed),
                active: s.counters.active.load(Relaxed),
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
        tunnels,
    })
}

#[derive(Deserialize)]
struct AddRequest {
    name: String,
    proto: String,
    local: String,
    remote_port: Option<u16>,
    encrypted: Option<bool>,
    udp_mtu: Option<u16>,
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
    let local_addr = match parse_local_addr(&req.local) {
        Ok(a) => a,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "local must be HOST:PORT or PORT").into_response();
        }
    };
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
        enabled: true,
        encrypted: req.encrypted.unwrap_or(false),
        udp_mtu: req.udp_mtu,
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

fn parse_local_addr(local: &str) -> Result<SocketAddr, std::net::AddrParseError> {
    let local = local.trim();
    match local.parse::<SocketAddr>() {
        Ok(addr) => Ok(addr),
        Err(err) => match local.parse::<u16>() {
            Ok(port) => Ok(SocketAddr::from(([127, 0, 0, 1], port))),
            Err(_) => Err(err),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_local_addr_keeps_explicit_addr() {
        assert_eq!(
            parse_local_addr("192.0.2.10:4040").unwrap(),
            "192.0.2.10:4040".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parse_local_addr_defaults_bare_port_to_loopback() {
        assert_eq!(
            parse_local_addr("4040").unwrap(),
            "127.0.0.1:4040".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parse_local_addr_rejects_garbage() {
        assert!(parse_local_addr("badaddr").is_err());
    }
}
