//! Client-only local web UI: a status page plus a small JSON API. Mutations are pushed as
//! commands to the control loop (which owns config write-back); handlers never touch sockets
//! or the config file directly.

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
use crate::config::TunnelConfig;
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
    server: String,
    uptime_secs: u64,
    tunnels: Vec<TunnelView>,
}

#[derive(Serialize)]
struct TunnelView {
    name: String,
    proto: String,
    local: String,
    remote_port: Option<u16>,
    public: Option<String>,
    enabled: bool,
    up: bool,
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
                public: s.public_addr.lock().unwrap().clone(),
                enabled: s.enabled.load(Relaxed),
                up: s.up.load(Relaxed),
                bytes_in: s.counters.bytes_in.load(Relaxed),
                bytes_out: s.counters.bytes_out.load(Relaxed),
                active: s.counters.active.load(Relaxed),
            }
        })
        .collect();
    tunnels.sort_by(|a, b| a.name.cmp(&b.name));

    Json(StatusResponse {
        connected: shared.connected.load(Relaxed),
        server: shared.server_addr.clone(),
        uptime_secs: shared.started.elapsed().as_secs(),
        tunnels,
    })
}

#[derive(Deserialize)]
struct AddRequest {
    name: String,
    proto: String,
    local: String,
    remote_port: Option<u16>,
}

async fn add_tunnel(State(st): State<AppState>, Json(req): Json<AddRequest>) -> impl IntoResponse {
    if req.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "name is required").into_response();
    }
    let proto: Proto = match req.proto.parse() {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, "proto must be tcp or udp").into_response(),
    };
    let local_addr = match req.local.parse() {
        Ok(a) => a,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "local must be HOST:PORT").into_response();
        }
    };
    let tunnel = TunnelConfig {
        name: req.name.trim().to_string(),
        protocol: proto,
        local_addr,
        remote_port: req.remote_port.filter(|p| *p != 0),
        enabled: true,
    };
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
