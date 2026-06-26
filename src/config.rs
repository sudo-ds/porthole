//! Configuration: on-disk TOML forms, CLI/env merging, and atomic write-back.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::cli::{ClientArgs, ServerArgs};
use crate::protocol::{Proto, DEFAULT_CONTROL_PORT, DEFAULT_WEB_BIND};

pub const ENV_SECRET: &str = "PORTHOLE_SECRET";

// ---------------------------------------------------------------------------
// Tunnel definition (shared between config file and runtime)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub name: String,
    pub protocol: Proto,
    /// Local service address the client forwards to, e.g. 127.0.0.1:25565.
    pub local_addr: SocketAddr,
    /// Requested public port on the server. `None`/`0` => server picks one.
    #[serde(default)]
    pub remote_port: Option<u16>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Parse a `name=proto:LOCAL->REMOTE` CLI spec.
pub fn parse_tunnel_spec(spec: &str) -> Result<TunnelConfig> {
    let (name, rest) = spec
        .split_once('=')
        .with_context(|| format!("tunnel spec {spec:?} missing `name=`"))?;
    let (proto, addrs) = rest
        .split_once(':')
        .with_context(|| format!("tunnel spec {spec:?} missing `proto:`"))?;
    let (local, remote) = addrs
        .split_once("->")
        .with_context(|| format!("tunnel spec {spec:?} missing `LOCAL->REMOTE`"))?;
    let protocol: Proto = proto.parse()?;
    let local_addr: SocketAddr = local
        .trim()
        .parse()
        .with_context(|| format!("invalid local address {local:?} in {spec:?}"))?;
    let remote_port: u16 = remote
        .trim()
        .parse()
        .with_context(|| format!("invalid remote port {remote:?} in {spec:?}"))?;
    Ok(TunnelConfig {
        name: name.trim().to_string(),
        protocol,
        local_addr,
        remote_port: (remote_port != 0).then_some(remote_port),
        enabled: true,
    })
}

// ---------------------------------------------------------------------------
// Server config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
struct ServerFile {
    bind_addr: Option<String>,
    control_port: Option<u16>,
    secret: Option<String>,
    min_port: Option<u16>,
    max_port: Option<u16>,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ServerSettings {
    pub bind_addr: String,
    pub control_port: u16,
    pub secret: String,
    pub min_port: u16,
    pub max_port: u16,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl ServerSettings {
    pub fn ingress_addr(&self) -> Result<SocketAddr> {
        format!("{}:{}", self.bind_addr, self.control_port)
            .parse()
            .with_context(|| format!("invalid bind {}:{}", self.bind_addr, self.control_port))
    }

    pub fn port_allowed(&self, port: u16) -> bool {
        port >= self.min_port && port <= self.max_port
    }
}

pub fn load_server(args: &ServerArgs) -> Result<ServerSettings> {
    let file: ServerFile = match &args.config {
        Some(p) => {
            toml::from_str(&read_file(p)?).with_context(|| format!("parsing {}", p.display()))?
        }
        None => ServerFile::default(),
    };

    let secret = resolve_secret(args.secret_file.as_deref(), file.secret.as_deref())?;
    let min_port = args.min_port.or(file.min_port).unwrap_or(10_000);
    let max_port = args.max_port.or(file.max_port).unwrap_or(20_000);
    if min_port > max_port {
        bail!("min_port ({min_port}) must be <= max_port ({max_port})");
    }

    Ok(ServerSettings {
        bind_addr: args
            .bind
            .clone()
            .or(file.bind_addr)
            .unwrap_or_else(|| "0.0.0.0".into()),
        control_port: args
            .control_port
            .or(file.control_port)
            .unwrap_or(DEFAULT_CONTROL_PORT),
        secret,
        min_port,
        max_port,
        cert_path: args
            .cert_path
            .clone()
            .or(file.cert_path)
            .unwrap_or_else(|| "porthole.crt".into()),
        key_path: args
            .key_path
            .clone()
            .or(file.key_path)
            .unwrap_or_else(|| "porthole.key".into()),
    })
}

// ---------------------------------------------------------------------------
// Client config (the file form doubles as the persistence form)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ClientFile {
    pub server_addr: Option<String>,
    pub server_fingerprint: Option<String>,
    pub web_bind: Option<String>,
    /// Persisted only if present here (a secret sourced from env stays out of the file).
    pub secret: Option<String>,
    #[serde(default, rename = "tunnels")]
    pub tunnels: Vec<TunnelConfig>,
}

#[derive(Debug, Clone)]
pub struct ClientSettings {
    pub server_addr: String,
    pub server_fingerprint: String,
    pub web_bind: String,
    pub secret: String,
    /// Where to persist tunnel changes (None => no config file in use).
    pub config_path: Option<PathBuf>,
    /// On-disk form, kept for write-back.
    pub file: ClientFile,
}

pub fn load_client(args: &ClientArgs) -> Result<ClientSettings> {
    let mut file: ClientFile = match &args.config {
        Some(p) if p.exists() => {
            toml::from_str(&read_file(p)?).with_context(|| format!("parsing {}", p.display()))?
        }
        _ => ClientFile::default(),
    };

    // Append CLI-provided tunnels.
    for spec in &args.tunnels {
        file.tunnels.push(parse_tunnel_spec(spec)?);
    }

    let secret = resolve_secret(args.secret_file.as_deref(), file.secret.as_deref())?;

    let server_addr = args
        .server
        .clone()
        .or_else(|| file.server_addr.clone())
        .context("no server address: pass --server host:port or set server_addr in config")?;

    let server_fingerprint = args
        .fingerprint
        .clone()
        .or_else(|| file.server_fingerprint.clone())
        .context("no server fingerprint: pass --fingerprint sha256:... or set server_fingerprint in config (the server prints it at startup)")?;

    let web_bind = args
        .web_bind
        .clone()
        .or_else(|| file.web_bind.clone())
        .unwrap_or_else(|| DEFAULT_WEB_BIND.to_string());

    Ok(ClientSettings {
        server_addr,
        server_fingerprint,
        web_bind,
        secret,
        config_path: args.config.clone(),
        file,
    })
}

/// Serialize a [`ClientFile`] to its config path atomically (temp file + rename).
pub fn save_client_file(path: &Path, file: &ClientFile) -> Result<()> {
    let toml = toml::to_string_pretty(file).context("serializing client config")?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, toml).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// Resolve the shared secret: --secret-file > $PORTHOLE_SECRET > config `secret`.
fn resolve_secret(secret_file: Option<&Path>, file_secret: Option<&str>) -> Result<String> {
    if let Some(p) = secret_file {
        return Ok(read_file(p)?.trim().to_string());
    }
    if let Ok(s) = std::env::var(ENV_SECRET) {
        if !s.is_empty() {
            return Ok(s);
        }
    }
    if let Some(s) = file_secret {
        if !s.is_empty() {
            return Ok(s.to_string());
        }
    }
    bail!("no secret provided: set ${ENV_SECRET}, pass --secret-file, or add `secret` to the config file");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_spec_tcp() {
        let t = parse_tunnel_spec("mc=tcp:127.0.0.1:25565->25565").unwrap();
        assert_eq!(t.name, "mc");
        assert_eq!(t.protocol, Proto::Tcp);
        assert_eq!(t.local_addr, "127.0.0.1:25565".parse().unwrap());
        assert_eq!(t.remote_port, Some(25565));
        assert!(t.enabled);
    }

    #[test]
    fn parse_spec_udp_auto_port() {
        let t = parse_tunnel_spec("g=udp:127.0.0.1:19132->0").unwrap();
        assert_eq!(t.protocol, Proto::Udp);
        assert_eq!(t.remote_port, None);
    }

    #[test]
    fn parse_spec_rejects_garbage() {
        assert!(parse_tunnel_spec("nope").is_err());
        assert!(parse_tunnel_spec("a=tcp:badaddr->1").is_err());
        assert!(parse_tunnel_spec("a=ftp:127.0.0.1:1->2").is_err());
    }
}
