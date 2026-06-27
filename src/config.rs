//! Configuration: on-disk TOML forms, CLI/env merging, and atomic write-back.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::cli::{ClientArgs, ServerArgs};
use crate::protocol::{Proto, DEFAULT_CONTROL_PORT, DEFAULT_WEB_BIND};

pub const ENV_SECRET: &str = "PORTHOLE_SECRET";

// ---------------------------------------------------------------------------
// Logging config (shared by server and client)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogMode {
    #[default]
    Both,
    Console,
    File,
    Off,
}

impl LogMode {
    pub fn console_enabled(self) -> bool {
        matches!(self, Self::Both | Self::Console)
    }

    pub fn file_enabled(self) -> bool {
        matches!(self, Self::Both | Self::File)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default)]
    pub mode: LogMode,
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_directory")]
    pub directory: PathBuf,
    #[serde(default = "default_log_max_files")]
    pub max_files: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            mode: LogMode::default(),
            level: default_log_level(),
            directory: default_log_directory(),
            max_files: default_log_max_files(),
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}

fn default_log_directory() -> PathBuf {
    "Logs".into()
}

fn default_log_max_files() -> usize {
    14
}

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

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ServerFile {
    pub bind_addr: Option<String>,
    pub control_port: Option<u16>,
    pub secret: Option<String>,
    pub min_port: Option<u16>,
    pub max_port: Option<u16>,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    /// Public address clients dial (used to build the connection code).
    #[serde(default)]
    pub public_host: Option<String>,
    #[serde(default)]
    pub logging: LoggingConfig,
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
    pub public_host: Option<String>,
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
    let path = args.config.clone().or_else(|| {
        let p = default_server_config_path();
        p.exists().then_some(p)
    });
    let file: ServerFile = match &path {
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
        public_host: args.public_host.clone().or(file.public_host),
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
    #[serde(default)]
    pub tunnels_paused: bool,
    /// Persisted only if present here (a secret sourced from env stays out of the file).
    pub secret: Option<String>,
    #[serde(default)]
    pub logging: LoggingConfig,
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
    let path = args.config.clone().or_else(|| {
        let p = default_client_config_path();
        p.exists().then_some(p)
    });
    let mut file: ClientFile = match &path {
        Some(p) => {
            toml::from_str(&read_file(p)?).with_context(|| format!("parsing {}", p.display()))?
        }
        None => ClientFile::default(),
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
        config_path: path,
        file,
    })
}

/// Load only the shared `[logging]` table from a TOML file.
pub fn load_logging(path: Option<&Path>) -> Result<LoggingConfig> {
    let Some(path) = path else {
        return Ok(LoggingConfig::default());
    };
    logging_from_str(&read_file(path)?).with_context(|| format!("parsing {}", path.display()))
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

/// Serialize a [`ServerFile`] to its config path atomically (temp file + rename).
pub fn save_server_file(path: &Path, file: &ServerFile) -> Result<()> {
    let toml = toml::to_string_pretty(file).context("serializing server config")?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, toml).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Default config path next to the executable (falls back to the bare name in the CWD).
pub fn default_server_config_path() -> PathBuf {
    config_beside_exe("porthole-server.toml")
}

pub fn default_client_config_path() -> PathBuf {
    config_beside_exe("porthole-client.toml")
}

fn config_beside_exe(name: &str) -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(name)))
        .unwrap_or_else(|| PathBuf::from(name))
}

/// Whether a shared secret is available without a config file (env or --secret-file).
pub fn has_secret_source(secret_file: Option<&Path>) -> bool {
    secret_file.is_some() || std::env::var_os(ENV_SECRET).is_some_and(|s| !s.is_empty())
}

/// Generate a fresh random shared secret (244 bits of entropy, hex).
pub fn gen_secret() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

fn logging_from_str(text: &str) -> Result<LoggingConfig> {
    let root: toml::Value = toml::from_str(text).context("parsing TOML")?;
    let Some(logging) = root.get("logging") else {
        return Ok(LoggingConfig::default());
    };
    logging.clone().try_into().context("parsing [logging]")
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

    #[test]
    fn client_file_defaults_to_unpaused() {
        let file: ClientFile = toml::from_str(
            r#"
server_addr = "example.com:7835"
server_fingerprint = "sha256:test"
"#,
        )
        .unwrap();
        assert!(!file.tunnels_paused);
    }

    #[test]
    fn client_file_persists_paused_state() {
        let file = ClientFile {
            tunnels_paused: true,
            ..Default::default()
        };
        let toml = toml::to_string(&file).unwrap();
        assert!(toml.contains("tunnels_paused = true"));
        let back: ClientFile = toml::from_str(&toml).unwrap();
        assert!(back.tunnels_paused);
    }

    #[test]
    fn logging_defaults_when_table_is_absent() {
        let logging = logging_from_str("server_addr = \"example.com:7835\"").unwrap();
        assert_eq!(logging, LoggingConfig::default());
    }

    #[test]
    fn logging_partial_table_uses_defaults() {
        let logging = logging_from_str(
            r#"
[logging]
mode = "file"
"#,
        )
        .unwrap();
        assert_eq!(logging.mode, LogMode::File);
        assert_eq!(logging.level, "info");
        assert_eq!(logging.directory, PathBuf::from("Logs"));
        assert_eq!(logging.max_files, 14);
    }

    #[test]
    fn logging_rejects_invalid_mode() {
        assert!(logging_from_str(
            r#"
[logging]
mode = "sideways"
"#
        )
        .is_err());
    }

    #[test]
    fn logging_accepts_zero_max_files() {
        let logging = logging_from_str(
            r#"
[logging]
max_files = 0
"#,
        )
        .unwrap();
        assert_eq!(logging.max_files, 0);
    }
}
