//! Command-line interface (clap derive).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "porthole",
    version,
    about = "Self-hosted TCP/UDP tunneling & relay service"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Increase log verbosity (-v = debug, -vv = trace). Overrides RUST_LOG.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Don't print the startup banner.
    #[arg(long, global = true)]
    pub no_banner: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the relay server (on your public droplet).
    Server(ServerArgs),
    /// Run the tunnel client (on the machine behind NAT). Also serves the local web UI.
    Client(ClientArgs),
    /// Connect to a relay using a connection code from its operator (porthole1_...).
    Join(JoinArgs),
    /// Install or uninstall porthole as a Windows service.
    Service(ServiceArgs),
    /// Print a fresh random secret token (use it on both server and client).
    GenToken,
}

#[derive(Args, Debug)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub command: ServiceCommand,
}

#[derive(Subcommand, Debug)]
pub enum ServiceCommand {
    /// Install an auto-start Windows service for the server or client.
    Install(ServiceInstallArgs),
    /// Uninstall a Windows service installed by porthole.
    Uninstall(ServiceUninstallArgs),
    /// Internal entrypoint used by the Windows Service Control Manager.
    #[command(hide = true)]
    Run(ServiceRunArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ServiceKind {
    Server,
    Client,
}

#[derive(Args, Debug)]
pub struct ServiceInstallArgs {
    /// Which porthole process this service should run.
    #[arg(value_enum)]
    pub kind: ServiceKind,
    /// Windows service name (default: porthole-server or porthole-client).
    #[arg(long)]
    pub name: Option<String>,
    /// Human-readable Windows service display name.
    #[arg(long)]
    pub display_name: Option<String>,
    /// TOML config file the service should use.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Directory porthole should use as its process working directory.
    ///
    /// Defaults to the directory containing this executable. If --config is omitted,
    /// the config file defaults to porthole-server.toml or porthole-client.toml in this directory.
    #[arg(long, value_name = "DIR")]
    pub working_dir: Option<PathBuf>,
    /// Start the service immediately after installing it.
    #[arg(long)]
    pub start: bool,
}

#[derive(Args, Debug)]
pub struct ServiceUninstallArgs {
    /// Which porthole service to uninstall.
    #[arg(value_enum)]
    pub kind: ServiceKind,
    /// Windows service name (default: porthole-server or porthole-client).
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ServiceRunArgs {
    /// Windows service name registered with the Service Control Manager.
    #[arg(long)]
    pub name: String,
    /// Which porthole process this service should run.
    #[arg(long, value_enum)]
    pub kind: ServiceKind,
    /// TOML config file the service should use.
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,
    /// Directory porthole should use as its process working directory.
    #[arg(long, value_name = "DIR")]
    pub working_dir: PathBuf,
}

#[derive(Args, Debug)]
pub struct JoinArgs {
    /// The connection code from the relay operator (porthole1_...).
    pub code: String,
    /// Address for the local web UI (default 127.0.0.1:4040).
    #[arg(long)]
    pub web_bind: Option<String>,
    /// Public host or IP to show for tunnel endpoints; defaults to the server address host.
    #[arg(long, value_name = "HOST")]
    pub public_addr: Option<String>,
}

#[derive(Args, Debug)]
pub struct ServerArgs {
    /// TOML config file (CLI flags override its values).
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Address to bind the ingress listener to (default 0.0.0.0).
    #[arg(long)]
    pub bind: Option<String>,
    /// Ingress (control + data) port.
    #[arg(long)]
    pub control_port: Option<u16>,
    /// Lowest public port a client may request.
    #[arg(long)]
    pub min_port: Option<u16>,
    /// Highest public port a client may request.
    #[arg(long)]
    pub max_port: Option<u16>,
    /// File containing the shared secret (preferred over putting it in argv/config).
    #[arg(long, value_name = "FILE")]
    pub secret_file: Option<PathBuf>,
    /// TLS certificate path (PEM). Auto-generated on first run if missing.
    #[arg(long, value_name = "FILE")]
    pub cert_path: Option<PathBuf>,
    /// TLS private key path (PEM). Auto-generated on first run if missing.
    #[arg(long, value_name = "FILE")]
    pub key_path: Option<PathBuf>,
    /// Public address (host or IP) clients use to reach this server; used in the connection code.
    #[arg(long)]
    pub public_host: Option<String>,
    /// Print a connection code to share with clients, then exit.
    #[arg(long)]
    pub show_invite: bool,
}

#[derive(Args, Debug)]
pub struct ClientArgs {
    /// TOML config file (CLI flags override its values; tunnels are appended).
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Connection code from the relay operator (porthole1_...); fills in server, fingerprint, secret.
    #[arg(long)]
    pub code: Option<String>,
    /// Server address, host:port.
    #[arg(long)]
    pub server: Option<String>,
    /// Pinned server certificate fingerprint (sha256:...). Required unless set in config.
    #[arg(long)]
    pub fingerprint: Option<String>,
    /// Address for the local web UI (default 127.0.0.1:4040).
    #[arg(long)]
    pub web_bind: Option<String>,
    /// Public host or IP to show for tunnel endpoints; defaults to the server address host.
    #[arg(long, value_name = "HOST")]
    pub public_addr: Option<String>,
    /// File containing the shared secret.
    #[arg(long, value_name = "FILE")]
    pub secret_file: Option<PathBuf>,
    /// Tunnel spec `name=proto:LOCAL->REMOTE[;proxy=v1|v2][;encrypted=true|false][;udp_mtu=N]` (repeatable),
    /// where proto is `tcp`, `udp`, or `both`.
    /// e.g. `mc=tcp:127.0.0.1:25565->25565`. Use REMOTE `0` for a server-assigned port.
    #[arg(long = "tunnel", value_name = "SPEC")]
    pub tunnels: Vec<String>,
}
