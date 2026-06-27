//! Command-line interface (clap derive).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

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
    /// Print a fresh random secret token (use it on both server and client).
    GenToken,
}

#[derive(Args, Debug)]
pub struct JoinArgs {
    /// The connection code from the relay operator (porthole1_...).
    pub code: String,
    /// Address for the local web UI (default 127.0.0.1:4040).
    #[arg(long)]
    pub web_bind: Option<String>,
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
    /// File containing the shared secret.
    #[arg(long, value_name = "FILE")]
    pub secret_file: Option<PathBuf>,
    /// Tunnel spec `name=proto:LOCAL->REMOTE` (repeatable),
    /// e.g. `mc=tcp:127.0.0.1:25565->25565`. Use REMOTE `0` for a server-assigned port.
    #[arg(long = "tunnel", value_name = "SPEC")]
    pub tunnels: Vec<String>,
}
