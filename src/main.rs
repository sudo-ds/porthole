use anyhow::Result;
use clap::Parser;
use uuid::Uuid;

use porthole::cli::{Cli, Command};
use porthole::{client, config, install_crypto_provider, server};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    install_crypto_provider()?;

    match cli.command {
        Command::GenToken => {
            // 244 bits of entropy, hex.
            println!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            Ok(())
        }
        Command::Server(args) => {
            let settings = config::load_server(&args)?;
            server::run(settings).await
        }
        Command::Client(args) => {
            let settings = config::load_client(&args)?;
            client::run(settings).await
        }
    }
}

fn init_tracing(verbose: u8) {
    use tracing_subscriber::EnvFilter;
    let filter = match verbose {
        0 => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        1 => EnvFilter::new("porthole=debug,info"),
        _ => EnvFilter::new("porthole=trace,debug"),
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
