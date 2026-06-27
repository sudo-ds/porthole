use std::io::IsTerminal;

use anyhow::Result;
use clap::Parser;

use porthole::cli::{Cli, Command};
use porthole::{banner, client, config, install_crypto_provider, server, tui};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // A client on an interactive terminal gets the live dashboard; its logs go into the
    // dashboard's ring buffer rather than scrolling stdout.
    let dashboard = !cli.no_banner
        && std::io::stdout().is_terminal()
        && matches!(cli.command, Command::Client(_) | Command::Join(_));
    init_tracing(cli.verbose, dashboard);
    if dashboard {
        tui::set_enabled(true);
    }

    install_crypto_provider()?;
    let show_banner = !cli.no_banner;

    match cli.command {
        Command::GenToken => {
            println!("{}", config::gen_secret());
            Ok(())
        }
        Command::Server(args) => {
            banner::print(&format!("relay server · v{VERSION}"), show_banner);
            server::run_cli(args).await
        }
        Command::Client(args) => {
            banner::print(&format!("client · v{VERSION}"), show_banner);
            client::run_cli(args).await
        }
        Command::Join(args) => {
            banner::print(&format!("client · v{VERSION}"), show_banner);
            client::join(args).await
        }
    }
}

fn init_tracing(verbose: u8, to_buffer: bool) {
    use tracing_subscriber::EnvFilter;
    let filter = match verbose {
        0 => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        1 => EnvFilter::new("porthole=debug,info"),
        _ => EnvFilter::new("porthole=trace,debug"),
    };
    if to_buffer {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(false)
            .without_time()
            .with_writer(tui::make_writer())
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .init();
    }
}
