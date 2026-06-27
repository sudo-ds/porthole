use std::io::IsTerminal;

use anyhow::Result;
use clap::Parser;

use porthole::cli::{Cli, Command};
use porthole::{banner, client, config, install_crypto_provider, logging, server, service, tui};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // A client on an interactive terminal gets the live dashboard; its logs go into the
    // dashboard's ring buffer rather than scrolling stdout.
    let dashboard = !cli.no_banner
        && std::io::stdout().is_terminal()
        && matches!(cli.command, Command::Client(_) | Command::Join(_));
    let _logging = logging::init_cli(&cli, dashboard)?;
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
        Command::Service(args) => match args.command {
            porthole::cli::ServiceCommand::Install(args) => service::install(args),
            porthole::cli::ServiceCommand::Uninstall(args) => service::uninstall(args),
            porthole::cli::ServiceCommand::Run(args) => service::run(args),
        },
    }
}
