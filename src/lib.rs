//! porthole — a simple self-hosted TCP/UDP tunneling & relay service.
//!
//! The server runs on a public host and relays traffic to a client behind NAT over
//! connections the client initiates outbound. See the `server` and `client` modules.

pub mod auth;
pub mod banner;
pub mod cli;
pub mod client;
pub mod config;
pub mod diagnostics;
pub mod invite;
pub mod logging;
pub mod net;
pub mod protocol;
pub mod server;
pub mod service;
pub mod tcp;
pub mod tls;
pub mod tui;
pub mod udp;
pub mod web;

/// Install the process-wide rustls crypto provider (ring). Call once at startup.
pub fn install_crypto_provider() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls ring crypto provider"))
}
