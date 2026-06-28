# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What this is

porthole is a self-hosted TCP/UDP tunneling/relay (ngrok / `bore` / `rathole` class), in Rust.
A `server` runs on a public host; a `client` behind NAT dials **out** to it, and the server
relays public traffic back over those outbound connections. One binary, clap subcommands:
`server`, `client`, `join`, `gen-token`.

## Commands

Standard Cargo commands; use the `cargo` available in the current environment.

- `cargo build` / `cargo build --release`
- `cargo test` — unit tests (in `src/`) + the integration suite in `tests/e2e.rs`
- `cargo test <name>` — a single test, e.g. `cargo test udp_tunnel_roundtrip`
- `cargo clippy --all-targets` / `cargo fmt`
- Run locally: `PORTHOLE_SECRET=dev cargo run -- server --control-port 7835 --min-port 10000 --max-port 20000`,
  then `PORTHOLE_SECRET=dev cargo run -- client --server 127.0.0.1:7835 --fingerprint sha256:<from server log> --tunnel mc=tcp:127.0.0.1:25565->25565`.

The `tests/e2e.rs` suite binds everything to `127.0.0.1:0`, generates a fresh cert per test,
and pushes real bytes through the relay — it's the fastest way to validate protocol/relay
changes.

## Architecture (the parts that span files)

**lib.rs vs main.rs:** every module is `pub` in `lib.rs` so `tests/e2e.rs` can drive the
server/client in-process; `main.rs` is a thin CLI dispatcher (banner, tracing setup, then
`server::run_cli` / `client::run_cli` / `client::join`).

**Single ingress port, first-frame demux (the core trick):** the server listens on ONE TLS
port (`server.rs::handle_inbound`). After the TLS handshake the first framed message decides
the connection's role — `Hello{token}` → control connection (`handle_control`),
`DataHello{token,id}` → data connection (`handle_data_conn`). There is no separate data port.

**Control vs data connections:**
- The **control** connection is long-lived; the client registers tunnels, the server pushes
  `NewConn`/`Accepted`/`Rejected`. The per-connection *writer task is the only writer* — other
  tasks send via an `mpsc<ServerMessage>` (`tcp.rs`/`udp.rs` push through it).
- **TCP** uses on-demand data connections paired to a pending accept by an unguessable `Uuid`
  (the `bore` model): server stores a `oneshot` in `pending`, sends `NewConn`, the client dials
  a data conn with that id, the server splices with `copy_bidirectional`.
- **UDP** multiplexes all of a tunnel's datagrams over one data connection, tagged with the
  end-user `SocketAddr` (the `rathole` model). The server keeps no per-flow state; the client
  keeps one ephemeral socket per source addr with idle eviction.

**protocol.rs** owns the wire format: length-delimited frames (4-byte BE length) of JSON
`ClientMessage`/`ServerMessage`, the compact binary UDP codec, and `Prefixed` — an
`AsyncRead/Write` adapter that hands a framed connection off to raw byte splicing without
losing bytes the codec already buffered (the TCP handshake→splice boundary).

**TLS & auth (tls.rs, auth.rs):** server generates a self-signed cert with `rcgen`; the client
pins its SHA-256 leaf fingerprint via a custom `ServerCertVerifier`. That verifier MUST
implement `verify_tls12/13_signature` + `supported_verify_schemes` (delegating to the `ring`
provider) — stubbing them silently accepts forged handshakes. A `ring` `CryptoProvider` must be
installed at startup (`install_crypto_provider`) or rustls panics. Auth is a constant-time
bearer-token compare.

**Onboarding (invite.rs):** the `porthole1_…` connection code is base64url(JSON of
host/port/fingerprint/secret) — how a non-technical user connects without touching certs/config.
`server --show-invite` prints it; `client join <code>` / `--code` / the paste-the-code wizard
consume it.

**Client shared state (client.rs):** `ClientShared` is the hub (status `DashMap`, current
control writer behind `Mutex<Option<Sender>>`, advertised port range, shutdown token). The
reconnect supervisor owns connect/backoff; a single **command processor** drains web-UI commands
and is the *only* writer of the client config file (atomic temp+rename in `config.rs`). The web
UI (`web.rs` + embedded `static/index.html`) never touches sockets/config directly — it pushes
commands via `cmd_tx`.

**Dashboard (tui.rs):** for an interactive client, `main` routes `tracing` into a ring buffer
(a `MakeWriter`) instead of stdout and sets a global flag; `client::run` then runs the dashboard
in the foreground (redrawing logo + stats table + log tail) while the reconnect supervisor runs
as a task. Non-TTY or `--no-banner` falls back to plain logs.

**config.rs split:** `*Settings` are resolved runtime forms; `*File` are the on-disk TOML forms
(also the persistence form). Precedence: CLI > `PORTHOLE_SECRET`/env > config file > default;
default config lives next to the executable.

## Invariants to keep
- Never hold a `dashmap` guard across an `.await` (deadlock).
- Accept/recv loops must `select!` on a `CancellationToken` — dropping the listener/socket Arc
  does NOT wake a task parked in the syscall, so ports/flows leak on disconnect otherwise.
- The UDP client→server queue is bounded and drops on full (UDP is lossy); don't make it block.
- Public listeners use `SO_REUSEADDR` (via `socket2`) so fast client reconnects don't hit
  `AddrInUse`.

## Deployment
Production relays can run as hardened systemd services using `porthole.service` and
`DynamicUser`; keep service data and secrets in deployment-specific locations. Repo:
`github.com/sudo-ds/porthole`. Build a portable Linux binary with the
`x86_64-unknown-linux-musl` target, or build directly on the target host.
