<!-- logo -->
```
       .-"""""-.
     .'  o o o  '.
    /  o  ___  o  \
   |  o  /   \  o  |     p o r t h o l e
   |  o |     | o  |     self-hosted tunnels
    \  o  \___/  o  /
     '.  o o o  .'
       '-.....-'
```

# porthole

A simple, self-hosted TCP/UDP tunneling & relay — a tiny alternative to playit.gg / ngrok /
`bore` that **you** run. Expose a service on a machine behind NAT (no port forwarding) to the
public internet through a server you control (e.g. a $5 VPS).

- **TCP and UDP** tunnels
- **Share one connection code** — no certs, fingerprints, or config files to hand-edit
- **Live terminal dashboard** (logo + stats + logs) and an **interactive web UI**
- **TLS everywhere** with certificate pinning + a shared token — secure by default
- A single static binary; one `porthole server`, one `porthole client`

## Quick start — share a connection code

**On your server** (a VPS with a public IP):

```sh
porthole server
# First run sets everything up and prints a connection code:
#
#   Share this connection code with anyone who should tunnel through you:
#
#       porthole1_eyJob3N0IjoiMTB4ZGV2LnNrIiwicG9ydCI6NzgzNS...
#
#   They run:  porthole join <code>
```

**On the other machine** (behind NAT — your PC, a friend's PC):

```sh
porthole join porthole1_eyJob3N0Ijoi...      # paste the code you were given
```

You do not pass `--fingerprint` to `porthole join`. The `porthole1_...` connection code already
contains the server address, the pinned TLS certificate fingerprint, and the shared secret; `join`
stores those in the client config for you.

If the server secret or certificate changes, generate a fresh connection code on the server.
Re-running `porthole join` with an old code will put the old secret/fingerprint back into the
client config.

That's it. The client connects, opens its dashboard, and you add tunnels (in the live web UI
at `http://127.0.0.1:4040`, or in the config). To expose a Minecraft server, point a tunnel at
`127.0.0.1:25565` and players connect to `your-server:25565`.

No code yet? Run the client with no arguments and it'll ask you to paste one:

```sh
porthole client      # prompts: "Paste your connection code:" (or set it up in the browser)
```

## How it works

The client is behind NAT and can't accept inbound connections, so it makes an **outbound** TLS
connection to the server (which always works through NAT). The server has a public IP and
relays public traffic back over connections the client opened.

```
   end user            porthole SERVER                  porthole CLIENT          your service
 (the internet)        (public VPS)                     (behind NAT)             (localhost)

   ┌────────┐  TCP/UDP   ┌───────────────────┐            ┌──────────────┐         ┌──────────┐
   │ player ├──────────► │ public port :25565│            │              │  dials  │ 127.0.0.1│
   │        │            │                   │            │              ├───────► │  :25565  │
   └────────┘            │ one TLS ingress   │            │              │         └──────────┘
                         │      :7835        │            │              │
                         └───────────────────┘            └──────────────┘
                              ▲         ▲                    │        │
                control conn  │         │   data conns       │        │
                (client dials ─┘         └─ (client dials ───┘        │
                 OUT, stays open)           OUT, on demand) ──────────┘
```

- **Control connection** — one long-lived TLS connection the client opens to the server. It
  carries auth, tunnel registration, and "a connection arrived" notifications.
- **TCP** — when someone hits a public port, the server tells the client; the client opens a
  fresh outbound data connection (paired by an unguessable id) and the server splices the two.
- **UDP** — datagrams are multiplexed over one data connection per tunnel, tagged with the
  end-user's address.
- **Security** — all hops between client and server are TLS. The server uses a self-signed
  certificate; its fingerprint travels inside the connection code, so the client pins it (no
  CA or domain needed). A shared token (also in the code) authenticates the client.

## The client experience

On an interactive terminal the client shows a live dashboard:

```
       .-"""""-.
     .'  o o o  '.        ... (purple logo) ...
       '-.....-'
  client · v0.3.0

  ● connected to 10xdev.sk:7835    public ports 1024-65535

    NAME           PROTO LOCAL              PUBLIC               STATUS      IN       OUT  CONNS
  ● minecraft      tcp   127.0.0.1:25565    10xdev.sk:25565      up       1.2 M    3.4 M     2

  ── logs ──────────────────────────────────────────────────
  tunnel 'minecraft' (tcp) is live at 10xdev.sk:25565
```

The web UI at `http://127.0.0.1:4040` shows the same and lets you add/remove/toggle tunnels.
It can also pause all tunnels at once. Pause is a persisted global hold: individual tunnel
`enabled` values stay unchanged, and unpause restores only the tunnels that were enabled.
Use `--no-banner` for plain log output (e.g. under a service manager).

## Configuration & CLI

```
porthole server [--public-host HOST] [--show-invite] [--config FILE] [--min-port N] [--max-port N]
porthole client [--code CODE] [--config FILE] [--web-bind 127.0.0.1:4040]
porthole join <CODE>
porthole service install server|client [--config FILE] [--working-dir DIR] [--start]
porthole service uninstall server|client
porthole gen-token
```

- `porthole server --show-invite [--public-host your.domain]` reprints the connection code.
  If the server uses a config file, always pass that same config when printing the code:
  `porthole server --config /path/to/server.toml --show-invite`.
  For the packaged systemd service, use the command in the deployment section so the invite is
  generated with the same `/etc/porthole/server.toml`, `PORTHOLE_SECRET`, and TLS certificate.
- `porthole join <CODE>` does not take `--fingerprint`; the code already includes the pinned
  fingerprint and shared secret, and the client saves them as `server_fingerprint` and `secret`.
  If you need to override the secret manually, use `porthole client` with `PORTHOLE_SECRET`,
  `--secret-file`, or a `secret = "..."` entry in the client config instead of `join`.
- Config files (`porthole-server.toml`, `porthole-client.toml`) are created next to the binary
  and updated as you change tunnels or pause/unpause them. See `config/*.example.toml`.
- `porthole server`, `porthole client`, and `porthole join` write daily rotated logs to
  `Logs/` under the process working directory by default, while keeping console/dashboard
  output enabled. Configure this in either TOML file:

```toml
[logging]
mode = "both"       # both | console | file | off
level = "info"      # RUST_LOG and -v/-vv override this
directory = "Logs"  # relative to the working directory unless absolute
max_files = 14      # 0 disables pruning
```

Log level precedence is `-v`/`-vv`, then `RUST_LOG`, then `logging.level`, then `info`.

## Windows service

Run these from an Administrator PowerShell or Command Prompt:

```powershell
porthole service install server --config C:\porthole\server.toml --working-dir C:\porthole --start
porthole service install client --config C:\porthole\client.toml --working-dir C:\porthole --start
```

`--working-dir` defaults to the directory containing `porthole.exe`. If `--config` is omitted,
the service uses `porthole-server.toml` or `porthole-client.toml` inside that working directory.
Logs default to the `Logs` folder inside that working directory. Create the config file before
using `--start`. The services are installed as `porthole-server` and `porthole-client`, set to
start automatically, and can be removed with:

```powershell
porthole service uninstall server
porthole service uninstall client
```

## Advanced (manual setup, no connection code)

You can wire things up by hand if you prefer. The server prints its certificate fingerprint at
startup; pin it on the client:

```sh
# server
PORTHOLE_SECRET=$(porthole gen-token) porthole server --min-port 20000 --max-port 30000
# client
PORTHOLE_SECRET=... porthole client \
  --server your-server:7835 \
  --fingerprint sha256:<from the server log> \
  --tunnel mc=tcp:127.0.0.1:25565->25565
```

`--tunnel` spec is `name=proto:LOCAL->REMOTE` (use REMOTE `0` for a server-assigned port).

## Build

Requires a recent Rust toolchain (`rustup`).

```sh
cargo build --release          # -> target/release/porthole
# static Linux binary for a VPS:
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The simplest deploy: `git clone` on the VPS and `cargo build --release` there.

## Deploy the server (systemd)

`scp` the binary to `/usr/local/bin/porthole`, then:

```sh
sudo install -d -m 755 /etc/porthole
sudo install -m 644 config/server.example.toml /etc/porthole/server.toml
printf 'PORTHOLE_SECRET=%s\n' "$(/usr/local/bin/porthole gen-token)" \
  | sudo tee /etc/porthole/porthole.env >/dev/null
sudo chmod 600 /etc/porthole/porthole.env
sudoedit /etc/porthole/server.toml       # set public_host and adjust the port range

sudo install -m 644 porthole.service /etc/systemd/system/porthole.service
sudo systemctl daemon-reload
sudo systemctl enable --now porthole
```

The packaged unit runs `porthole server --config /etc/porthole/server.toml`, so that file must
exist before the service starts. Its default rotated log files are written under
`/var/lib/porthole/Logs`. To print a client connection code from the same config, secret, and TLS
certificate used by systemd:

```sh
sudo sh -c 'set -a; . /etc/porthole/porthole.env; set +a; cd /var/lib/porthole && /usr/local/bin/porthole server --config /etc/porthole/server.toml --show-invite'
```

Open the ingress port and your public tunnel range in the firewall (e.g.
`ufw allow 7835/tcp`, `ufw allow 1024:65535/tcp` and `/udp`). The client needs no inbound rules.

## Security notes

- The connection code contains the shared secret — treat it like a password.
- Regenerating the server cert changes its fingerprint; existing codes/clients must re-pin.
- The server only grants public ports inside its configured range.

## License

MIT
