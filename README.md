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

- **TCP, UDP, and same-port TCP+UDP** tunnels
- Optional TCP source IP forwarding with **PROXY protocol v1/v2**
- **Share one connection code** — no certs, fingerprints, or config files to hand-edit
- **Live terminal dashboard** (logo + stats + logs) and an **interactive web UI**
- **TLS-pinned control** with optional per-tunnel data encryption
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
control connection to the server (which always works through NAT). The server has a public IP
and relays public traffic back over data channels the client opened.

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
  TCP data channels are plaintext by default; set `encrypted = true` to wrap them in TLS.
- **UDP** — plaintext UDP tunnels use a native authenticated UDP data channel for lower latency.
  Large plaintext datagrams are fragmented/reassembled between the relay and client according
  to `udp_mtu` (default `1200`). Set `encrypted = true` to use the compatibility path that
  multiplexes UDP over TLS/TCP.
- **Both** — for services that bind TCP and UDP on the same port, set `protocol = "both"`.
  The relay binds both public sockets on one port and uses the same `encrypted` setting for
  both halves. PROXY protocol is not available in this mode.
- **Security** — control traffic is always TLS. The server uses a self-signed certificate; its
  fingerprint travels inside the connection code, so the client pins it (no CA or domain needed).
  A shared token (also in the code) authenticates the client. Plain data channels are not
  encrypted; plaintext UDP packets are authenticated to prevent off-path injection.

## The client experience

On an interactive terminal the client shows a live dashboard:

```
       .-"""""-.
     .'  o o o  '.        ... (purple logo) ...
       '-.....-'
  client · v0.5.2

  ● connected to 10xdev.sk:7835    public ports 1024-65535

    NAME           PROTO LOCAL              PUBLIC               STATUS      IN       OUT  CONNS
  ● minecraft      tcp   127.0.0.1:25565    10xdev.sk:25565      up       1.2 M    3.4 M     2

  ── logs ──────────────────────────────────────────────────
  tunnel 'minecraft' (tcp) is live at 10xdev.sk:25565
```

The web UI at `http://127.0.0.1:4040` shows the same, live bandwidth/latency history, and lets
you add/edit/remove/toggle tunnels. It can also pause all tunnels at once. Pause is a persisted
global hold: individual tunnel `enabled` values stay unchanged, and unpause restores only the
tunnels that were enabled.
Use `--no-banner` for plain log output (e.g. under a service manager).

## Configuration & CLI

```
porthole server [--public-host HOST] [--show-invite] [--config FILE] [--min-port N] [--max-port N]
porthole client [--code CODE] [--config FILE] [--web-bind 127.0.0.1:4040] [--public-addr HOST]
porthole join <CODE> [--public-addr HOST]
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
- Set `public_addr = "10xdev.sk"` in the client config, or pass `--public-addr HOST`,
  to show tunnel endpoints as `HOST:<public_port>` while still dialing `server_addr` for the
  control connection and encrypted TCP data connections.
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

`--tunnel` spec is
`name=proto:LOCAL->REMOTE[;proxy=v1|v2][;encrypted=true|false][;udp_mtu=N][;udp_source_pool=CIDR]`
(use REMOTE `0` for a server-assigned port). The `encrypted` key also accepts `encrypt` or `tls` as aliases.
`proto` is `tcp`, `udp`, or `both`. For UDP-capable tunnels, `udp_mtu` also accepts `mtu`;
it defaults to `1200` and must be between `256` and `65507`.

`LOCAL` may also select multiple local ports. Ranges are inclusive:
`games=udp:127.0.0.1:4000-6000->0` asks the relay to reserve the first contiguous public block
with the same number of ports. Sparse lists are also supported:
`admin=tcp:127.0.0.1:1000,2000->0` maps those local ports to the first free public ports. If
REMOTE is non-zero, it is treated as the fixed public start for a range, or the fixed first
public port for a sparse list. A logical tunnel may reserve up to 2048 public ports.

### TCP source IP forwarding

By default your local service sees incoming TCP connections as coming from the porthole client
machine, usually `127.0.0.1` or a LAN address. For TCP services that explicitly support the
[HAProxy PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt), enable
source IP forwarding per tunnel:

```toml
[[tunnels]]
name = "minecraft"
protocol = "tcp"
local_addr = "127.0.0.1:25565"
remote_port = 25565
encrypted = false    # false = plaintext data, true = TLS data
proxy_protocol = "v1" # off | v1 | v2
```

Or from the CLI:

```sh
porthole client ... --tunnel 'mc=tcp:127.0.0.1:25565->25565;proxy=v1;encrypted=true'
```

The web UI exposes the same setting as a TCP-only advanced option when adding a tunnel, and
shows a PROXY badge for tunnels using it. `protocol = "both"` cannot use PROXY protocol.

Only enable this if the upstream service is configured to accept PROXY protocol. Incompatible
servers will receive the PROXY header before the normal game/application traffic and will often
drop the connection. Also make sure the upstream service only accepts PROXY protocol from the
trusted porthole client address, such as `127.0.0.1` or a private LAN IP; otherwise direct
callers could spoof client IPs by sending their own PROXY header. UDP and both-protocol tunnels
do not support this option.

### UDP MTU and fragmentation

Plaintext UDP-capable tunnels (`encrypted = false`) use authenticated native UDP packets between the
relay and client. If the encoded datagram is larger than `udp_mtu`, porthole fragments it into
multiple authenticated relay packets and reassembles it on the other side. `udp_mtu` is the
maximum porthole UDP packet payload sent on the socket, excluding outer IP/UDP headers.

```toml
[[tunnels]]
name = "valheim"
protocol = "udp"
local_addr = "127.0.0.1:2456"
remote_port = 2456
encrypted = false
udp_mtu = 1200      # default; valid range 256-65507
```

Encrypted UDP-capable tunnels (`encrypted = true`) keep the compatibility path that multiplexes
UDP over TLS/TCP, so `udp_mtu` is reported but not used by that data channel.

### Experimental UDP source address pooling

For UDP game servers running on the same machine as the porthole client, an experimental
loopback source pool can make different Internet peers appear as different local source IPs.
This does not forward real client IPs; it assigns stable synthetic `127.x.x.x` addresses while
each UDP flow is active.

```toml
[[tunnels]]
name = "bedrock"
protocol = "udp"
local_addr = "127.0.0.1:19132"
remote_port = 19132
udp_source_pool = "127.64.0.0/16"
```

Or from the CLI:

```sh
porthole client ... --tunnel 'bedrock=udp:127.0.0.1:19132->19132;udp_source_pool=127.64.0.0/16'
```

`udp_source_pool` is client-only and requires a UDP-capable tunnel whose `local_addr` is IPv4
loopback. Only IPv4 CIDRs inside `127.0.0.0/8` are accepted. If all pool addresses are in use,
datagrams from new UDP peers are dropped until existing flows go idle.

## Build

Requires a recent Rust toolchain (`rustup`).

```sh
cargo build --release          # -> target/release/porthole
# static Linux binary for a VPS:
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The simplest deploy: `git clone` on the VPS and `cargo build --release` there.

## Deploy the server (Docker)

For a fresh VPS, Docker is the easiest server path. The Compose template uses host networking
because porthole binds one control port plus whatever public TCP/UDP tunnel ports clients
request.

```sh
git clone https://github.com/sudo-ds/porthole.git
cd porthole
bash ./scripts/setup-docker-server.sh --public-host your.domain.or.ip
docker compose pull
docker compose up -d
docker compose run --rm porthole invite
```

The setup script writes `.env` with a random `PORTHOLE_SECRET`, `chmod 600`s it, and defaults to:

```dotenv
PORTHOLE_CONTROL_PORT=7835
PORTHOLE_MIN_PORT=10000
PORTHOLE_MAX_PORT=20000
PORTHOLE_LOG_LEVEL=info
PORTHOLE_LOG_MODE=console
```

The container renders `/var/lib/porthole/server.toml` from those values on startup. The shared
secret stays in `.env`; the TLS cert, key, generated server config, and optional file logs live in
the `porthole-data` Docker volume. Back up both `.env` and that volume if you want existing
connection codes to keep working after a move. Deleting the volume regenerates the TLS cert and
invalidates old connection codes.

Useful Docker commands:

```sh
docker compose logs -f porthole
docker compose run --rm porthole invite
docker compose pull && docker compose up -d
```

Open the control port and tunnel range in your provider firewall and on the host firewall. For
the defaults:

```sh
ufw allow 7835/tcp
ufw allow 10000:20000/tcp
ufw allow 10000:20000/udp
```

The default image is `ghcr.io/sudo-ds/porthole:latest`. To pin a release or use a fork, add a
`PORTHOLE_IMAGE=...` line to `.env`. The default container runs unprivileged, so public tunnel
ports below `1024` are not supported unless you intentionally customize the container privileges.

### DigitalOcean one-boot setup

When creating an Ubuntu droplet, paste `deploy/digitalocean/cloud-init.yaml` into the
DigitalOcean User Data / Startup Script box. If you are using a fork or a repository created from
this template, edit `REPO_URL` in that file first. It installs Docker Engine from Docker's Ubuntu
apt repository, clones the repo to `/opt/porthole`, creates `.env`, pulls the GHCR image, and
starts the server.

After the droplet finishes booting:

```sh
ssh root@your-droplet
cd /opt/porthole
docker compose logs -f porthole
docker compose run --rm porthole invite
```

Also configure the DigitalOcean Cloud Firewall for `7835/tcp` and your chosen tunnel range for
both TCP and UDP.

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

### Example: private control plane over Tailscale

A useful VPS setup is to keep the relay's control plane private, while still exposing the
tunnels themselves on the public internet:

- your VPS runs porthole server and a Tailscale client
- port `7835/tcp` and SSH are reachable only over Tailscale, by you
- the tunnel port range, such as `10000:20000/tcp` and `/udp`, is reachable from the public
  internet
- the client dials the server through its Tailscale address, but the dashboard/web UI shows
  tunnel endpoints on your public hostname

For that shape, let porthole bind normally on the VPS and enforce the private control plane in
your firewall and Tailscale ACLs:

```toml
# /etc/porthole/server.toml on the VPS
bind_addr = "0.0.0.0"
control_port = 7835
min_port = 10000
max_port = 20000

# Address baked into connection codes. Use a Tailscale MagicDNS name or 100.x.y.z address
# for the TLS control connection and encrypted TCP data channels.
public_host = "relay.your-tailnet.ts.net"
```

Then configure the client to connect to the Tailscale address, but display the public host for
created tunnels:

```toml
# porthole-client.toml
server_addr = "relay.your-tailnet.ts.net:7835"
public_addr = "tunnels.example.com"
web_bind = "127.0.0.1:4040"
```

Leave `web_bind` on `127.0.0.1` when you manage tunnels from the same machine. If the client
runs somewhere else and you want to reach its web UI over Tailscale, bind it to that client's
Tailscale address and restrict the port with Tailscale ACLs; do not expose the web UI publicly.

Or, when joining from a connection code:

```sh
porthole join porthole1_... --public-addr tunnels.example.com
```

With this setup, porthole control traffic and encrypted TCP data channels use Tailscale on
`relay.your-tailnet.ts.net:7835`, while end users and plaintext UDP data channels use public
tunnel endpoints such as `tunnels.example.com:25565`.

The exact firewall rules depend on your distro and provider, but the intent is:

```sh
# allow your private control plane
ufw allow in on tailscale0 to any port 7835 proto tcp
ufw allow in on tailscale0 to any port 22 proto tcp

# expose only the tunnel range publicly
ufw allow 10000:20000/tcp
ufw allow 10000:20000/udp

# do not allow public internet traffic to 7835
```

If the VPS is tagged as untrusted in Tailscale, use ACLs so it does not gain access to the rest
of your tailnet; it only needs to accept connections from your admin devices on `7835` and
optionally `22`.

## Security notes

- The connection code contains the shared secret — treat it like a password.
- Regenerating the server cert changes its fingerprint; existing codes/clients must re-pin.
- The server only grants public ports inside its configured range.
- Data channels default to plaintext. Set `encrypted = true` per tunnel when confidentiality
  matters more than lowest latency.

## License

MIT
