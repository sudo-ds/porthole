# porthole

A simple, self-hosted TCP/UDP tunneling & relay service — a minimal alternative to
playit.gg / ngrok / `bore` that **you** run. Expose a service on a machine behind NAT
(no port forwarding) to the public internet through a server you control (e.g. a $5
droplet).

- **TCP and UDP** tunnels
- **TLS everywhere** with certificate pinning (no domain or CA needed) + a shared token
- **Interactive web UI** on the client — add / remove / toggle tunnels at runtime
- **Fixed public ports** (request the exact port you want) within a server-allowed range
- A single static binary; one `porthole server` on the droplet, one `porthole client` at home

## How it works

The client is behind NAT and can't accept inbound connections, so it opens an **outbound**
TLS control connection to the server. The server has a public IP and listens on one ingress
port plus your public tunnel ports.

- **TCP:** when an end-user connects to a public port, the server tells the client over the
  control connection; the client dials a fresh outbound data connection (paired by an
  unguessable id) and the server splices the two. Your local service is reached at
  `127.0.0.1:<local-port>`.
- **UDP:** each UDP tunnel multiplexes all datagrams over one data connection, tagged with
  the end-user's address; the client keeps one ephemeral socket per end-user.

```
end-user ──▶ droplet:25565 ──(TLS)──▶ porthole server ──(TLS)──▶ porthole client ──▶ 127.0.0.1:25565
```

## Build

Requires a recent Rust toolchain (`rustup`).

```sh
cargo build --release        # -> target/release/porthole
```

A static Linux binary for the droplet (no glibc surprises):

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# or, if you have Docker:  cross build --release --target x86_64-unknown-linux-musl
# or:                      cargo zigbuild --release --target x86_64-unknown-linux-musl
```

The simplest path if cross-compiling is fussy: `git clone` on the droplet and
`cargo build --release` there.

## Quick start (local)

```sh
# 1. one shared secret for both sides
export PORTHOLE_SECRET=$(porthole gen-token)

# 2. server (prints its certificate fingerprint — copy it)
porthole server --bind 127.0.0.1 --control-port 7835 --min-port 20000 --max-port 20010

# 3. client: tunnel a local service (e.g. a Minecraft server on 25565)
porthole client \
  --server 127.0.0.1:7835 \
  --fingerprint sha256:<the fingerprint from step 2> \
  --tunnel mc=tcp:127.0.0.1:25565->25565

# 4. open the web UI
#    http://127.0.0.1:4040
```

`--tunnel` spec is `name=proto:LOCAL->REMOTE` (use REMOTE `0` for a server-assigned port).

## Deploy the server on a droplet

1. Copy the binary: `scp target/.../porthole root@droplet:/usr/local/bin/porthole`
2. Config + secret:
   ```sh
   ssh root@droplet
   mkdir -p /etc/porthole
   cp server.example.toml /etc/porthole/server.toml      # edit min/max ports
   printf 'PORTHOLE_SECRET=%s\n' "$(porthole gen-token)" > /etc/porthole/porthole.env
   chmod 600 /etc/porthole/porthole.env
   ```
   With the provided systemd unit the cert/key land in `/var/lib/porthole`
   (`WorkingDirectory` + `StateDirectory`); the defaults `porthole.crt` / `porthole.key`
   resolve there.
3. Firewall — open the ingress port and your public tunnel range:
   ```sh
   ufw allow 7835/tcp
   ufw allow 20000:30000/tcp
   ufw allow 20000:30000/udp
   ```
   The home client needs **no** inbound rules.
4. Service:
   ```sh
   cp porthole.service /etc/systemd/system/porthole.service
   systemctl enable --now porthole
   journalctl -u porthole -f      # note the printed server_fingerprint
   ```
5. On the client, set `server_addr`, `server_fingerprint`, and the same secret, then run
   `porthole client --config client.toml`.

## Web UI

The client serves a local dashboard at `http://127.0.0.1:4040` (loopback only). It shows each
tunnel's status, public address, traffic, and active connections, and lets you add, remove,
enable, or disable tunnels at runtime. Changes are persisted to the client config file
(if one is in use).

## Configuration

See `config/server.example.toml` and `config/client.example.toml`. Precedence is
**CLI flag > `PORTHOLE_SECRET` / env > config file > default**.

| | Server | Client |
|---|---|---|
| key fields | `bind_addr`, `control_port`, `min_port`, `max_port`, `cert_path`, `key_path` | `server_addr`, `server_fingerprint`, `web_bind`, `[[tunnels]]` |
| secret | `PORTHOLE_SECRET` / `--secret-file` / `secret` | same |

## Security

- All control and relayed traffic is encrypted with TLS. The server uses a self-signed
  certificate generated on first run; the client pins its SHA-256 fingerprint, so no CA or
  domain is required. **Keep the cert/key stable** — regenerating them changes the
  fingerprint and clients must re-pin.
- Clients authenticate with a shared bearer token (constant-time compared) sent inside TLS.
- The server only grants public ports inside `[min_port, max_port]`; defaults stay above
  1024 so no privileged bind is needed.
- Prefer `PORTHOLE_SECRET` or `--secret-file` over putting the secret on the command line
  (argv is visible in `ps`).

## License

MIT
