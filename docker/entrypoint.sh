#!/bin/sh
set -eu

STATE_DIR="${PORTHOLE_STATE_DIR:-/var/lib/porthole}"
CONFIG_FILE="${PORTHOLE_CONFIG_FILE:-$STATE_DIR/server.toml}"

die() {
    echo "porthole-entrypoint: $*" >&2
    exit 64
}

toml_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

require_uint() {
    name="$1"
    value="$2"
    case "$value" in
        ''|*[!0-9]*) die "$name must be a positive integer" ;;
    esac
}

render_config() {
    public_host="${PORTHOLE_PUBLIC_HOST:-}"
    secret="${PORTHOLE_SECRET:-}"
    control_port="${PORTHOLE_CONTROL_PORT:-7835}"
    min_port="${PORTHOLE_MIN_PORT:-10000}"
    max_port="${PORTHOLE_MAX_PORT:-20000}"
    log_level="${PORTHOLE_LOG_LEVEL:-info}"
    log_mode="${PORTHOLE_LOG_MODE:-console}"

    [ -n "$public_host" ] || die "set PORTHOLE_PUBLIC_HOST to this relay's public DNS name or IP"
    [ -n "$secret" ] || die "set PORTHOLE_SECRET or run ./scripts/setup-docker-server.sh"
    case "$public_host" in
        203.0.113.*|your.domain.or.ip|YOUR.SERVER.IP)
            die "PORTHOLE_PUBLIC_HOST is still a placeholder; set it to this relay's public DNS name or IP"
            ;;
    esac
    case "$secret" in
        replace-with-a-random-secret|CHANGE_ME|change-me*)
            die "PORTHOLE_SECRET is still a placeholder; run ./scripts/setup-docker-server.sh"
            ;;
    esac
    require_uint "PORTHOLE_CONTROL_PORT" "$control_port"
    require_uint "PORTHOLE_MIN_PORT" "$min_port"
    require_uint "PORTHOLE_MAX_PORT" "$max_port"

    mkdir -p "$STATE_DIR"

    tmp="$CONFIG_FILE.tmp"
    cat > "$tmp" <<EOF
bind_addr = "0.0.0.0"
control_port = $control_port
public_host = "$(toml_escape "$public_host")"
min_port = $min_port
max_port = $max_port
cert_path = "$(toml_escape "$STATE_DIR")/porthole.crt"
key_path = "$(toml_escape "$STATE_DIR")/porthole.key"

[logging]
mode = "$(toml_escape "$log_mode")"
level = "$(toml_escape "$log_level")"
directory = "$(toml_escape "$STATE_DIR")/Logs"
max_files = 14
EOF
    mv "$tmp" "$CONFIG_FILE"
}

cmd="${1:-server}"

case "$cmd" in
    server)
        shift || true
        render_config
        exec porthole --no-banner server --config "$CONFIG_FILE" "$@"
        ;;
    invite)
        shift || true
        render_config
        exec porthole --no-banner server --config "$CONFIG_FILE" --show-invite "$@"
        ;;
    --version|-V|--help|-h|gen-token|client|join|service)
        exec porthole "$@"
        ;;
    -*)
        render_config
        exec porthole --no-banner server --config "$CONFIG_FILE" "$@"
        ;;
    *)
        exec porthole "$@"
        ;;
esac
