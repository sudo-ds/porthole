#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/setup-docker-server.sh [--public-host HOST] [--force]

Creates a root .env file for the Docker server template.

Options:
  --public-host HOST   DNS name or public IP to bake into connection codes
  --force              overwrite an existing .env
  -h, --help           show this help
EOF
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="${repo_root}/.env"
public_host="${PORTHOLE_PUBLIC_HOST:-}"
force=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-host)
      [[ $# -ge 2 ]] || { echo "--public-host needs a value" >&2; exit 64; }
      public_host="$2"
      shift 2
      ;;
    --force)
      force=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

detect_public_ip() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true
  fi
}

generate_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
    printf '\n'
  fi
}

if [[ -z "$public_host" ]]; then
  public_host="$(detect_public_ip)"
fi

if [[ -z "$public_host" && -t 0 ]]; then
  read -r -p "Public DNS name or IP for this relay: " public_host
fi

if [[ -z "$public_host" ]]; then
  echo "Could not detect a public IP. Re-run with --public-host your.domain.or.ip" >&2
  exit 64
fi

if [[ "$public_host" =~ [[:space:]] ]]; then
  echo "Public host must not contain whitespace: ${public_host}" >&2
  exit 64
fi

if [[ -e "$env_file" && "$force" -ne 1 ]]; then
  echo "${env_file} already exists. Re-run with --force to overwrite it." >&2
  exit 1
fi

secret="${PORTHOLE_SECRET:-$(generate_secret)}"
tmp="${env_file}.tmp"

cat > "$tmp" <<EOF
PORTHOLE_PUBLIC_HOST=${public_host}
PORTHOLE_SECRET=${secret}

PORTHOLE_CONTROL_PORT=${PORTHOLE_CONTROL_PORT:-7835}
PORTHOLE_MIN_PORT=${PORTHOLE_MIN_PORT:-10000}
PORTHOLE_MAX_PORT=${PORTHOLE_MAX_PORT:-20000}
PORTHOLE_LOG_LEVEL=${PORTHOLE_LOG_LEVEL:-info}
PORTHOLE_LOG_MODE=${PORTHOLE_LOG_MODE:-console}

# PORTHOLE_IMAGE=ghcr.io/sudo-ds/porthole:latest
EOF

chmod 600 "$tmp"
mv "$tmp" "$env_file"

cat <<EOF
Wrote ${env_file}

Next:
  docker compose pull
  docker compose up -d
  docker compose logs -f porthole

Print the client connection code:
  docker compose run --rm porthole invite
EOF
