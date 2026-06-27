#!/usr/bin/env bash
set -euo pipefail

REPO="${REPO:-sudo-ds/porthole}"
SERVICE="${SERVICE:-porthole}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/porthole}"
TARGET="${TARGET:-x86_64-unknown-linux-musl}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo $0"
  exit 1
fi

for cmd in curl jq tar sha256sum systemctl install find; do
  command -v "$cmd" >/dev/null || {
    echo "Missing required command: $cmd"
    echo "Install deps with: sudo apt-get update && sudo apt-get install -y curl jq coreutils tar"
    exit 1
  }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Fetching latest Porthole release..."
release_json="$tmp/release.json"
curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" -o "$release_json"

tag="$(jq -r '.tag_name' "$release_json")"
asset_name="$(
  jq -r --arg target "$TARGET" \
    '.assets[] | select(.name | endswith($target + ".tar.gz")) | .name' \
    "$release_json" | head -n1
)"
asset_url="$(
  jq -r --arg name "$asset_name" \
    '.assets[] | select(.name == $name) | .browser_download_url' \
    "$release_json"
)"
sha_name="${asset_name}.sha256"
sha_url="$(
  jq -r --arg name "$sha_name" \
    '.assets[] | select(.name == $name) | .browser_download_url' \
    "$release_json" | head -n1
)"

if [[ -z "$asset_name" || -z "$asset_url" || "$asset_url" == "null" ]]; then
  echo "Could not find Linux ${TARGET} tarball for release ${tag}"
  exit 1
fi

echo "Downloading ${tag}..."
archive="$tmp/$asset_name"
curl -fL "$asset_url" -o "$archive"

if [[ -n "$sha_url" && "$sha_url" != "null" ]]; then
  echo "Verifying SHA256..."
  curl -fsSL "$sha_url" -o "$tmp/$sha_name"
  (
    cd "$tmp"
    sha256sum -c "$sha_name"
  )
fi

tar -xzf "$archive" -C "$tmp"
new_bin="$(find "$tmp" -type f -name porthole -perm -111 | head -n1)"

if [[ -z "$new_bin" ]]; then
  echo "Downloaded release did not contain a porthole binary"
  exit 1
fi

echo "Installing to ${BIN_PATH}..."
if [[ -e "$BIN_PATH" ]]; then
  cp -a "$BIN_PATH" "${BIN_PATH}.bak"
fi
install -m 0755 "$new_bin" "${BIN_PATH}.new"
mv -f "${BIN_PATH}.new" "$BIN_PATH"

echo "Restarting ${SERVICE}.service..."
systemctl restart "$SERVICE"

echo "Done. Installed:"
"$BIN_PATH" --version
systemctl --no-pager --full status "$SERVICE" | sed -n '1,8p'
