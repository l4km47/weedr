#!/bin/bash

# ============================================================
# downloader.sh  (no root, static aria2 binary)
# Usage: ./downloader.sh "magnet:?xt=urn:btih:..."
# ============================================================

set -euo pipefail

DOWNLOAD_DIR="$HOME/torrents"
MAGNET_URL="${1-}"
USER_BIN="$HOME/.local/bin"
ARIA2_BIN="$USER_BIN/aria2c"
ARIA2_TMP_ROOT="/tmp/aria2-installer"
ARIA2_STATE_DIR="$HOME/.cache/aria2"
ARIA2_DHT_FILE="$ARIA2_STATE_DIR/dht.dat"
ARIA2_DHT6_FILE="$ARIA2_STATE_DIR/dht6.dat"
PUBLIC_TRACKERS="udp://tracker.opentrackr.org:1337/announce,udp://open.stealth.si:80/announce,udp://tracker.torrent.eu.org:451/announce,udp://exodus.desync.com:6969/announce,udp://tracker.openbittorrent.com:6969/announce,udp://tracker.internetwarriors.net:1337/announce"

# ---------- Helpers ----------
die() {
    echo "ERROR: $*" >&2
    exit 1
}

cleanup_aria2_artifacts() {
    rm -f "$ARIA2_BIN" /tmp/aria2.tar.* /tmp/aria2.pkg 2>/dev/null || true
    rm -rf "$ARIA2_TMP_ROOT" /tmp/aria2-* /tmp/*aria2* 2>/dev/null || true
    rm -f "$ARIA2_DHT_FILE" "$ARIA2_DHT6_FILE" "$ARIA2_STATE_DIR"/aria2.session* 2>/dev/null || true
}

download_to_file() {
    local url="$1"
    local out="$2"
    if command -v curl &>/dev/null; then
        curl -fL -o "$out" "$url"
    elif command -v wget &>/dev/null; then
        wget -O "$out" "$url"
    else
        die "Neither curl nor wget is available. Install one of them first."
    fi
}

extract_archive() {
    local archive="$1"
    local dest="$2"

    if tar -xf "$archive" -C "$dest" 2>/dev/null; then
        return 0
    fi
    if command -v bsdtar &>/dev/null && bsdtar -xf "$archive" -C "$dest" 2>/dev/null; then
        return 0
    fi
    if command -v unzip &>/dev/null && unzip -q "$archive" -d "$dest" 2>/dev/null; then
        return 0
    fi
    return 1
}

fetch_release_assets() {
    local api_url="$1"
    local out_file="$2"

    if command -v curl &>/dev/null; then
        curl -fsSL "$api_url" | sed -n 's/.*"browser_download_url": *"\([^"]*\)".*/\1/p' > "$out_file"
    elif command -v wget &>/dev/null; then
        wget -qO- "$api_url" | sed -n 's/.*"browser_download_url": *"\([^"]*\)".*/\1/p' > "$out_file"
    else
        die "Neither curl nor wget is available. Install one of them first."
    fi
}

# ---------- Validate input ----------
if [[ -z "$MAGNET_URL" ]]; then
    echo "Usage: $0 \"magnet:?xt=urn:btih:...\""
    exit 1
fi

if [[ ! "$MAGNET_URL" =~ ^magnet:\?xt=urn:btih: ]]; then
    die "Invalid magnet URL. Must start with 'magnet:?xt=urn:btih:'"
fi

# ---------- Cleanup + reinstall aria2 every run ----------
echo "Cleaning old aria2 install/artifacts..."
cleanup_aria2_artifacts
mkdir -p "$USER_BIN" "$ARIA2_TMP_ROOT"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        ARCH_PATTERNS=("amd64" "x86_64" "64" "x64")
        ;;
    aarch64|arm64)
        ARCH_PATTERNS=("arm64" "aarch64")
        ;;
    armv7l|armv7|armhf)
        ARCH_PATTERNS=("armhf" "armv7")
        ;;
    i386|i686)
        ARCH_PATTERNS=("i386" "i686" "32")
        ;;
    *)
        die "Unsupported architecture '$ARCH' for automatic aria2 install. Install aria2c manually."
        ;;
esac

ASSET_LIST="/tmp/aria2-assets.txt"
ARIA2_RELEASE_API="https://api.github.com/repos/P3TERX/Aria2-Pro-Core/releases/latest"
echo "Fetching latest release assets from P3TERX/Aria2-Pro-Core..."
fetch_release_assets "$ARIA2_RELEASE_API" "$ASSET_LIST" || die "Failed to query GitHub release assets"
[[ -s "$ASSET_LIST" ]] || die "No assets found in latest Aria2-Pro-Core release"

ARIA2C_EXTRACTED=""
while IFS= read -r ARIA2_URL; do
    lower_url=$(echo "$ARIA2_URL" | tr '[:upper:]' '[:lower:]')
    matches_arch=0
    for p in "${ARCH_PATTERNS[@]}"; do
        if [[ "$lower_url" == *"$p"* ]]; then
            matches_arch=1
            break
        fi
    done

    if [[ "$matches_arch" -ne 1 ]]; then
        continue
    fi
    if [[ "$lower_url" != *.tar.* && "$lower_url" != *.zip ]]; then
        continue
    fi

    ARIA2_PKG="/tmp/aria2.pkg"
    echo "Trying aria2 package: $ARIA2_URL"
    rm -f "$ARIA2_PKG"
    rm -rf "$ARIA2_TMP_ROOT"/*

    if ! download_to_file "$ARIA2_URL" "$ARIA2_PKG"; then
        echo "Failed download from this URL, trying next..."
        continue
    fi

    if ! extract_archive "$ARIA2_PKG" "$ARIA2_TMP_ROOT"; then
        echo "Archive extraction failed for this package, trying next..."
        continue
    fi

    for candidate in "$ARIA2_TMP_ROOT"/aria2c "$ARIA2_TMP_ROOT"/aria2-*/aria2c "$ARIA2_TMP_ROOT"/aria2*/aria2c "$ARIA2_TMP_ROOT"/*aria2*/aria2c; do
        if [[ -f "$candidate" ]]; then
            ARIA2C_EXTRACTED="$candidate"
            break
        fi
    done

    if [[ -n "$ARIA2C_EXTRACTED" ]]; then
        break
    fi
done < "$ASSET_LIST"

if [[ -z "$ARIA2C_EXTRACTED" ]]; then
    die "Failed to install aria2c automatically. All package URLs failed."
fi

cp "$ARIA2C_EXTRACTED" "$ARIA2_BIN"
chmod +x "$ARIA2_BIN"
rm -f /tmp/aria2.pkg
rm -f "$ASSET_LIST"
rm -rf "$ARIA2_TMP_ROOT"
echo "aria2c installed to $ARIA2_BIN"

# Ensure aria2c is in PATH (add user bin if needed)
if ! command -v aria2c &>/dev/null; then
    export PATH="$USER_BIN:$PATH"
fi

[[ -x "$ARIA2_BIN" ]] || die "aria2c binary missing after install: $ARIA2_BIN"

# ---------- Create download directory ----------
mkdir -p "$DOWNLOAD_DIR" || die "Cannot create $DOWNLOAD_DIR"
mkdir -p "$ARIA2_STATE_DIR" || die "Cannot create $ARIA2_STATE_DIR"

# ---------- Download torrent without seeding ----------
echo "Starting download to: $DOWNLOAD_DIR"
"$ARIA2_BIN" \
    --no-conf=true \
    --dir="$DOWNLOAD_DIR" \
    --seed-time=0 \
    --bt-save-metadata=true \
    --bt-tracker="$PUBLIC_TRACKERS" \
    --enable-dht=true \
    --enable-dht6=true \
    --dht-file-path="$ARIA2_DHT_FILE" \
    --dht-file-path6="$ARIA2_DHT6_FILE" \
    --follow-torrent=mem \
    --max-connection-per-server=16 \
    --split=16 \
    --min-split-size=1M \
    "$MAGNET_URL"

# ---------- Report ----------
echo "Download finished successfully."