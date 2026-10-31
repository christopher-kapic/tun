#!/bin/sh
# cockpit-tunnel installer: download cockpit-tunnel-server, verify its minisign
# signature and SHA-256, install it to /usr/local/bin, then run the setup
# wizard. All configuration logic lives in `cockpit-tunnel-server setup`.
#
#   curl -fsSL https://<private-host>/install.sh | sh
#   curl -fsSL https://<private-host>/install.sh | sh -s -- --staging
set -eu

# REPLACE before publishing: base URL of the release artifacts.
DOWNLOAD_BASE="${DOWNLOAD_BASE:-https://downloads.example.invalid/cockpit-tunnel/latest}"
# REPLACE before publishing: the minisign public key (second line of minisign.pub).
MINISIGN_PUBKEY="REPLACE_WITH_MINISIGN_PUBLIC_KEY"
PUBKEY_PLACEHOLDER="REPLACE_WITH_MINISIGN_PUBLIC_KEY"

BIN=cockpit-tunnel-server
INSTALL_DIR=/usr/local/bin

die() {
    echo "install.sh: $*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || die "only Linux is supported"
[ "$(id -u)" = 0 ] || die "must run as root (curl -fsSL ... | sudo sh)"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

case "$(uname -m)" in
    x86_64 | amd64) target=x86_64-unknown-linux-musl ;;
    aarch64 | arm64) target=aarch64-unknown-linux-musl ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac
asset="$BIN-$target"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM

fetch() {
    curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$1" "$DOWNLOAD_BASE/$1" ||
        die "download failed: $DOWNLOAD_BASE/$1"
}

install_minisign() {
    command -v minisign >/dev/null 2>&1 && return 0
    echo "Installing minisign"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq minisign
    elif command -v dnf >/dev/null 2>&1; then
        # Fedora ships minisign; RHEL-likes need EPEL.
        dnf install -y -q minisign || { dnf install -y -q epel-release && dnf install -y -q minisign; }
    fi
    command -v minisign >/dev/null 2>&1 || die "could not install minisign"
}

echo "Downloading $asset from $DOWNLOAD_BASE"
fetch "$asset"
fetch SHA256SUMS
fetch SHA256SUMS.minisig

if [ "$MINISIGN_PUBKEY" = "$PUBKEY_PLACEHOLDER" ]; then
    if [ "${COCKPIT_ALLOW_UNSIGNED:-0}" = 1 ]; then
        echo "WARNING: no minisign public key embedded; skipping signature check (COCKPIT_ALLOW_UNSIGNED=1)" >&2
    else
        die "this installer has no minisign public key embedded; refusing to install (set COCKPIT_ALLOW_UNSIGNED=1 to override)"
    fi
else
    install_minisign
    minisign -V -q -P "$MINISIGN_PUBKEY" -m "$tmp/SHA256SUMS" -x "$tmp/SHA256SUMS.minisig" ||
        die "SHA256SUMS signature verification failed"
fi

# Lines are "<hash>  <name>" (or "<hash> *<name>" in binary mode).
expected=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || die "$asset is not listed in SHA256SUMS"
actual=$(sha256sum "$tmp/$asset" | awk '{ print $1 }')
[ "$expected" = "$actual" ] || die "checksum mismatch for $asset (expected $expected, got $actual)"

# Copy then rename, so a running service's binary is replaced atomically.
mkdir -p "$INSTALL_DIR"
cp "$tmp/$asset" "$INSTALL_DIR/.$BIN.new"
chmod 0755 "$INSTALL_DIR/.$BIN.new"
mv -f "$INSTALL_DIR/.$BIN.new" "$INSTALL_DIR/$BIN"
echo "Installed $INSTALL_DIR/$BIN ($("$INSTALL_DIR/$BIN" --version 2>/dev/null || echo unknown version))"

# exec skips the EXIT trap.
rm -rf "$tmp"
trap - EXIT INT TERM

(exec </dev/tty) 2>/dev/null || die "no terminal available; run '$INSTALL_DIR/$BIN setup' from an interactive shell"
exec "$INSTALL_DIR/$BIN" setup "$@" </dev/tty
