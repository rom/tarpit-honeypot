#!/bin/sh
# Builds a .deb of tarpit-honeypot.
#
# Inputs (env or override):
#   ARCH       — dpkg arch (amd64 / arm64 / armhf). Default: amd64.
#   VERSION    — package version. Default: git describe --tags --always.
#   BIN        — path to a pre-built static binary. If unset, this
#                script runs `make cross` and picks the matching arch.
#
# Output:
#   dist/tarpit-honeypot_<version>_<arch>.deb

set -eu

ARCH="${ARCH:-amd64}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)}"
# Debian Version field must start with a digit. If git describe gave us
# a bare commit hash (no tags yet), prefix with 0.0.0+.
case "$VERSION" in
    [0-9]*) : ;;
    *) VERSION="0.0.0+$(echo "$VERSION" | tr -c 'A-Za-z0-9.~' '.' | sed 's/[.]*$//')" ;;
esac
REPO_ROOT="$(cd "$(dirname "$0")"/../.. && pwd)"
cd "$REPO_ROOT"

case "$ARCH" in
    amd64) GOOS_BIN=tarpit-honeypot-linux-amd64 ;;
    arm64) GOOS_BIN=tarpit-honeypot-linux-arm64 ;;
    armhf) GOOS_BIN=tarpit-honeypot-linux-armv7 ;;
    *)     echo "unsupported ARCH: $ARCH" >&2; exit 1 ;;
esac

if [ -z "${BIN:-}" ]; then
    [ -f "dist/$GOOS_BIN" ] || make cross
    BIN="dist/$GOOS_BIN"
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# File layout under the staging dir.
install -d -m 0755 \
    "$STAGE/usr/local/bin" \
    "$STAGE/etc/tarpit-honeypot" \
    "$STAGE/etc/tarpit-honeypot/conf.d" \
    "$STAGE/var/lib/tarpit-honeypot" \
    "$STAGE/lib/systemd/system" \
    "$STAGE/usr/share/doc/tarpit-honeypot" \
    "$STAGE/usr/share/bash-completion/completions" \
    "$STAGE/usr/share/zsh/site-functions" \
    "$STAGE/usr/share/fish/vendor_completions.d" \
    "$STAGE/DEBIAN"

install -m 0755 "$BIN"                                              "$STAGE/usr/local/bin/tarpit-honeypot"
install -m 0640 "$REPO_ROOT/configs/tarpit-honeypot.example.yaml"   "$STAGE/etc/tarpit-honeypot/config.yaml"
install -m 0644 "$REPO_ROOT/packaging/systemd/tarpit-honeypot.service" "$STAGE/lib/systemd/system/"
install -m 0644 "$REPO_ROOT/README.md"      "$STAGE/usr/share/doc/tarpit-honeypot/"
install -m 0644 "$REPO_ROOT/CHANGELOG.md"   "$STAGE/usr/share/doc/tarpit-honeypot/"
install -m 0644 "$REPO_ROOT/LICENSE"        "$STAGE/usr/share/doc/tarpit-honeypot/copyright"

# Generate shell completions from the built binary so they always match
# the subcommand set we ship.
"$BIN" completion bash > "$STAGE/usr/share/bash-completion/completions/tarpit-honeypot"
"$BIN" completion zsh  > "$STAGE/usr/share/zsh/site-functions/_tarpit-honeypot"
"$BIN" completion fish > "$STAGE/usr/share/fish/vendor_completions.d/tarpit-honeypot.fish"

# DEBIAN/control
cat >"$STAGE/DEBIAN/control" <<EOF
Package: tarpit-honeypot
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Depends: systemd
Maintainer: tarpit-honeypot <noreply@example.com>
Homepage: https://github.com/rom/tarpit-honeypot
Description: Low-to-medium interaction deception sensor
 Single static Go binary that runs protocol-shaped honeypots,
 file / URL / DNS canary tokens, port-scan / brute-force /
 slow-scan correlation, per-event pcap capture, and SIEM-friendly
 outbound channels (CEF / LEEF / OCSF / JSON / MQTT / SMS / SNS).
EOF

# postinst — create the dedicated service account + chown the data dir.
# The account MUST match the shipped systemd unit (User=honey, Group=honeypot)
# or the service won't start.
cat >"$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
getent group honeypot >/dev/null 2>&1 || groupadd --system honeypot
if ! getent passwd honey >/dev/null 2>&1; then
    useradd --system --gid honeypot --no-create-home --shell /usr/sbin/nologin honey
fi
chown -R honey:honeypot /var/lib/tarpit-honeypot || true
chmod 0750 /var/lib/tarpit-honeypot || true
systemctl daemon-reload || true
echo "Edit /etc/tarpit-honeypot/config.yaml, then: systemctl enable --now tarpit-honeypot"
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"

cat >"$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    systemctl stop tarpit-honeypot >/dev/null 2>&1 || true
    systemctl disable tarpit-honeypot >/dev/null 2>&1 || true
fi
EOF
chmod 0755 "$STAGE/DEBIAN/prerm"

cat >"$STAGE/DEBIAN/conffiles" <<EOF
/etc/tarpit-honeypot/config.yaml
EOF

mkdir -p "$REPO_ROOT/dist"
OUT="$REPO_ROOT/dist/tarpit-honeypot_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT"
echo "built: $OUT"
