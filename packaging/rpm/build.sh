#!/bin/sh
# Builds an .rpm of tarpit-honeypot. See packaging/rpm/tarpit-honeypot.spec
# for inputs.

set -eu

ARCH="${ARCH:-amd64}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)}"
REPO_ROOT="$(cd "$(dirname "$0")"/../.. && pwd)"
cd "$REPO_ROOT"

# Strip leading 'v' and replace dashes — RPM versions don't take '-'.
RPMVER="$(echo "$VERSION" | sed -e 's/^v//' -e 's/-/_/g')"

case "$ARCH" in
    amd64) GOOS_BIN=dist/tarpit-honeypot-linux-amd64; RPMARCH=x86_64 ;;
    arm64) GOOS_BIN=dist/tarpit-honeypot-linux-arm64; RPMARCH=aarch64 ;;
    *)     echo "unsupported ARCH: $ARCH" >&2; exit 1 ;;
esac

[ -f "$GOOS_BIN" ] || make cross

TOPDIR="$REPO_ROOT/dist/rpmbuild"
mkdir -p "$TOPDIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,BUILDROOT}

rpmbuild \
    --define "_topdir $TOPDIR" \
    --define "version $RPMVER" \
    --define "src_root $REPO_ROOT" \
    --define "bin_path $GOOS_BIN" \
    --target "$RPMARCH" \
    -bb packaging/rpm/tarpit-honeypot.spec

find "$TOPDIR/RPMS" -name '*.rpm' -print
