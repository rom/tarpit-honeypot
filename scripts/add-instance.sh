#!/usr/bin/env bash
#
# add-instance.sh — provision one additional honeypot instance servicing a
# specific server IP, with its OWN config, database, certificates and UI.
#
# Run scripts/install.sh ONCE first (it installs the binary, the service
# account, the SELinux/AppArmor policy, the rsyslog routing and the
# tarpit-honeypot@.service template). Then add one instance per server IP:
#
#   sudo scripts/add-instance.sh --name web1 --listen-ip 192.0.2.10
#   sudo scripts/add-instance.sh --name web2 --listen-ip 192.0.2.11 --ui-port 8090
#
# Each instance is fully isolated:
#   config : /etc/tarpit-honeypot/instances/<name>.yaml
#   state  : /var/lib/tarpit-honeypot/<name>   (events.db, .deployment-id, tls/, captures/)
#   unit   : tarpit-honeypot@<name>            (own deployment identity → own certs)
#   UI     : 127.0.0.1:<ui-port>               (auto-assigned unless --ui-port)
#
# Options:
#   --name NAME         instance id (systemd: tarpit-honeypot@NAME). Default:
#                       the --listen-ip with dots/colons turned into dashes.
#   --listen-ip IP      server IP this instance services (sensor.listen_addresses).
#   --ui-port N         loopback UI port. Default: first free from 8089 up.
#   -c, --config FILE   base config to derive from. Default: the installed
#                       /etc/tarpit-honeypot/config.yaml, else the CENTOS example.
#   --hostname NAME     sensor.name for this instance (default: NAME).
#   --domain NAME       sensor.domain (default: inherited from the base config).
#   --tls-domain NAME   sensor.tls_domain (default: <hostname>.<domain>).
#   --tls-org NAME      sensor.tls_org.
#   --user / --group    service account (default: honey / honeypot).
#   --data-root DIR     parent of per-instance data dirs (default: /var/lib/tarpit-honeypot).
#   --etc DIR           config root (default: /etc/tarpit-honeypot).
#   --force             overwrite an existing instance config.
#   --no-start          create + enable but do not start the instance now.
#   -h, --help          this help.

set -euo pipefail

NAME=""; LISTEN_IP=""; UI_PORT=""; BASE_CONFIG=""
DEPLOY_HOST=""; DEPLOY_DOMAIN=""; TLS_DOMAIN="${TLS_DOMAIN:-}"; TLS_ORG="${TLS_ORG:-}"
SVC_USER="honey"; SVC_GROUP="honeypot"
DATA_ROOT="/var/lib/tarpit-honeypot"; ETC="/etc/tarpit-honeypot"
FORCE=0; DO_START=1
REPO="$(cd "$(dirname "$0")/.." && pwd)"

info() { printf '\033[1;32m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
	--name) NAME="$2"; shift 2 ;;
	--listen-ip) LISTEN_IP="$2"; shift 2 ;;
	--ui-port) UI_PORT="$2"; shift 2 ;;
	-c | --config) BASE_CONFIG="$2"; shift 2 ;;
	--hostname) DEPLOY_HOST="$2"; shift 2 ;;
	--domain) DEPLOY_DOMAIN="$2"; shift 2 ;;
	--tls-domain) TLS_DOMAIN="$2"; shift 2 ;;
	--tls-org) TLS_ORG="$2"; shift 2 ;;
	--user) SVC_USER="$2"; shift 2 ;;
	--group) SVC_GROUP="$2"; shift 2 ;;
	--data-root) DATA_ROOT="$2"; shift 2 ;;
	--etc) ETC="$2"; shift 2 ;;
	--force) FORCE=1; shift ;;
	--no-start) DO_START=0; shift ;;
	-h | --help) sed -n '2,35p' "$0"; exit 0 ;;
	*) die "unknown option: $1" ;;
	esac
done

[ "$(id -u)" = 0 ] || die "must run as root (sudo $0 ...)"
[ -n "$LISTEN_IP" ] || die "--listen-ip is required (the server IP this instance services)"

# Default the instance name to a filesystem/systemd-safe form of the IP.
if [ -z "$NAME" ]; then
	NAME="$(printf '%s' "$LISTEN_IP" | tr ':.' '--')"
fi
case "$NAME" in
	*[!A-Za-z0-9_-]*) die "--name '$NAME' has invalid characters (use A-Za-z0-9_-)" ;;
esac

# Base config: prefer the already-installed one, else the CENTOS example.
if [ -z "$BASE_CONFIG" ]; then
	if [ -f "$ETC/config.yaml" ]; then BASE_CONFIG="$ETC/config.yaml"
	else BASE_CONFIG="$REPO/configs/tarpit-honeypot.example-CENTOS-SERVER.yaml"; fi
fi
[ -f "$BASE_CONFIG" ] || die "base config not found: $BASE_CONFIG"

DEPLOY_HOST="${DEPLOY_HOST:-$NAME}"
DATA="$DATA_ROOT/$NAME"
INST_DIR="$ETC/instances"
CONFIG="$INST_DIR/$NAME.yaml"
BIN="$(command -v tarpit-honeypot || echo /usr/local/bin/tarpit-honeypot)"

# Auto-assign a free loopback UI port (8089+) not already used by an instance.
if [ -z "$UI_PORT" ]; then
	UI_PORT=8089
	if [ -d "$INST_DIR" ]; then
		used="$(grep -rhoE 'bind:[[:space:]]*127\.0\.0\.1:[0-9]+' "$INST_DIR" 2>/dev/null | grep -oE '[0-9]+$' || true)"
		while printf '%s\n' "$used" | grep -qx "$UI_PORT"; do UI_PORT=$((UI_PORT + 1)); done
	fi
fi

# set_block_key FILE BLOCK KEY VALUE — set (or insert) a 2-space-indented scalar
# inside the named top-level YAML block ONLY, so keys of the same name nested in
# other blocks (e.g. a listener's bind:) are never touched. VALUE is written
# verbatim, so the caller quotes scalars and formats flow lists as needed.
set_block_key() {
	local f="$1" block="$2" key="$3" val="$4"
	awk -v block="$block" -v key="$key" -v val="$val" '
		BEGIN { inblk = 0; done = 0 }
		/^[^[:space:]#]/ {
			# A new top-level key. If we were in our block and never found the
			# key, insert it before leaving.
			if (inblk && !done) { print "  " key ": " val; done = 1 }
			inblk = ($0 ~ ("^" block ":")) ? 1 : 0
		}
		{
			if (inblk && !done && $0 ~ ("^[[:space:]]+" key ":")) {
				print "  " key ": " val; done = 1; next
			}
			print
		}
		END { if (inblk && !done) print "  " key ": " val }
	' "$f" >"$f.tmp" && mv "$f.tmp" "$f"
}

info "Instance '$NAME' -> IP $LISTEN_IP, UI 127.0.0.1:$UI_PORT, data $DATA"

# Directories. Instance data lives UNDER the labeled /var/lib/tarpit-honeypot
# tree so the SELinux fcontext applies recursively.
install -d -o root        -g "$SVC_GROUP" -m 0750 "$INST_DIR"
install -d -o "$SVC_USER" -g "$SVC_GROUP" -m 0750 "$DATA"

if [ -f "$CONFIG" ] && [ "$FORCE" != 1 ]; then
	die "instance config already exists: $CONFIG (use --force to overwrite)"
fi
install -o root -g "$SVC_GROUP" -m 0640 "$BASE_CONFIG" "$CONFIG"

# Patch the per-instance config.
set_block_key "$CONFIG" sensor data_dir "\"$DATA\""
set_block_key "$CONFIG" sensor listen_addresses "[\"$LISTEN_IP\"]"
set_block_key "$CONFIG" sensor name "\"$DEPLOY_HOST\""
[ -n "$DEPLOY_DOMAIN" ] && set_block_key "$CONFIG" sensor domain "\"$DEPLOY_DOMAIN\""
[ -z "$TLS_DOMAIN" ] && [ -n "$DEPLOY_DOMAIN" ] && TLS_DOMAIN="$DEPLOY_HOST.$DEPLOY_DOMAIN"
[ -n "$TLS_DOMAIN" ] && set_block_key "$CONFIG" sensor tls_domain "\"$TLS_DOMAIN\""
[ -n "$TLS_ORG" ] && set_block_key "$CONFIG" sensor tls_org "\"$TLS_ORG\""
set_block_key "$CONFIG" ui bind "127.0.0.1:$UI_PORT"

# SELinux: the new dir + config inherit their parents' labels; relabel to be sure.
if command -v restorecon >/dev/null 2>&1; then
	restorecon -RF "$DATA" "$CONFIG" 2>/dev/null || true
fi

if "$BIN" validate-config -c "$CONFIG" >/dev/null 2>&1; then
	info "Config validates: $CONFIG"
else
	warn "config did not validate — check: $BIN validate-config -c $CONFIG"
fi

if command -v systemctl >/dev/null 2>&1; then
	[ -f /etc/systemd/system/tarpit-honeypot@.service ] || \
		warn "tarpit-honeypot@.service template not installed — run scripts/install.sh first"
	systemctl daemon-reload
	if [ "$DO_START" = 1 ]; then
		systemctl enable --now "tarpit-honeypot@$NAME" >/dev/null 2>&1 || \
			warn "could not start tarpit-honeypot@$NAME — check: journalctl -u tarpit-honeypot@$NAME"
		info "Enabled + started tarpit-honeypot@$NAME"
	else
		systemctl enable "tarpit-honeypot@$NAME" >/dev/null 2>&1 || true
		info "Enabled tarpit-honeypot@$NAME (not started; --no-start)"
	fi
else
	warn "no systemd; run manually: $BIN run -c $CONFIG (as $SVC_USER)"
fi

cat <<EOF

$(info "Instance '$NAME' ready.")

  service : tarpit-honeypot@$NAME   (systemctl status tarpit-honeypot@$NAME)
  ip      : $LISTEN_IP   (all listeners bound here via sensor.listen_addresses)
  config  : $CONFIG
  data    : $DATA   (own events.db, .deployment-id, certs)
  ui      : http://127.0.0.1:$UI_PORT
  logs    : journalctl -u tarpit-honeypot@$NAME   (also /var/log/tarpit-honeypot/)

Add another IP:  sudo $0 --name <other> --listen-ip <other-ip>
EOF
