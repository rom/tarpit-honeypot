#!/usr/bin/env bash
#
# install.sh — install tarpit-honeypot as a hardened, sandboxed system service.
#
# It detects your Linux distribution and then:
#   1. creates a dedicated unprivileged service account (honey:honeypot),
#   2. builds (or uses prebuilt) binaries and installs them to /usr/local/bin
#      owned by that account,
#   3. grants the binary exactly the file capabilities it needs
#      (CAP_NET_BIND_SERVICE + CAP_NET_RAW [+ CAP_NET_ADMIN with --tun]) and
#      sets the setuid/setgid bits so manual launches also drop to honey:honeypot
#      (guarded: refuses unless the binary is owned by that unprivileged account),
#   4. lays out + permissions /etc, /var/lib, /var/log, and the enrichment/TLS
#      directories,
#   5. deploys the config with privilege-drop + seccomp + Landlock enabled and
#      the UI pointed at Let's Encrypt TLS paths,
#   6. installs the host LSM policy your distro enforces (SELinux on RHEL-family,
#      AppArmor on Debian-family),
#   7. installs a hardened systemd service (NoNewPrivileges, ProtectSystem=strict,
#      PrivateTmp/Devices, a tight CapabilityBoundingSet, …) plus the enrichment
#      refresh timer.
#
# Run as root on the sensor:
#   sudo scripts/install.sh -c configs/tarpit-honeypot.example-CENTOS-SERVER.yaml
#
# Options:
#   -c, --config FILE   config to deploy (default: the CENTOS-SERVER example)
#       --user NAME     service user  (default: honey)
#       --group NAME    service group (default: honeypot)
#       --prefix DIR    binary dir    (default: /usr/local/bin)
#       --data DIR      data dir      (default: /var/lib/tarpit-honeypot)
#       --hostname NAME this sensor's host label (sensor.name; default: short
#                       hostname). Used by every banner-aware decoy service.
#       --domain NAME   deployment DNS domain for ALL decoy services
#                       (sensor.domain; e.g. corp.example.com) — DNS zone, SMTP
#                       HELO, Kerberos realm, LDAP base, etc.
#       --tls-domain N  TLS cert CN/SAN (sensor.tls_domain; default:
#                       <hostname>.<domain>, so the cert matches the identity)
#       --tls-org NAME  TLS cert organization (sensor.tls_org)
#       --bgp-as N      BGP Autonomous System number the bgp decoy advertises
#                       (sensor.bgp_as). Prompted for when the deployed config
#                       runs the BGP service but no AS is set.
#       --tun           also grant CAP_NET_ADMIN (TUN adapter / nft egress backstop)
#       --force-config  overwrite an existing /etc/tarpit-honeypot/config.yaml
#       --no-build      use prebuilt ./bin/tarpit-honeypot instead of `go build`
#       --no-selinux    skip the SELinux policy module (RHEL-family)
#       --no-apparmor   skip the AppArmor profile (Debian-family)
#       --no-deps       don't try to install missing OS packages
#       --no-relocate-sshd     don't move a host sshd off tcp/22 (default: relocate
#                              the real sshd to tcp/10022 when the decoy wants 22)
#       --ssh-relocate-port N  port to move the host sshd to (default: 10022)
#   -h, --help          this help
#
# Idempotent: safe to re-run to upgrade the binary / refresh the unit.

set -euo pipefail

# ---------------------------------------------------------------------------
SVC_USER="honey"
SVC_GROUP="honeypot"
# NoNewPrivileges in the generated unit. Flipped to "no" by install_selinux when
# the policy lacks init_nnp_daemon_domain, since NoNewPrivileges would otherwise
# block the SELinux domain transition and leave the daemon unconfined.
SVC_NNP="true"
PREFIX="/usr/local/bin"
SHARE="/usr/local/share/tarpit-honeypot"
DATA="/var/lib/tarpit-honeypot"
LOGDIR="/var/log/tarpit-honeypot"
ETC="/etc/tarpit-honeypot"
CONFIG_SRC=""
WITH_TUN=0
FORCE_CONFIG=0
DO_BUILD=1
DO_SELINUX=1
DO_APPARMOR=1
DO_DEPS=1
RELOCATE_SSHD=1
SSH_RELO_PORT=10022
TLS_DOMAIN="${TLS_DOMAIN:-}"
TLS_ORG="${TLS_ORG:-}"
# Deployment identity used by every decoy service (not just TLS). sensor.name +
# sensor.domain; env TARPIT_HOSTNAME / TARPIT_DOMAIN (TARPIT_-prefixed so the
# domain one doesn't collide with the shell's $HOSTNAME).
DEPLOY_HOST="${TARPIT_HOSTNAME:-}"
DEPLOY_DOMAIN="${TARPIT_DOMAIN:-}"
# BGP Autonomous System number (sensor.bgp_as) — only relevant when the deployed
# config runs the `bgp` service. env TARPIT_BGP_AS or --bgp-as; otherwise the
# installer prompts when BGP is configured but the AS is unset.
BGP_AS="${TARPIT_BGP_AS:-}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DEFAULT_CONFIG="$REPO/configs/tarpit-honeypot.example-CENTOS-SERVER.yaml"

while [ $# -gt 0 ]; do
	case "$1" in
	-c | --config) CONFIG_SRC="$2"; shift 2 ;;
	--user) SVC_USER="$2"; shift 2 ;;
	--group) SVC_GROUP="$2"; shift 2 ;;
	--prefix) PREFIX="$2"; shift 2 ;;
	--data) DATA="$2"; shift 2 ;;
	--hostname) DEPLOY_HOST="$2"; shift 2 ;;
	--domain) DEPLOY_DOMAIN="$2"; shift 2 ;;
	--tun) WITH_TUN=1; shift ;;
	--force-config) FORCE_CONFIG=1; shift ;;
	--no-build) DO_BUILD=0; shift ;;
	--no-selinux) DO_SELINUX=0; shift ;;
	--no-apparmor) DO_APPARMOR=0; shift ;;
	--no-deps) DO_DEPS=0; shift ;;
	--no-relocate-sshd) RELOCATE_SSHD=0; shift ;;
	--ssh-relocate-port) SSH_RELO_PORT="$2"; shift 2 ;;
	--tls-domain) TLS_DOMAIN="$2"; shift 2 ;;
	--tls-org) TLS_ORG="$2"; shift 2 ;;
	--bgp-as) BGP_AS="$2"; shift 2 ;;
	-h | --help) sed -n '2,49p' "$0"; exit 0 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
CONFIG_SRC="${CONFIG_SRC:-$DEFAULT_CONFIG}"

info() { printf '\033[1;32m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root (sudo $0)"
[ -f "$CONFIG_SRC" ] || die "config not found: $CONFIG_SRC"

# ---------------------------------------------------------------------------
# 1. Detect the Linux distribution / family.
# ---------------------------------------------------------------------------
DISTRO_ID="unknown"; DISTRO_LIKE=""; FAMILY="unknown"; PKG=""; LSM="none"
detect_distro() {
	if [ -r /etc/os-release ]; then
		# shellcheck disable=SC1091
		. /etc/os-release
		DISTRO_ID="${ID:-unknown}"
		DISTRO_LIKE="${ID_LIKE:-}"
	fi
	case " $DISTRO_ID $DISTRO_LIKE " in
	*" debian "* | *" ubuntu "*) FAMILY="debian" ;;
	*" rhel "* | *" fedora "* | *" centos "*) FAMILY="rhel" ;;
	*" suse "* | *" opensuse "*) FAMILY="suse" ;;
	*" arch "*) FAMILY="arch" ;;
	esac
	# Direct IDs win over ID_LIKE.
	case "$DISTRO_ID" in
	debian | ubuntu | linuxmint | pop | raspbian) FAMILY="debian" ;;
	rhel | centos | almalinux | rocky | fedora | ol | oracle | amzn) FAMILY="rhel" ;;
	sles | opensuse* | suse) FAMILY="suse" ;;
	arch | manjaro) FAMILY="arch" ;;
	esac
	case "$FAMILY" in
	debian) PKG="apt-get"; LSM="apparmor" ;;
	rhel)   PKG="$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)"; LSM="selinux" ;;
	suse)   PKG="zypper"; LSM="apparmor" ;;
	arch)   PKG="pacman"; LSM="none" ;;
	esac
}
detect_distro
info "Distribution: ${DISTRO_ID} (family: ${FAMILY}, pkg: ${PKG:-none}, LSM: ${LSM})"
[ "$FAMILY" = "unknown" ] && warn "unrecognized distro; continuing with best-effort defaults"

# pkg_install <pkg...> — best-effort, never fatal.
pkg_install() {
	[ "$DO_DEPS" = 1 ] || { warn "skipping package install (--no-deps): $*"; return 0; }
	[ -n "$PKG" ] || { warn "no known package manager; install manually: $*"; return 0; }
	info "Installing packages: $*"
	case "$PKG" in
	apt-get) DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1 || warn "apt-get failed for: $*" ;;
	dnf | yum) "$PKG" install -y "$@" >/dev/null 2>&1 || warn "$PKG failed for: $*" ;;
	zypper)  zypper --non-interactive install "$@" >/dev/null 2>&1 || warn "zypper failed for: $*" ;;
	pacman)  pacman -S --noconfirm "$@" >/dev/null 2>&1 || warn "pacman failed for: $*" ;;
	esac
}

# ---------------------------------------------------------------------------
# 2. Ensure setcap is available (libcap).
# ---------------------------------------------------------------------------
if ! command -v setcap >/dev/null 2>&1; then
	case "$FAMILY" in
	debian) pkg_install libcap2-bin ;;
	rhel)   pkg_install libcap ;;
	suse)   pkg_install libcap-progs ;;
	arch)   pkg_install libcap ;;
	esac
fi

# ---------------------------------------------------------------------------
# 3. Service account: group + system user (no login, home = data dir).
# ---------------------------------------------------------------------------
if ! getent group "$SVC_GROUP" >/dev/null; then
	info "Creating group: $SVC_GROUP"
	groupadd --system "$SVC_GROUP"
fi
if ! getent passwd "$SVC_USER" >/dev/null; then
	info "Creating system user: $SVC_USER"
	useradd --system --gid "$SVC_GROUP" --home-dir "$DATA" --no-create-home \
		--shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null ||
		useradd --system --gid "$SVC_GROUP" --home-dir "$DATA" --no-create-home \
			--shell /sbin/nologin "$SVC_USER"
fi

# ---------------------------------------------------------------------------
# 4. Build (or locate) and install the binary, owned by the service account.
# ---------------------------------------------------------------------------
BIN_SRC=""
if [ "$DO_BUILD" = 1 ] && command -v go >/dev/null 2>&1; then
	info "Building tarpit-honeypot (go build)…"
	( cd "$REPO" && CGO_ENABLED=0 go build -trimpath -o "$REPO/bin/tarpit-honeypot" ./cmd/tarpit-honeypot )
	BIN_SRC="$REPO/bin/tarpit-honeypot"
elif [ -x "$REPO/bin/tarpit-honeypot" ]; then
	BIN_SRC="$REPO/bin/tarpit-honeypot"
else
	die "no binary: install Go (to build) or provide a prebuilt ./bin/tarpit-honeypot (and pass --no-build)"
fi

install -d -o root -g "$SVC_GROUP" -m 0755 "$PREFIX"
info "Installing $PREFIX/tarpit-honeypot (owner $SVC_USER:$SVC_GROUP, 0750)"
install -o "$SVC_USER" -g "$SVC_GROUP" -m 0750 "$BIN_SRC" "$PREFIX/tarpit-honeypot"
BIN="$PREFIX/tarpit-honeypot"
# Ship the harness too if it's around (optional).
[ -x "$REPO/bin/tarpit-testharness" ] &&
	install -o "$SVC_USER" -g "$SVC_GROUP" -m 0750 "$REPO/bin/tarpit-testharness" "$PREFIX/tarpit-testharness" || true

# ---------------------------------------------------------------------------
# 5. File capabilities — the only privilege the dropped process keeps.
# ---------------------------------------------------------------------------
CAPS="cap_net_bind_service,cap_net_raw"
[ "$WITH_TUN" = 1 ] && CAPS="$CAPS,cap_net_admin"
if command -v setcap >/dev/null 2>&1; then
	info "Granting file capabilities: ${CAPS}+ep"
	setcap "${CAPS}+ep" "$BIN" || warn "setcap failed (filesystem may be nosuid/overlay); systemd AmbientCapabilities still covers it"
	getcap "$BIN" || true
else
	warn "setcap not available; relying on systemd AmbientCapabilities only"
fi

# ---------------------------------------------------------------------------
# 5b. Pin the runtime identity to the service account (setuid + setgid).
#
# The setuid/setgid bits make a *manual* launch (root, or any admin running the
# binary by hand for a one-off subcommand) drop to honey:honeypot instead of
# inheriting the launcher's identity. Under systemd this is a no-op — the unit's
# NoNewPrivileges=yes tells the kernel to ignore the bits, and User=/Group=
# already pin the identity — so this only closes the manual-launch hole.
#
# This is ONLY safe because a setuid bit runs the binary as its file *owner*: we
# MUST confirm that owner is the unprivileged service account first. A setuid
# bit on a root-owned file is a setuid-root binary (full privilege escalation),
# so we refuse outright unless the on-disk owner/group are exactly the expected
# unprivileged account.
# ---------------------------------------------------------------------------
SVC_UID="$(id -u "$SVC_USER" 2>/dev/null || echo -1)"
# `|| SVC_GID=-1` catches a missing group without tripping set -e/pipefail.
SVC_GID="$(getent group "$SVC_GROUP" 2>/dev/null | cut -d: -f3)" || SVC_GID="-1"
: "${SVC_GID:=-1}"
CUR_UID="$(stat -c '%u' "$BIN")"
CUR_GID="$(stat -c '%g' "$BIN")"
CUR_OWNER="$(stat -c '%U:%G' "$BIN")"

# Never produce a setuid-root (or setuid-to-unknown) binary.
if [ "$SVC_UID" = "0" ] || [ "$SVC_USER" = "root" ]; then
	die "refusing setuid: service user is root — a setuid-root honeypot is a privilege-escalation hole"
fi
if [ "$SVC_UID" = "-1" ] || [ "$SVC_GID" = "-1" ]; then
	die "refusing setuid: cannot resolve ${SVC_USER}:${SVC_GROUP} to a uid/gid"
fi
# The on-disk owner/group must be exactly the unprivileged service account.
if [ "$CUR_UID" != "$SVC_UID" ] || [ "$CUR_GID" != "$SVC_GID" ]; then
	die "refusing setuid/setgid: $BIN is owned by ${CUR_OWNER} (uid:gid ${CUR_UID}:${CUR_GID}), expected ${SVC_USER}:${SVC_GROUP} (${SVC_UID}:${SVC_GID})"
fi

info "Pinning runtime identity: chmod ug+s $BIN (manual launches drop to ${SVC_USER}:${SVC_GROUP})"
chmod ug+s "$BIN"

# Re-read the mode: on a nosuid mount the bits are accepted by chmod but ignored
# at exec, so warn if they didn't stick to the symbolic mode.
MODE_AFTER="$(stat -c '%A' "$BIN")"
case "$MODE_AFTER" in
	???s??s*) : ;;  # -rwsr-sr-x : both setuid (pos 4) and setgid (pos 7) present
	*) warn "setuid/setgid not reflected in mode ($MODE_AFTER) — is $PREFIX a nosuid mount? systemd User=/Group= still applies" ;;
esac

# ---------------------------------------------------------------------------
# 6. Directory layout + permissions.
# ---------------------------------------------------------------------------
info "Creating directories"
install -d -o root        -g "$SVC_GROUP" -m 0750 "$ETC"
install -d -o root        -g "$SVC_GROUP" -m 0750 "$ETC/enrichment" "$ETC/enrichment/geoip" "$ETC/enrichment/threat"
install -d -o "$SVC_USER" -g "$SVC_GROUP" -m 0750 "$ETC/tls"          # sensor-readable cert copies
install -d -o "$SVC_USER" -g "$SVC_GROUP" -m 0750 "$DATA" "$LOGDIR"
install -d -o root        -g "$SVC_GROUP" -m 0755 "$SHARE" "$SHARE/scripts"

# Repair ownership of any PRE-EXISTING contents (e.g. a .deployment-id, events.db
# or pcaps left root-owned by an earlier run made as root). `install -d` only
# sets the directory's own owner, not its contents, so without this the dropped
# honey user hits "permission denied" opening files an earlier root run created.
chown -R "$SVC_USER:$SVC_GROUP" "$DATA" "$LOGDIR" "$ETC/tls" 2>/dev/null || true

# Ship the helper scripts where the systemd units expect them.
for s in fetch-enrichment.sh install-enrichment.sh update-enrichment.sh letsencrypt-cert.sh selinux-verify.sh add-instance.sh; do
	[ -f "$REPO/scripts/$s" ] && install -o root -g "$SVC_GROUP" -m 0755 "$REPO/scripts/$s" "$SHARE/scripts/$s"
done

# ---------------------------------------------------------------------------
# 7. Deploy the config; enable privilege-drop + sandbox + LE TLS paths.
# ---------------------------------------------------------------------------
CONFIG="$ETC/config.yaml"
if [ -f "$CONFIG" ] && [ "$FORCE_CONFIG" != 1 ]; then
	warn "keeping existing $CONFIG (use --force-config to overwrite)"
else
	info "Deploying config -> $CONFIG"
	install -o root -g "$SVC_GROUP" -m 0640 "$CONFIG_SRC" "$CONFIG"
fi

# Ensure the privilege-drop + sandbox keys are present, and — once the Let's
# Encrypt cert exists — point the UI at it. The validator stat()s the cert, so
# we only wire TLS when the files are actually there (re-run install.sh after
# letsencrypt-cert.sh, which also wires it). Idempotent; only touches our keys.
#
# prompt_identity resolves the ONE deployment identity every decoy service uses:
# the host label (sensor.name), the DNS domain (sensor.domain — DNS zone, SMTP
# HELO, Kerberos realm, LDAP base, …), and the TLS cert CN/SAN (sensor.tls_domain).
# Precedence: --hostname/--domain/--tls-domain flags (or TARPIT_HOSTNAME /
# TARPIT_DOMAIN / TLS_DOMAIN env) win; otherwise prompt interactively. The TLS
# name DEFAULTS to <host>.<domain> so the certificate stays coherent with the
# deployment domain instead of drifting to a generic "localhost"/example.internal.
prompt_identity() {
	# Host label (sensor.name).
	if [ -z "$DEPLOY_HOST" ]; then
		local h; h="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo host)"
		if [ -t 0 ]; then
			printf 'Hostname for this sensor (sensor.name) [%s]: ' "$h"
			read -r DEPLOY_HOST || true
		fi
		DEPLOY_HOST="${DEPLOY_HOST:-$h}"
	fi
	# Deployment DNS domain (sensor.domain) — the suffix EVERY decoy advertises.
	if [ -z "$DEPLOY_DOMAIN" ]; then
		local d; d="$(hostname -d 2>/dev/null || true)"; d="${d:-example.internal}"
		if [ -t 0 ]; then
			printf 'Deployment DNS domain for all decoy services (sensor.domain) [%s]: ' "$d"
			read -r DEPLOY_DOMAIN || true
		fi
		DEPLOY_DOMAIN="${DEPLOY_DOMAIN:-$d}"
	fi
	# TLS cert identity — default to <host>.<domain> so it matches the above.
	if [ -z "$TLS_DOMAIN" ]; then
		local fqdn="${DEPLOY_HOST}.${DEPLOY_DOMAIN}"
		if [ -t 0 ]; then
			printf 'TLS certificate domain/name for decoy services [%s]: ' "$fqdn"
			read -r TLS_DOMAIN || true
		fi
		TLS_DOMAIN="${TLS_DOMAIN:-$fqdn}"
	fi
	if [ -z "$TLS_ORG" ] && [ -t 0 ]; then
		printf 'TLS certificate organization (optional, blank to vary per service): '
		read -r TLS_ORG || true
	fi
	info "Deployment identity: host=$DEPLOY_HOST domain=$DEPLOY_DOMAIN tls=$TLS_DOMAIN org=${TLS_ORG:-<per-service>}"
}

# set_sensor_key inserts or replaces a scalar key in the top-level "sensor:"
# block. It deliberately matches only a 2-space-indented key (the sensor block's
# own scalars) and only the FIRST occurrence: other blocks (webapp brand,
# honeynet hosts/networks) carry name:/domain: keys at deeper indentation, and
# rewriting those would corrupt unrelated config.
set_sensor_key() {
	local f="$1" key="$2" val="$3"
	[ -n "$val" ] || return 0
	if grep -qE "^  $key:" "$f"; then
		sed -i -E "0,/^  $key:.*/s||  $key: \"$val\"|" "$f"
	else
		# insert right after the "sensor:" line (2-space indent to match the block)
		sed -i "/^sensor:/a\\  $key: \"$val\"" "$f"
	fi
}

# set_sensor_num_key is set_sensor_key for a numeric scalar — written UNQUOTED
# so YAML parses it as an integer (a quoted "64512" would be a string and fail
# to unmarshal into the uint32 sensor.bgp_as field).
set_sensor_num_key() {
	local f="$1" key="$2" val="$3"
	[ -n "$val" ] || return 0
	if grep -qE "^  $key:" "$f"; then
		sed -i -E "0,/^  $key:.*/s||  $key: $val|" "$f"
	else
		sed -i "/^sensor:/a\\  $key: $val" "$f"
	fi
}

# prompt_bgp_as wires sensor.bgp_as when the deployed config runs the BGP
# service (handler: bgp) but no AS is set. The bgp decoy uses it to answer a
# peer's OPEN with its own OPEN advertising this AS; without it the decoy
# advertises no AS. Value comes from --bgp-as / TARPIT_BGP_AS, else an
# interactive prompt; non-interactive with neither leaves it unset (+ a warning)
# rather than guessing an ASN.
prompt_bgp_as() {
	local f="$1"
	grep -Eq 'handler:[[:space:]]*bgp([,}[:space:]]|$)' "$f" || return 0
	if grep -Eq '^[[:space:]]*bgp_as:[[:space:]]*[0-9]+' "$f"; then
		info "BGP AS already set (sensor.bgp_as) — leaving as-is"
		return 0
	fi
	local as="$BGP_AS"
	if [ -z "$as" ]; then
		if [ -t 0 ]; then
			printf 'This config runs the BGP service (handler: bgp) but sensor.bgp_as is unset.\n'
			printf 'BGP Autonomous System number to advertise (1-4294967295; e.g. 64512, a private ASN) [64512]: '
			read -r as || true
			as="${as:-64512}"
		else
			warn "config runs BGP but sensor.bgp_as is unset and there's no TTY/--bgp-as to prompt; set sensor.bgp_as manually (the decoy won't advertise an AS until then)"
			return 0
		fi
	fi
	if ! printf '%s' "$as" | grep -Eq '^[0-9]+$' || [ "$as" -lt 1 ] || [ "$as" -gt 4294967295 ]; then
		warn "invalid BGP AS '$as' (want 1-4294967295) — leaving sensor.bgp_as unset"
		return 0
	fi
	set_sensor_num_key "$f" "bgp_as" "$as"
	info "Set sensor.bgp_as=$as in $f"
}

patch_config() {
	local f="$1"
	# Keep the config's data_dir in lockstep with --data (and the systemd unit's
	# ReadWritePaths, which is set to $DATA). Without this the daemon writes to
	# whatever path the config shipped with while ProtectSystem=strict leaves
	# only $DATA writable — so SQLite can't create its DB/-wal/-shm and the
	# sensor dies with "unable to open database file (14) ... not writable".
	set_sensor_key "$f" "data_dir" "$DATA"
	# Pin the deployment identity so every banner-aware decoy (DNS / SMTP /
	# Kerberos / LDAP / …) advertises the operator's real host + domain instead
	# of the generic example default, and the TLS cert (tls_domain) matches it.
	set_sensor_key "$f" "name" "$DEPLOY_HOST"
	set_sensor_key "$f" "domain" "$DEPLOY_DOMAIN"
	set_sensor_key "$f" "tls_domain" "$TLS_DOMAIN"
	set_sensor_key "$f" "tls_org" "$TLS_ORG"
	if [ -f "$ETC/tls/cert.pem" ] && [ -f "$ETC/tls/key.pem" ]; then
		info "Pointing UI TLS at $ETC/tls/{cert,key}.pem"
		sed -i \
			-e "s|^\([[:space:]]*\)# *tls_cert:.*|\1tls_cert: $ETC/tls/cert.pem|" \
			-e "s|^\([[:space:]]*\)# *tls_key:.*|\1tls_key:  $ETC/tls/key.pem|" \
			"$f" 2>/dev/null || true
	else
		warn "no TLS cert yet at $ETC/tls/ — run letsencrypt-cert.sh to get one (it wires the config)"
	fi
	grep -q "drop_user:" "$f" || warn "config has no sensor.drop_user — add 'drop_user: $SVC_USER' / 'drop_group: $SVC_GROUP'"
	grep -q "seccomp:" "$f"  || warn "config has no sensor.sandbox.seccomp — add 'sandbox: { seccomp: true, landlock: true }'"
}
prompt_identity
patch_config "$CONFIG"
prompt_bgp_as "$CONFIG"

if "$BIN" validate-config -c "$CONFIG" >/dev/null 2>&1; then
	info "Config validates"
else
	warn "config did not validate — run: $BIN validate-config -c $CONFIG"
fi

# ---------------------------------------------------------------------------
# 8. Host LSM policy (SELinux on RHEL-family, AppArmor on Debian-family).
# ---------------------------------------------------------------------------
install_selinux() {
	[ "$DO_SELINUX" = 1 ] || { info "SELinux module skipped (--no-selinux)"; return 0; }
	command -v getenforce >/dev/null 2>&1 || { warn "SELinux tools absent; skipping module"; return 0; }
	info "SELinux: $(getenforce)"
	if [ -d "$REPO/packaging/selinux" ] && command -v make >/dev/null 2>&1; then
		command -v checkmodule >/dev/null 2>&1 || pkg_install policycoreutils-devel selinux-policy-devel
		# Capture the build/install output so a failure shows the actual compiler
		# error (a missing perm/interface on an older selinux-policy is the usual
		# cause) instead of a generic "build failed" with the reason swallowed.
		local sel_log; sel_log="$(mktemp /tmp/tarpit-selinux.XXXXXX.log)"
		if ( cd "$REPO/packaging/selinux" && make && make install ) >"$sel_log" 2>&1; then
			info "SELinux policy module installed (tarpit_honeypot)"
			rm -f "$sel_log"
		else
			warn "SELinux module build failed — compiler output below (also at $sel_log):"
			sed 's/^/    /' "$sel_log" >&2
			warn "Fix: install policycoreutils-devel + selinux-policy-devel and re-run, or run with --no-selinux."
		fi
	fi
	# NoNewPrivileges=yes BLOCKS the SELinux domain transition unless the policy
	# grants process2:nnp_transition (the init_nnp_daemon_domain interface). If
	# this selinux-policy predates that interface, keeping NoNewPrivileges would
	# leave the daemon unconfined — so disable it in the unit (SELinux confinement
	# is the stronger control for an internet-facing honeypot).
	if ! grep -rqs 'init_nnp_daemon_domain' /usr/share/selinux/devel/include/ 2>/dev/null; then
		warn "selinux-policy lacks init_nnp_daemon_domain — setting NoNewPrivileges=no in the unit so the SELinux domain transition applies."
		SVC_NNP="no"
	fi
	# Label the binary + data so the domain transition / file access apply.
	# The policy module's own .fc already maps $BIN to tarpit_honeypot_exec_t —
	# do NOT add a local 'bin_t' fcontext for it. A local semanage entry outranks
	# the module's .fc, so labeling the binary bin_t would suppress the
	# init_t->tarpit_honeypot_t domain transition and leave the daemon running
	# unconfined (unconfined_service_t). Drop any stale bin_t override a previous
	# install may have left behind, then let restorecon apply the module label.
	if command -v semanage >/dev/null 2>&1; then
		semanage fcontext -d "$BIN" 2>/dev/null || true
		# A custom --data dir isn't covered by the policy module's .fc (which maps
		# only the default /var/lib/tarpit-honeypot to tarpit_honeypot_var_lib_t).
		# Add a file-context equivalence so $DATA inherits the same labels, or the
		# confined domain can't write there (CANTOPEN / "permission denied").
		if [ "$DATA" != "/var/lib/tarpit-honeypot" ]; then
			semanage fcontext -a -e /var/lib/tarpit-honeypot "$DATA" 2>/dev/null ||
				semanage fcontext -m -e /var/lib/tarpit-honeypot "$DATA" 2>/dev/null || true
		fi
	fi
	if command -v restorecon >/dev/null 2>&1; then
		# Recurse (-R) so pre-existing files inside the data/etc/log dirs get the
		# tarpit_honeypot_*_t labels too — otherwise the now-confined domain is
		# denied (EACCES "permission denied") writing e.g. .deployment-id.
		restorecon -F "$BIN" 2>/dev/null || true
		restorecon -RF "$DATA" "$ETC" "$LOGDIR" 2>/dev/null || true
	fi
	# Verify the exec label actually took — a wrong/missing label is exactly what
	# leaves the service unconfined, so surface it loudly instead of silently.
	# stat -c '%C' prints just the context (e.g. system_u:object_r:<type>:s0).
	if ctx="$(stat -c '%C' "$BIN" 2>/dev/null)"; then
		case "$ctx" in
			*:tarpit_honeypot_exec_t:*)
				info "SELinux: $BIN labeled tarpit_honeypot_exec_t (domain transition will apply)" ;;
			*)
				warn "SELinux: $BIN is labeled '${ctx:-unknown}', not tarpit_honeypot_exec_t — the daemon will run UNCONFINED."
				warn "  Fix: ensure the module installed (semodule -l | grep tarpit_honeypot), then:"
				warn "       semanage fcontext -d '$BIN' 2>/dev/null; restorecon -Fv '$BIN'"
				warn "  Re-check with: ps -eZ | grep tarpit-honeypot  (want tarpit_honeypot_t, not unconfined_service_t)" ;;
		esac
	fi
}
install_apparmor() {
	[ "$DO_APPARMOR" = 1 ] || { info "AppArmor profile skipped (--no-apparmor)"; return 0; }
	command -v apparmor_parser >/dev/null 2>&1 || { warn "AppArmor absent; skipping profile"; return 0; }
	local prof="$REPO/packaging/apparmor/usr.local.bin.tarpit-honeypot"
	[ -f "$prof" ] || { warn "AppArmor profile not found in repo; skipping"; return 0; }
	info "Installing AppArmor profile (complain mode — switch to enforce after observing)"
	install -o root -g root -m 0644 "$prof" /etc/apparmor.d/usr.local.bin.tarpit-honeypot
	apparmor_parser -r -W /etc/apparmor.d/usr.local.bin.tarpit-honeypot 2>/dev/null || warn "apparmor_parser failed"
	command -v aa-complain >/dev/null 2>&1 && aa-complain "$BIN" 2>/dev/null || true
	info "  enforce later with: aa-enforce $BIN"
}
case "$LSM" in
selinux)  install_selinux ;;
apparmor) install_apparmor ;;
*)        warn "no host LSM detected; relying on seccomp + Landlock + systemd sandboxing" ;;
esac

# ---------------------------------------------------------------------------
# 8.5 Relocate the host's real sshd off tcp/22 so the SSH decoy can own it.
# Only acts when the deployed config binds tcp/22 AND a system sshd is there.
# The admin's CURRENT session survives; new real-SSH connections move to 10022.
# ---------------------------------------------------------------------------
relocate_sshd() {
	[ "$RELOCATE_SSHD" = 1 ] || { info "SSH relocation skipped (--no-relocate-sshd)"; return 0; }
	# Does the honeypot config actually want tcp/22?
	if ! grep -qE 'bind:[^#]*:22([^0-9]|$)' "$CONFIG_SRC" && ! grep -qE 'port:[[:space:]]*22([^0-9]|$)' "$CONFIG_SRC"; then
		info "Config does not bind tcp/22 — leaving the host sshd in place."
		return 0
	fi
	# Is something already listening on tcp/22 (the host sshd, not us)?
	local on22=0
	if command -v ss >/dev/null 2>&1; then
		ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -qE '[:.]22$' && on22=1
	elif command -v netstat >/dev/null 2>&1; then
		netstat -ltn 2>/dev/null | awk '{print $4}' | grep -qE '[:.]22$' && on22=1
	fi
	if [ "$on22" = 0 ]; then
		info "Nothing on tcp/22 — the SSH decoy can bind it directly."
		return 0
	fi

	warn "================== SSH RELOCATION =================="
	warn "A system SSH daemon is on tcp/22, which the honeypot decoy needs."
	warn "Moving the real sshd to tcp/${SSH_RELO_PORT} so the decoy can own tcp/22."
	warn "(Re-run with --no-relocate-sshd to skip this.)"

	# 1. Tell sshd to listen on the new port. Prefer a drop-in; otherwise edit
	#    sshd_config, commenting any literal 'Port 22'.
	if [ -d /etc/ssh/sshd_config.d ] && grep -qsE '^[Ii]nclude[[:space:]]+/etc/ssh/sshd_config.d/' /etc/ssh/sshd_config; then
		printf '# Set by the tarpit-honeypot installer: the decoy owns tcp/22.\nPort %s\n' "$SSH_RELO_PORT" \
			> /etc/ssh/sshd_config.d/00-tarpit-relocate.conf
		info "Wrote /etc/ssh/sshd_config.d/00-tarpit-relocate.conf (Port ${SSH_RELO_PORT})"
	else
		sed -i 's/^[[:space:]]*Port[[:space:]]\{1,\}22[[:space:]]*$/# &  (moved by tarpit-honeypot)/' /etc/ssh/sshd_config 2>/dev/null || true
		printf '\n# Set by the tarpit-honeypot installer: the decoy owns tcp/22.\nPort %s\n' "$SSH_RELO_PORT" \
			>> /etc/ssh/sshd_config
		info "Set Port ${SSH_RELO_PORT} in /etc/ssh/sshd_config"
	fi

	# 2. SELinux: label the new port so sshd is allowed to bind it.
	if command -v semanage >/dev/null 2>&1; then
		if semanage port -a -t ssh_port_t -p tcp "$SSH_RELO_PORT" 2>/dev/null ||
			semanage port -m -t ssh_port_t -p tcp "$SSH_RELO_PORT" 2>/dev/null; then
			info "SELinux: tcp/${SSH_RELO_PORT} labeled ssh_port_t"
		else
			warn "SELinux: could not label tcp/${SSH_RELO_PORT}; run: semanage port -a -t ssh_port_t -p tcp ${SSH_RELO_PORT}"
		fi
	fi

	# 3. Firewall: open the new SSH port (best-effort).
	if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
		firewall-cmd --permanent --add-port="${SSH_RELO_PORT}/tcp" >/dev/null 2>&1 || true
		firewall-cmd --reload >/dev/null 2>&1 || true
		info "firewalld: opened ${SSH_RELO_PORT}/tcp"
	elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
		ufw allow "${SSH_RELO_PORT}/tcp" >/dev/null 2>&1 || true
		info "ufw: allowed ${SSH_RELO_PORT}/tcp"
	fi

	# 4. Validate the config before touching the running daemon.
	if command -v sshd >/dev/null 2>&1 && ! sshd -t 2>/dev/null; then
		warn "sshd -t reported a config error — NOT restarting sshd. Fix /etc/ssh and"
		warn "restart it yourself; until then the decoy must not bind tcp/22."
		return 0
	fi

	# 5. Apply. Handle socket-activated SSH (newer Ubuntu) where the listen port
	#    lives in ssh.socket, not sshd_config.
	if command -v systemctl >/dev/null 2>&1; then
		if systemctl is-active --quiet ssh.socket 2>/dev/null; then
			mkdir -p /etc/systemd/system/ssh.socket.d
			printf '[Socket]\nListenStream=\nListenStream=%s\n' "$SSH_RELO_PORT" \
				> /etc/systemd/system/ssh.socket.d/00-tarpit-relocate.conf
			systemctl daemon-reload
			systemctl restart ssh.socket 2>/dev/null || warn "could not restart ssh.socket"
			info "ssh.socket now listens on tcp/${SSH_RELO_PORT}"
		fi
		local unit=""
		for u in sshd ssh; do
			systemctl list-unit-files 2>/dev/null | grep -q "^${u}\.service" && { unit="$u"; break; }
		done
		if [ -n "$unit" ]; then
			systemctl restart "${unit}" 2>/dev/null || warn "could not restart ${unit}; restart it manually"
			info "Restarted ${unit}; real SSH is now on tcp/${SSH_RELO_PORT}"
		else
			warn "No ssh systemd unit found; restart sshd manually for Port ${SSH_RELO_PORT} to take effect."
		fi
	else
		warn "No systemd; restart sshd manually so Port ${SSH_RELO_PORT} takes effect."
	fi

	warn "---------------------------------------------------"
	warn "ACTION REQUIRED — reconnect to THIS host's real SSH on the new port:"
	warn "    ssh -p ${SSH_RELO_PORT} <user>@<this-host>"
	warn "  Make it permanent in your ~/.ssh/config on the CLIENT:"
	warn "      Host <this-host-or-alias>"
	warn "          HostName <this-host>"
	warn "          Port ${SSH_RELO_PORT}"
	warn "  Then: ssh <this-host-or-alias>   (no -p needed)"
	warn "  scp/sftp likewise: scp -P ${SSH_RELO_PORT} file <user>@<host>:  /  sftp -P ${SSH_RELO_PORT} <user>@<host>"
	warn "  Your CURRENT session stays up; new tcp/22 connections now hit the DECOY."
	warn "==================================================="
}
relocate_sshd

# ---------------------------------------------------------------------------
# 9. systemd: hardened service + enrichment/cert timers.
# ---------------------------------------------------------------------------
install_systemd() {
	command -v systemctl >/dev/null 2>&1 || { warn "no systemd; start manually: $BIN run -c $CONFIG (as $SVC_USER)"; return 0; }
	local amb="CAP_NET_BIND_SERVICE CAP_NET_RAW"
	[ "$WITH_TUN" = 1 ] && amb="$amb CAP_NET_ADMIN"
	info "Installing systemd unit -> /etc/systemd/system/tarpit-honeypot.service"
	cat >/etc/systemd/system/tarpit-honeypot.service <<EOF
[Unit]
Description=tarpit-honeypot deception sensor
Documentation=https://github.com/rom/tarpit-honeypot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_GROUP
ExecStart=$BIN run -c $CONFIG
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s

# Tag stderr (slog startup/warning output) so the rsyslog drop-in can route the
# sensor's logs into $LOGDIR instead of /var/log/messages.
SyslogIdentifier=tarpit-honeypot

# Capabilities the sensor keeps after privilege drop.
AmbientCapabilities=$amb
CapabilityBoundingSet=$amb
NoNewPrivileges=$SVC_NNP

# Pin the SELinux domain. NoNewPrivileges=yes blocks the automatic
# init_t->tarpit_honeypot_t transition, so without this (+ the policy's
# init_nnp_daemon_domain grant) the daemon would run unconfined. The leading
# '-' makes it non-fatal when SELinux is off or the module isn't installed.
SELinuxContext=-system_u:system_r:tarpit_honeypot_t:s0

# Hardening (complements the in-process seccomp + Landlock).
ProtectSystem=strict
ReadWritePaths=$DATA $LOGDIR
ReadOnlyPaths=$ETC
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictNamespaces=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET AF_NETLINK
MemoryDenyWriteExecute=true
LockPersonality=true
SystemCallArchitectures=native
# NB: no SystemCallFilter allowlist here — the sensor's in-process seccomp
# DENYLIST (sensor.sandbox.seccomp) blocks the dangerous syscalls precisely,
# without risk of an allowlist blocking the in-process Landlock syscalls.

[Install]
WantedBy=multi-user.target
EOF
	# Template unit for the multi-instance model (one honeypot per server IP,
	# each its own config/DB/certs/UI). Not enabled here — provision instances
	# with scripts/add-instance.sh, which enables tarpit-honeypot@<name>.
	info "Installing systemd template unit -> /etc/systemd/system/tarpit-honeypot@.service"
	cat >/etc/systemd/system/tarpit-honeypot@.service <<EOF
[Unit]
Description=tarpit-honeypot deception sensor (instance %i)
Documentation=https://github.com/rom/tarpit-honeypot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_GROUP
ExecStart=$BIN run -c $ETC/instances/%i.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s

# Per-instance syslog identity; the rsyslog drop-in routes every tarpit-honeypot*
# tag to $LOGDIR.
SyslogIdentifier=tarpit-honeypot@%i

AmbientCapabilities=$amb
CapabilityBoundingSet=$amb
NoNewPrivileges=$SVC_NNP
SELinuxContext=-system_u:system_r:tarpit_honeypot_t:s0

ProtectSystem=strict
ReadWritePaths=$DATA/%i $LOGDIR
ReadOnlyPaths=$ETC
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictNamespaces=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET AF_NETLINK
MemoryDenyWriteExecute=true
LockPersonality=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
	# Maintenance timers (paths resolve against $SHARE/scripts).
	for u in tarpit-enrichment.service tarpit-enrichment.timer tarpit-cert-renew.service tarpit-cert-renew.timer; do
		[ -f "$REPO/packaging/systemd/$u" ] && install -o root -g root -m 0644 "$REPO/packaging/systemd/$u" "/etc/systemd/system/$u"
	done
	systemctl daemon-reload
	systemctl enable tarpit-honeypot.service >/dev/null 2>&1 || true
	systemctl enable --now tarpit-enrichment.timer >/dev/null 2>&1 || true
	info "Enabled tarpit-honeypot.service + tarpit-enrichment.timer"
}
install_systemd

# ---------------------------------------------------------------------------
# 10. Local syslog routing: keep the sensor's own logs out of /var/log/messages.
#
# The sensor emits two streams under the syslog identity "tarpit-honeypot": its
# operational logs (startup/warnings — slog -> stderr -> journald, tagged by the
# unit's SyslogIdentifier) and the CEF event stream (the `syslog` channel, same
# tag). Both otherwise land in /var/log/messages. An rsyslog drop-in matches
# that program name, writes a dedicated file under $LOGDIR, and stops further
# processing so the lines don't also hit /var/log/messages. A logrotate policy
# keeps that file bounded.
# ---------------------------------------------------------------------------
install_syslog_routing() {
	local logfile="$LOGDIR/tarpit-honeypot.log"
	# rsyslog writes the file: as root on RHEL/SUSE/Arch (no priv drop) it can
	# write the honey-owned $LOGDIR directly; on Debian/Ubuntu it drops to the
	# 'syslog' user, so pre-create the file owned by that writer and grant it
	# access to the dir (which stays honey:honeypot 0750 for the sensor's own
	# artifacts) via an ACL, falling back to a group membership.
	local rsuser="root" rsgroup="$SVC_GROUP"
	if getent passwd syslog >/dev/null 2>&1; then
		rsuser="syslog"
		getent group adm >/dev/null 2>&1 && rsgroup="adm"
	fi
	install -o "$rsuser" -g "$rsgroup" -m 0640 /dev/null "$logfile" 2>/dev/null \
		|| { : >"$logfile" 2>/dev/null && chmod 0640 "$logfile" 2>/dev/null; } || true
	if [ "$rsuser" = "syslog" ]; then
		if command -v setfacl >/dev/null 2>&1; then
			setfacl -m u:syslog:rwx "$LOGDIR" 2>/dev/null || true
			setfacl -m u:syslog:rw "$logfile" 2>/dev/null || true
		else
			usermod -aG "$SVC_GROUP" syslog 2>/dev/null && chmod 0770 "$LOGDIR" 2>/dev/null || true
		fi
	fi
	# SELinux: the file inherits the dir's tarpit_honeypot_log_t label; the policy
	# module (section 8) grants syslogd_t management of that type. Relabel so a
	# fresh file definitely carries it.
	command -v restorecon >/dev/null 2>&1 && restorecon -F "$logfile" 2>/dev/null || true

	local conf_src="$REPO/packaging/rsyslog/30-tarpit-honeypot.conf"
	if [ -d /etc/rsyslog.d ] && [ -f "$conf_src" ]; then
		info "Installing rsyslog drop-in -> /etc/rsyslog.d/30-tarpit-honeypot.conf"
		install -o root -g root -m 0644 "$conf_src" /etc/rsyslog.d/30-tarpit-honeypot.conf
		if command -v systemctl >/dev/null 2>&1; then
			systemctl restart rsyslog >/dev/null 2>&1 ||
				systemctl restart syslog >/dev/null 2>&1 ||
				warn "could not restart rsyslog; reload it for the drop-in to take effect"
		fi
		info "Sensor logs route to $logfile (kept out of /var/log/messages)"
	else
		warn "rsyslog not detected (no /etc/rsyslog.d) — sensor logs stay in the journal: journalctl -u tarpit-honeypot"
	fi

	local lr_src="$REPO/packaging/logrotate/tarpit-honeypot"
	if [ -d /etc/logrotate.d ] && [ -f "$lr_src" ]; then
		info "Installing logrotate policy -> /etc/logrotate.d/tarpit-honeypot"
		install -o root -g root -m 0644 "$lr_src" /etc/logrotate.d/tarpit-honeypot
	fi
}
install_syslog_routing

# ---------------------------------------------------------------------------
# 11. Confirm the data dir is consistent end-to-end (config data_dir == --data,
# and — under SELinux — the dir carries the tarpit_honeypot_var_lib_t label the
# confined domain needs to write it). A mismatch here is exactly what makes the
# sensor die with "unable to open database file (14) ... not writable", so make
# it obvious at install time instead of in the journal after a failed start.
# ---------------------------------------------------------------------------
verify_data_dir() {
	local cfg_data
	cfg_data="$(sed -nE 's/^[[:space:]]*data_dir:[[:space:]]*"?([^"#]*)"?[[:space:]]*$/\1/p' "$CONFIG" 2>/dev/null | head -1)"
	cfg_data="${cfg_data%"${cfg_data##*[![:space:]]}"}" # rtrim
	if [ "$cfg_data" = "$DATA" ]; then
		info "data_dir: $DATA (config matches the systemd ReadWritePaths)"
	else
		warn "data_dir MISMATCH: config has '${cfg_data:-<unset>}' but the unit only makes '$DATA' writable — the sensor will fail to open its DB. Re-run with -c on that config, or set 'data_dir: $DATA'."
	fi
	# SELinux label check (only meaningful when enforcing + tools present).
	if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" != "Disabled" ] && command -v stat >/dev/null 2>&1; then
		local ctx; ctx="$(stat -c '%C' "$DATA" 2>/dev/null)"
		case "$ctx" in
			*:tarpit_honeypot_var_lib_t:*) info "data_dir SELinux label: tarpit_honeypot_var_lib_t (OK)" ;;
			"") : ;; # no context (SELinux off for this fs); nothing to assert
			*) warn "data_dir SELinux label is '${ctx}', not tarpit_honeypot_var_lib_t — the confined domain can't write it. Fix: semanage fcontext -a -e /var/lib/tarpit-honeypot '$DATA'; restorecon -RFv '$DATA'" ;;
		esac
	fi
}
verify_data_dir

# ---------------------------------------------------------------------------
# Done.
# ---------------------------------------------------------------------------
cat <<EOF

$(info "Install complete.")

  binary   : $BIN  ($(getcap "$BIN" 2>/dev/null || echo 'no file caps'))
  user     : $SVC_USER:$SVC_GROUP
  identity : host=$DEPLOY_HOST domain=$DEPLOY_DOMAIN  (TLS cert: $TLS_DOMAIN)
  config   : $CONFIG
  data     : $DATA
  logs     : $LOGDIR/tarpit-honeypot.log  (sensor logs + events; kept out of /var/log/messages)
  scripts  : $SHARE/scripts

Next steps:
  1. Get a real TLS cert for the web UI (asks for domain + hostname):
       sudo $SHARE/scripts/letsencrypt-cert.sh
  2. Pull the enrichment data now (then the daily timer keeps it fresh):
       sudo $SHARE/scripts/update-enrichment.sh
  3. Start the sensor:
       sudo systemctl start tarpit-honeypot
       systemctl status tarpit-honeypot ; journalctl -u tarpit-honeypot -f
  4. Confirm SELinux confinement (diagnoses + fixes "running uncontained"):
       sudo $SHARE/scripts/selinux-verify.sh

Hardening in effect: privilege drop ($SVC_USER), file caps ${CAPS}, in-process
seccomp + Landlock (config), host LSM ($LSM), and systemd confinement.

If this installer relocated your real sshd, reconnect on the new port:
       ssh -p ${SSH_RELO_PORT} <user>@<this-host>     (the decoy now owns tcp/22)
EOF
