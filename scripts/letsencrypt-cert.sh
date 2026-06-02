#!/usr/bin/env bash
#
# letsencrypt-cert.sh — obtain a real Let's Encrypt TLS certificate for the
# tarpit-honeypot management web UI, and install a sensor-readable copy that
# auto-renews.
#
# It asks for the DOMAIN and HOSTNAME to put on the certificate (or take them on
# the command line), installs certbot for your distro, obtains the cert, and
# writes a renewal deploy-hook that copies the cert to a location the
# unprivileged sensor user can read and reloads the service. The tarpit-cert-
# renew.timer (installed by install.sh) then keeps it current.
#
# NOTE: this cert is for the MANAGEMENT UI only. Do NOT point the deceptive
# `https` SERVICE listeners at a real cert — that would tie the honeypot to your
# real identity; they intentionally use archetype-shaped self-signed certs.
#
# Because the sensor binds port 80, the default HTTP-01 method briefly stops the
# service for validation (via certbot pre/post hooks). Use --method dns for a
# zero-downtime issuance if you have a DNS plugin configured.
#
# Usage:
#   letsencrypt-cert.sh [OPTIONS]
#   -d, --domain DOMAIN     base domain (e.g. example.com)
#   -H, --hostname HOST     hostname or FQDN for the cert (e.g. hp01 or hp01.example.com)
#   -m, --email EMAIL       ACME account email (expiry notices)
#       --method M          standalone (default) | webroot | dns
#       --webroot DIR       webroot path (with --method webroot)
#       --service NAME      service to stop/start for standalone (default tarpit-honeypot)
#       --tls-dir DIR       sensor-readable copy dir (default /etc/tarpit-honeypot/tls)
#       --user NAME         owner of the copy (default honey)
#       --group NAME        group of the copy (default honeypot)
#       --staging           use the LE staging environment (testing — untrusted certs)
#   -h, --help              this help

set -euo pipefail

DOMAIN=""; HOSTNAME_IN=""; EMAIL=""
METHOD="standalone"; WEBROOT=""; SERVICE="tarpit-honeypot"
TLS_DIR="/etc/tarpit-honeypot/tls"; OWNER="honey"; OGROUP="honeypot"; STAGING=0

while [ $# -gt 0 ]; do
	case "$1" in
	-d | --domain) DOMAIN="$2"; shift 2 ;;
	-H | --hostname) HOSTNAME_IN="$2"; shift 2 ;;
	-m | --email) EMAIL="$2"; shift 2 ;;
	--method) METHOD="$2"; shift 2 ;;
	--webroot) WEBROOT="$2"; shift 2 ;;
	--service) SERVICE="$2"; shift 2 ;;
	--tls-dir) TLS_DIR="$2"; shift 2 ;;
	--user) OWNER="$2"; shift 2 ;;
	--group) OGROUP="$2"; shift 2 ;;
	--staging) STAGING=1; shift ;;
	-h | --help) sed -n '2,33p' "$0"; exit 0 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

info() { printf '\033[1;32m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "must run as root (sudo $0)"

# ---- interactive prompts for anything not supplied -------------------------
[ -n "$DOMAIN" ]      || read -rp "Domain (e.g. example.com): " DOMAIN
[ -n "$HOSTNAME_IN" ] || read -rp "Hostname for the certificate (e.g. hp01 or hp01.$DOMAIN): " HOSTNAME_IN
[ -n "$DOMAIN" ] && [ -n "$HOSTNAME_IN" ] || die "domain and hostname are required"

# Build the FQDN: a hostname that already contains a dot is taken as-is.
case "$HOSTNAME_IN" in
*.*) FQDN="$HOSTNAME_IN" ;;
*)   FQDN="$HOSTNAME_IN.$DOMAIN" ;;
esac
info "Certificate FQDN: $FQDN"

if [ -z "$EMAIL" ]; then
	read -rp "ACME account email (blank = register unsafely without one): " EMAIL || true
fi

# ---- install certbot for this distro ---------------------------------------
ensure_certbot() {
	command -v certbot >/dev/null 2>&1 && return 0
	local id like; id=""; like=""
	[ -r /etc/os-release ] && { . /etc/os-release; id="${ID:-}"; like="${ID_LIKE:-}"; }
	info "Installing certbot…"
	case " $id $like " in
	*debian* | *ubuntu*) DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y certbot >/dev/null 2>&1 ;;
	*fedora*)            dnf install -y certbot >/dev/null 2>&1 ;;
	*rhel* | *centos*)   { dnf install -y epel-release >/dev/null 2>&1 || yum install -y epel-release >/dev/null 2>&1 || true; } && { dnf install -y certbot >/dev/null 2>&1 || yum install -y certbot >/dev/null 2>&1; } ;;
	*suse*)              zypper --non-interactive install certbot >/dev/null 2>&1 ;;
	*arch*)              pacman -S --noconfirm certbot >/dev/null 2>&1 ;;
	esac
	command -v certbot >/dev/null 2>&1 || die "could not install certbot automatically; install it and re-run"
}
ensure_certbot

# ---- renewal deploy-hook: copy a sensor-readable cert + reload -------------
# Runs on issuance and on every future renewal (the tarpit-cert-renew.timer
# fires `certbot renew`, which calls deploy hooks for renewed lineages).
install -d -o "$OWNER" -g "$OGROUP" -m 0750 "$TLS_DIR"
HOOK_DIR="/etc/letsencrypt/renewal-hooks/deploy"
install -d -m 0755 "$HOOK_DIR"
HOOK="$HOOK_DIR/tarpit-honeypot.sh"
info "Installing renewal deploy-hook -> $HOOK"
cat >"$HOOK" <<EOF
#!/usr/bin/env bash
# Installed by letsencrypt-cert.sh. Copies the renewed cert to a location the
# unprivileged sensor user can read, then reloads the sensor.
set -eu
TLS_DIR="$TLS_DIR"; OWNER="$OWNER"; OGROUP="$OGROUP"; SERVICE="$SERVICE"; FQDN="$FQDN"
# RENEWED_LINEAGE is set by certbot; fall back to our known path for a manual run.
LINEAGE="\${RENEWED_LINEAGE:-/etc/letsencrypt/live/\$FQDN}"
[ -f "\$LINEAGE/fullchain.pem" ] || exit 0
install -o "\$OWNER" -g "\$OGROUP" -m 0644 "\$LINEAGE/fullchain.pem" "\$TLS_DIR/cert.pem"
install -o "\$OWNER" -g "\$OGROUP" -m 0640 "\$LINEAGE/privkey.pem"   "\$TLS_DIR/key.pem"
if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled "\$SERVICE" >/dev/null 2>&1; then
	systemctl reload-or-restart "\$SERVICE" || true
else
	pkill -HUP -x tarpit-honeypot || true
fi
EOF
chmod 0755 "$HOOK"

# ---- obtain the certificate ------------------------------------------------
CB=(certbot certonly --non-interactive --agree-tos -d "$FQDN")
[ "$STAGING" = 1 ] && CB+=(--staging)
if [ -n "$EMAIL" ]; then CB+=(-m "$EMAIL"); else CB+=(--register-unsafely-without-email); fi

case "$METHOD" in
standalone)
	# The sensor occupies port 80, so stop it for the HTTP-01 challenge and
	# start it again afterwards. certbot stores these hooks for renewals too.
	CB+=(--standalone
		--pre-hook  "systemctl stop $SERVICE 2>/dev/null || pkill -x tarpit-honeypot || true"
		--post-hook "systemctl start $SERVICE 2>/dev/null || true")
	warn "standalone mode briefly stops '$SERVICE' to free port 80 for validation"
	;;
webroot)
	[ -n "$WEBROOT" ] || die "--method webroot requires --webroot DIR"
	CB+=(--webroot -w "$WEBROOT")
	;;
dns)
	# Zero-downtime, but needs a DNS plugin/credentials configured beforehand.
	CB+=(--manual --preferred-challenges dns)
	warn "DNS-01: follow certbot's prompt to publish the TXT record (or pre-configure a DNS plugin)"
	;;
*) die "unknown --method: $METHOD (standalone|webroot|dns)" ;;
esac

info "Requesting certificate: ${CB[*]}"
"${CB[@]}"

# ---- run the deploy hook now so the copies + config are ready --------------
RENEWED_LINEAGE="/etc/letsencrypt/live/$FQDN" "$HOOK"

# ---- point the config at the cert, enable the renew timer ------------------
CONFIG="/etc/tarpit-honeypot/config.yaml"
if [ -f "$CONFIG" ]; then
	sed -i \
		-e "s|^\([[:space:]]*\)# *tls_cert:.*|\1tls_cert: $TLS_DIR/cert.pem|" \
		-e "s|^\([[:space:]]*\)# *tls_key:.*|\1tls_key:  $TLS_DIR/key.pem|" \
		"$CONFIG" 2>/dev/null || true
fi
if command -v systemctl >/dev/null 2>&1; then
	systemctl enable --now tarpit-cert-renew.timer >/dev/null 2>&1 || true
fi

cat <<EOF

$(info "Done.")
  FQDN        : $FQDN
  cert (UI)   : $TLS_DIR/cert.pem
  key  (UI)   : $TLS_DIR/key.pem   (owner $OWNER:$OGROUP, mode 0640)
  renew hook  : $HOOK
  auto-renew  : tarpit-cert-renew.timer (twice daily)

Wire it into the UI (in $CONFIG under 'ui:'):
  tls_cert: $TLS_DIR/cert.pem
  tls_key:  $TLS_DIR/key.pem
To expose the UI off-loopback you MUST also set 'bind:' to a routable address
and 'auth_token_env:' (the validator enforces TLS + auth for non-loopback UI).
Then: sudo systemctl reload tarpit-honeypot
EOF
