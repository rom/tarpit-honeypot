#!/usr/bin/env bash
#
# wireguard-setup.sh — install and configure a WireGuard tunnel on a sensor so
# its management UI and outbound alert channels reach your SOC over an encrypted
# link instead of riding the public internet.
#
# It detects the distro, installs wireguard-tools, generates THIS sensor's
# keypair (the private key never leaves the host), writes /etc/wireguard/<iface>.conf
# with an [Interface] + one [Peer] (your hub), brings the tunnel up with
# wg-quick@<iface>, and then PRINTS the exact, value-filled [Peer] block plus this
# sensor's PUBLIC key for you to paste into the other side.
#
# Two topologies, chosen automatically from --endpoint:
#
#   spoke    (--endpoint HOST:PORT given): the sensor DIALS the hub. No inbound
#            port is opened; PersistentKeepalive holds the path open through NAT.
#            Use this for sensors scattered behind firewalls / NAT (the common case).
#
#   listener (no --endpoint): the hub DIALS the sensor. The script binds ListenPort,
#            opens that UDP port in the host firewall, and tells you to set
#            Endpoint=<this sensor's public IP>:PORT on the hub. Use this when the
#            sensor has a stable public IP and the hub initiates.
#
#   sudo scripts/wireguard-setup.sh --endpoint soc.example.com:51820 \
#        --tunnel-ip 10.8.0.2/24 --hub-ip 10.8.0.1 --hub-pubkey <HUB_PUBLIC_KEY>
#   scripts/wireguard-setup.sh --endpoint soc.example.com:51820 --dry-run
#
# Options:
#   --endpoint HOST:PORT  the hub's public WireGuard endpoint. Given → spoke mode
#                         (dial out). Omitted → listener mode (hub dials in).
#   --hub-pubkey KEY      the hub's PUBLIC key. If you already have it the config
#                         is complete and the tunnel starts; if not, a placeholder
#                         is written and the script prints how to finish later.
#   --tunnel-ip CIDR      this sensor's address inside the tunnel (default 10.8.0.2/24).
#   --hub-ip ADDR         the hub's address inside the tunnel (default 10.8.0.1).
#   --allowed-ips LIST    what this sensor routes INTO the tunnel (default: the
#                         subnet of --tunnel-ip, e.g. 10.8.0.0/24 — reach the whole
#                         WG net; narrow to <hub-ip>/32 to reach only the hub).
#   --listen-port N       UDP port WireGuard binds (default 51820). Only opened in
#                         the firewall in listener mode.
#   --keepalive N         PersistentKeepalive seconds (default 25 spoke / off listener).
#   --iface NAME          WireGuard interface / config name (default wg0).
#   --no-psk              do not use a pre-shared key (default: generate one — an
#                         extra symmetric secret both sides share; recommended).
#   --rotate-keys         regenerate this sensor's keypair even if one exists
#                         (invalidates the public key already given to the hub).
#   --enable-forwarding   set net.ipv4.ip_forward=1 (ONLY if this sensor must ROUTE
#                         for others; a plain endpoint sensor does not need it).
#   --no-firewall         don't touch the firewall (listener mode).
#   --no-start            write everything but don't enable/start wg-quick@<iface>.
#   --force               overwrite an existing <iface>.conf (a backup is kept).
#   --dry-run             print what would happen; write/install/change nothing.
#   -h, --help            this help.
#
# SECURITY: the sensor's PRIVATE key is generated on the host, stored 0600 under
# /etc/wireguard, and is NEVER printed or transmitted. You exchange only PUBLIC
# keys. A pre-shared key, if used, IS a shared secret — send the printed hub
# snippet over a secure channel (SSH / age / password manager), not plain mail/chat.

set -euo pipefail

ENDPOINT=""
HUB_PUB=""
TUNNEL_IP="10.8.0.2/24"
HUB_IP="10.8.0.1"
ALLOWED_IPS=""
LISTEN_PORT="51820"
KEEPALIVE=""            # resolved once the mode is known
IFACE="wg0"
USE_PSK=1
ROTATE_KEYS=0
ENABLE_FWD=0
DO_FIREWALL=1
DO_START=1
FORCE=0
DRY_RUN=0
ETC_WG="/etc/wireguard"
HUB_PUB_PLACEHOLDER="<PASTE_HUB_PUBLIC_KEY_HERE>"

info() { printf '\033[1;32m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
	--endpoint) ENDPOINT="$2"; shift 2 ;;
	--hub-pubkey | --peer-pubkey) HUB_PUB="$2"; shift 2 ;;
	--tunnel-ip | --address) TUNNEL_IP="$2"; shift 2 ;;
	--hub-ip) HUB_IP="$2"; shift 2 ;;
	--allowed-ips) ALLOWED_IPS="$2"; shift 2 ;;
	--listen-port) LISTEN_PORT="$2"; shift 2 ;;
	--keepalive) KEEPALIVE="$2"; shift 2 ;;
	--iface) IFACE="$2"; shift 2 ;;
	--no-psk) USE_PSK=0; shift ;;
	--psk) USE_PSK=1; shift ;;
	--rotate-keys) ROTATE_KEYS=1; shift ;;
	--enable-forwarding) ENABLE_FWD=1; shift ;;
	--no-firewall) DO_FIREWALL=0; shift ;;
	--no-start) DO_START=0; shift ;;
	--force) FORCE=1; shift ;;
	--dry-run) DRY_RUN=1; shift ;;
	-h | --help) sed -n '2,/^set -euo pipefail$/p' "$0" | sed '$d'; exit 0 ;;
	-*) die "unknown option: $1 (see --help)" ;;
	*) die "unexpected argument: $1 (see --help)" ;;
	esac
done

CONF="$ETC_WG/$IFACE.conf"
KEY="$ETC_WG/$IFACE.key"
PUBKEY_FILE="$ETC_WG/$IFACE.pub"
PSK_FILE="$ETC_WG/$IFACE.psk"

# --- helpers ----------------------------------------------------------------

# tunnel_subnet CIDR -> network/prefix (IPv4). For /32 (or a bare IP) it falls
# back to <hub-ip>/32 so AllowedIPs still includes the hub. IPv6 punts to hub/128.
tunnel_subnet() {
	local cidr="$1" ip prefix a b c d ipnum mask net
	ip="${cidr%/*}"; prefix="${cidr#*/}"
	[ "$ip" = "$cidr" ] && prefix=32
	case "$ip" in *:*) printf '%s/128' "$HUB_IP"; return ;; esac
	case "$prefix" in *[!0-9]*) prefix=32 ;; esac
	if [ "$prefix" -ge 32 ]; then printf '%s/32' "$HUB_IP"; return; fi
	IFS=. read -r a b c d <<EOF2
$ip
EOF2
	ipnum=$(( (a << 24) | (b << 16) | (c << 8) | d ))
	if [ "$prefix" -eq 0 ]; then mask=0; else mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF )); fi
	net=$(( ipnum & mask ))
	printf '%d.%d.%d.%d/%d' $(( (net >> 24) & 255 )) $(( (net >> 16) & 255 )) $(( (net >> 8) & 255 )) $(( net & 255 )) "$prefix"
}

# host32 CIDR -> the host address as a /32 (IPv4) or /128 (IPv6).
host32() { case "$1" in *:*) printf '%s/128' "${1%/*}" ;; *) printf '%s/32' "${1%/*}" ;; esac; }

# detect_public_ip -> the source address this host uses for off-link traffic.
detect_public_ip() {
	local ip=""
	if command -v ip >/dev/null 2>&1; then
		ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
	fi
	[ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
	printf '%s' "${ip:-<this-sensor-public-IP>}"
}

# run a command, or just print it under --dry-run.
run() {
	if [ "$DRY_RUN" = 1 ]; then printf '      + %s\n' "$*"; return 0; fi
	"$@"
}

# --- validate + resolve topology --------------------------------------------
case "$TUNNEL_IP" in */*) : ;; *) die "--tunnel-ip must be CIDR (e.g. 10.8.0.2/24), got: $TUNNEL_IP" ;; esac
case "$LISTEN_PORT" in *[!0-9]*) die "--listen-port must be numeric, got: $LISTEN_PORT" ;; esac

if [ -z "$ENDPOINT" ] && [ "$DRY_RUN" = 0 ] && [ -t 0 ]; then
	printf 'Hub WireGuard endpoint HOST:PORT (blank = this sensor LISTENS and the hub dials in): '
	read -r ans || true
	ENDPOINT="${ans:-}"
fi

if [ -n "$ENDPOINT" ]; then
	MODE="spoke"
	case "$ENDPOINT" in *:*) : ;; *) die "--endpoint must be HOST:PORT (got: $ENDPOINT)" ;; esac
	[ -n "$KEEPALIVE" ] || KEEPALIVE=25
else
	MODE="listener"
	[ -n "$KEEPALIVE" ] || KEEPALIVE=0
fi
case "$KEEPALIVE" in *[!0-9]*) die "--keepalive must be numeric, got: $KEEPALIVE" ;; esac

# Default AllowedIPs = the whole tunnel subnet implied by --tunnel-ip.
[ -n "$ALLOWED_IPS" ] || ALLOWED_IPS="$(tunnel_subnet "$TUNNEL_IP")"

info "Interface $IFACE — $MODE mode"
info "  tunnel address : $TUNNEL_IP   (hub: $HUB_IP)"
info "  routes into WG : $ALLOWED_IPS"
[ "$MODE" = spoke ] && info "  dials hub at   : $ENDPOINT   (keepalive ${KEEPALIVE}s)"
[ "$MODE" = listener ] && info "  listens on     : UDP/$LISTEN_PORT (hub dials in)"
[ "$USE_PSK" = 1 ] && info "  pre-shared key : yes (extra symmetric secret)"

# --- preflight (do this before installing anything) -------------------------
[ "$DRY_RUN" = 1 ] || [ "$(id -u)" = 0 ] || die "must run as root to install + configure WireGuard (or use --dry-run)"

if [ "$DRY_RUN" = 0 ] && [ -e "$CONF" ] && [ "$FORCE" = 0 ]; then
	die "$CONF already exists — refusing to overwrite. Re-run with --force (a timestamped backup is kept), or edit it by hand."
fi

case "$(uname -r)" in
[1-4].* | 5.[0-5].* | 5.[0-5]) warn "kernel $(uname -r) predates in-tree WireGuard (5.6+); also install the DKMS 'wireguard' package" ;;
esac

# --- distro detection + install ---------------------------------------------
FAMILY="unknown"; PKG=""
detect_distro() {
	if [ -r /etc/os-release ]; then
		# shellcheck disable=SC1091
		. /etc/os-release
	fi
	case " ${ID:-} ${ID_LIKE:-} " in
	*" debian "* | *" ubuntu "*) FAMILY="debian" ;;
	*" rhel "* | *" fedora "* | *" centos "*) FAMILY="rhel" ;;
	*" suse "* | *" opensuse "*) FAMILY="suse" ;;
	*" arch "*) FAMILY="arch" ;;
	esac
	case "${ID:-}" in
	debian | ubuntu | linuxmint | pop | raspbian) FAMILY="debian" ;;
	rhel | centos | almalinux | rocky | fedora | ol | oracle | amzn) FAMILY="rhel" ;;
	sles | opensuse*) FAMILY="suse" ;;
	arch | manjaro) FAMILY="arch" ;;
	esac
	case "$FAMILY" in
	debian) PKG="apt-get" ;;
	rhel)   PKG="$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)" ;;
	suse)   PKG="zypper" ;;
	arch)   PKG="pacman" ;;
	esac
}
detect_distro

install_wireguard() {
	if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
		info "wireguard-tools already present ($(wg --version 2>/dev/null | head -1))"
		return 0
	fi
	info "Installing wireguard-tools (pkg manager: ${PKG:-unknown})…"
	case "$PKG" in
	apt-get)
		DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
		DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools >/dev/null 2>&1 ||
			DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard >/dev/null 2>&1 ||
			warn "apt-get could not install wireguard-tools" ;;
	dnf | yum) "$PKG" install -y wireguard-tools >/dev/null 2>&1 || warn "$PKG could not install wireguard-tools" ;;
	zypper)    zypper --non-interactive install wireguard-tools >/dev/null 2>&1 || warn "zypper could not install wireguard-tools" ;;
	pacman)    pacman -Sy --noconfirm wireguard-tools >/dev/null 2>&1 || warn "pacman could not install wireguard-tools" ;;
	*)         warn "unknown package manager — install 'wireguard-tools' manually" ;;
	esac
	command -v wg >/dev/null 2>&1 || die "wg not found after install — install wireguard-tools manually and re-run"
}

# --- generate / reuse this sensor's keypair ---------------------------------
generate_keys() {
	install -d -m 0700 "$ETC_WG"
	if [ "$ROTATE_KEYS" = 1 ] || [ ! -s "$KEY" ]; then
		info "Generating this sensor's WireGuard keypair…"
		( umask 077; wg genkey > "$KEY" )
		chmod 0600 "$KEY"
	else
		info "Reusing existing private key $KEY (use --rotate-keys to replace)"
	fi
	SENSOR_PUB="$(wg pubkey < "$KEY")"
	printf '%s\n' "$SENSOR_PUB" > "$PUBKEY_FILE"; chmod 0644 "$PUBKEY_FILE"
	if [ "$USE_PSK" = 1 ]; then
		if [ "$ROTATE_KEYS" = 1 ] || [ ! -s "$PSK_FILE" ]; then
			( umask 077; wg genpsk > "$PSK_FILE" ); chmod 0600 "$PSK_FILE"
		fi
		PSK="$(cat "$PSK_FILE")"
	fi
}

# --- assemble the sensor config ---------------------------------------------
build_conf() {
	printf '# tarpit-honeypot sensor tunnel — generated by scripts/wireguard-setup.sh\n'
	printf '# interface %s | mode %s | %s\n' "$IFACE" "$MODE" "$(date -u +%FT%TZ)"
	printf '[Interface]\n'
	printf 'PrivateKey = %s\n' "$PRIV_REF"
	printf 'Address = %s\n' "$TUNNEL_IP"
	if [ "$MODE" = listener ]; then printf 'ListenPort = %s\n' "$LISTEN_PORT"; fi
	printf '\n[Peer]\n'
	printf '# hub / SOC management endpoint\n'
	printf 'PublicKey = %s\n' "$HUB_PUB_REF"
	printf 'AllowedIPs = %s\n' "$ALLOWED_IPS"
	if [ -n "$ENDPOINT" ]; then printf 'Endpoint = %s\n' "$ENDPOINT"; fi
	if [ "$USE_PSK" = 1 ]; then printf 'PresharedKey = %s\n' "$PSK_REF"; fi
	if [ "$KEEPALIVE" -gt 0 ]; then printf 'PersistentKeepalive = %s\n' "$KEEPALIVE"; fi
	return 0
}

# --- single UDP port opener (listener mode) ---------------------------------
open_udp_port() { # port
	local port="$1" bk=""
	if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then bk=firewalld
	elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi 'status: active'; then bk=ufw
	elif command -v iptables >/dev/null 2>&1; then bk=iptables
	fi
	case "$bk" in
	firewalld)
		info "Opening UDP/$port (firewalld)…"
		run firewall-cmd --permanent --add-port="$port/udp" || warn "firewalld: add $port/udp failed"
		run firewall-cmd --reload || warn "firewalld: reload failed" ;;
	ufw)
		info "Opening UDP/$port (ufw)…"
		run ufw allow "$port/udp" || warn "ufw: allow $port/udp failed" ;;
	iptables)
		info "Opening UDP/$port (iptables)…"
		if [ "$DRY_RUN" = 1 ]; then
			printf '      + iptables -I INPUT -p udp --dport %s -j ACCEPT\n' "$port"
		else
			iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null ||
				iptables -I INPUT -p udp --dport "$port" -j ACCEPT || warn "iptables: insert failed"
		fi ;;
	*) warn "no supported firewall detected — open UDP/$port manually so the hub can reach this sensor" ;;
	esac
}

# --- bring the tunnel up ----------------------------------------------------
start_tunnel() {
	if command -v systemctl >/dev/null 2>&1; then
		run systemctl enable --now "wg-quick@$IFACE"
	else
		run wg-quick up "$IFACE"
	fi
}

# ===========================================================================
# Execute
# ===========================================================================
if [ "$DRY_RUN" = 1 ]; then
	SENSOR_PUB="<sensor-public-key>"
	PRIV_REF="<sensor-private-key (generated on first real run; never shared)>"
	PSK="<pre-shared-key>"
else
	install_wireguard
	generate_keys
	PRIV_REF="$(cat "$KEY")"
fi

# Secrets that go into the on-disk config (real values) vs. the dry-run preview.
PSK_REF="$PSK"
if [ "$DRY_RUN" = 1 ] && [ "$USE_PSK" = 1 ]; then PSK_REF="<pre-shared-key>"; fi

CAN_START=1
if [ -n "$HUB_PUB" ]; then
	HUB_PUB_REF="$HUB_PUB"
else
	HUB_PUB_REF="$HUB_PUB_PLACEHOLDER"
	CAN_START=0
fi

# Write (or preview) the sensor config.
if [ "$DRY_RUN" = 1 ]; then
	info "(dry-run) $CONF would contain:"
	build_conf | sed 's/^/      /'
else
	if [ -e "$CONF" ]; then
		cp -a "$CONF" "$CONF.bak.$(date +%s)" && info "backed up existing $CONF"
	fi
	( umask 077; build_conf > "$CONF" ); chmod 0600 "$CONF"
	info "Wrote $CONF (PrivateKey/PresharedKey stored 0600, not shown)"
fi

# Firewall: only the listener needs an inbound UDP hole.
if [ "$MODE" = listener ] && [ "$DO_FIREWALL" = 1 ]; then
	open_udp_port "$LISTEN_PORT"
elif [ "$MODE" = spoke ]; then
	info "Spoke mode — no inbound firewall change needed (the sensor dials out)."
fi

# Optional IP forwarding (only when this sensor must route for others).
if [ "$ENABLE_FWD" = 1 ]; then
	info "Enabling net.ipv4.ip_forward (this sensor will ROUTE for the tunnel)…"
	run sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
	if [ -d /etc/sysctl.d ]; then
		run sh -c 'printf "net.ipv4.ip_forward = 1\n" > /etc/sysctl.d/99-tarpit-wireguard.conf'
	fi
fi

# Start, if we can (we need the hub's public key for a working tunnel).
if [ "$DO_START" = 1 ] && [ "$DRY_RUN" = 0 ]; then
	if [ "$CAN_START" = 1 ]; then
		info "Bringing up the tunnel (wg-quick@$IFACE)…"
		start_tunnel
		command -v wg >/dev/null 2>&1 && wg show "$IFACE" 2>/dev/null || true
	else
		warn "Not starting yet — the hub's public key is unknown, so $CONF has a placeholder."
		warn "Finish once the hub gives you its key (steps printed below)."
	fi
elif [ "$DO_START" = 0 ]; then
	info "Not starting (per --no-start). Start later: systemctl enable --now wg-quick@$IFACE"
fi

# ===========================================================================
# Describe the OTHER SIDE (the hub) — the value-filled snippet to paste there.
# ===========================================================================
print_other_side() {
	local tun32 pubip host today
	tun32="$(host32 "$TUNNEL_IP")"
	host="$(hostname -s 2>/dev/null || echo sensor)"
	today="$(date -u +%F)"

	printf '\n'
	printf '==================================================================\n'
	printf ' CONFIGURE THE OTHER SIDE (your hub / SOC management endpoint)\n'
	printf '==================================================================\n'

	info "This sensor's PUBLIC key (safe to send in the clear):"
	printf '      %s\n\n' "$SENSOR_PUB"

	if [ "$MODE" = spoke ]; then
		cat <<-TXT
		Topology: this sensor DIALS the hub at $ENDPOINT and holds the path open
		with PersistentKeepalive=$KEEPALIVE; the hub never needs the sensor's IP.

		1. On the hub, generate ITS own keypair (the hub's private key stays there):
		      wg genkey | tee hub.key | wg pubkey > hub.pub
		2. Add THIS sensor as a [Peer] in the hub's config:
		TXT
	else
		pubip="$(detect_public_ip)"
		cat <<-TXT
		Topology: the hub DIALS this sensor. This sensor listens on UDP/$LISTEN_PORT
		(opened in the firewall). Point the hub's Endpoint at this sensor's reachable
		address (detected $pubip — verify it is the public / NATed address the hub
		can reach, and that UDP/$LISTEN_PORT is forwarded to here).

		1. On the hub, generate ITS own keypair (the hub's private key stays there):
		      wg genkey | tee hub.key | wg pubkey > hub.pub
		2. Add THIS sensor as a [Peer] in the hub's config:
		TXT
	fi

	{
		printf '\n[Peer]\n'
		printf '# tarpit-honeypot sensor %s — added %s\n' "$host" "$today"
		printf 'PublicKey = %s\n' "$SENSOR_PUB"
		printf 'AllowedIPs = %s\n' "$tun32"
		if [ "$USE_PSK" = 1 ]; then printf 'PresharedKey = %s\n' "$PSK"; fi
		if [ "$MODE" = listener ]; then printf 'Endpoint = %s:%s\n' "$pubip" "$LISTEN_PORT"; fi
		printf '\n'
	} | sed 's/^/      /'

	if [ "$USE_PSK" = 1 ]; then
		warn "The snippet above contains the pre-shared KEY (a shared secret)."
		warn "Send it over a secure channel (SSH / age / password manager), not plain mail/chat."
	fi

	# A sketch of the hub's own [Interface], tailored to the topology.
	printf '\n   The matching [Interface] on the hub looks like:\n\n'
	if [ "$MODE" = spoke ]; then
		cat <<-TXT | sed 's/^/      /'
		[Interface]
		PrivateKey = <hub-private-key>        # the hub.key generated above
		Address    = $HUB_IP/${TUNNEL_IP#*/}
		ListenPort = ${ENDPOINT##*:}                   # the port this sensor dials — must be reachable
		TXT
	else
		cat <<-TXT | sed 's/^/      /'
		[Interface]
		PrivateKey = <hub-private-key>        # the hub.key generated above
		Address    = $HUB_IP/${TUNNEL_IP#*/}
		# ListenPort optional; the hub initiates to the sensor's Endpoint above.
		TXT
	fi

	cat <<-TXT

	3. Reload the hub so the peer takes effect:
	      wg syncconf <iface> <(wg-quick strip <iface>)   # hot-reload, no flap
	      # or: systemctl restart wg-quick@<iface>

	Verify from either end:  wg show     (look for a recent handshake + rising rx/tx)
	TXT
	return 0
}
print_other_side

# Finish-up steps when the hub key was not supplied yet.
if [ "$CAN_START" = 0 ]; then
	cat <<-TXT

	------------------------------------------------------------------
	 FINISH ON THIS SENSOR once you have the hub's public key
	------------------------------------------------------------------
	  sudo sed -i "s#$HUB_PUB_PLACEHOLDER#<hub-public-key>#" $CONF
	  sudo systemctl enable --now wg-quick@$IFACE
	TXT
fi

cat <<-TXT

	Tip: route the management UI over the tunnel by binding it to the sensor's
	tunnel address — set  ui.bind: ${TUNNEL_IP%/*}:8088  in the config and reach it
	from the SOC at https://${TUNNEL_IP%/*}:8088. The decoy listeners stay on the
	public interface; only your console rides the encrypted link.
TXT

info "Done."
