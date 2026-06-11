#!/usr/bin/env bash
#
# open-firewall.sh — open the host firewall for every decoy port a
# tarpit-honeypot config exposes, then reload so the rules go live.
#
# Reads a config YAML, extracts the (proto, port) of every `listeners:` entry
# (both flow `- { proto: tcp, bind: 0.0.0.0:502 }` and block styles), and adds
# an allow rule for each on whichever Linux firewall is in charge:
#
#   firewalld  → firewall-cmd --permanent --add-port=PORT/PROTO ; --reload
#   ufw        → ufw allow PORT/PROTO                            ; ufw reload
#   iptables   → iptables/ip6tables -I INPUT -p PROTO --dport PORT -j ACCEPT
#                (rules are live immediately; the script then persists them)
#
#   sudo scripts/open-firewall.sh -c /etc/tarpit-honeypot/config.yaml
#   scripts/open-firewall.sh -c configs/tarpit-honeypot.example-ALL-OT.yaml --dry-run
#
# Options:
#   -c, --config FILE   config to read (also accepted as the first argument).
#       --interface IF  scope the rules to inbound traffic on this NIC (e.g. eth0).
#       --ip ADDR       scope the rules to this destination IP (the host address
#                       attackers reach). --interface and --ip may be combined.
#       --backend NAME  force auto|firewalld|ufw|iptables (default: auto-detect).
#       --zone ZONE     firewalld zone (default: the interface's / default zone).
#       --dry-run       print what would change; touch nothing (no root needed).
#   -h, --help          this help.
#
# If neither --interface nor --ip is given and the script is run interactively,
# it asks which interface or IP to scope the rules to (blank = all).
#
# NOTE: the management UI port (ui.bind) is deliberately NOT opened — it is meant
# to stay on loopback behind an SSH tunnel / reverse proxy. Only the decoy
# listener ports are exposed.

set -euo pipefail

CONFIG=""
BACKEND="auto"
ZONE=""
DRY_RUN=0
INTERFACE=""
IP=""

info() { printf '\033[1;32m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
	-c | --config) CONFIG="$2"; shift 2 ;;
	--interface | --iface) INTERFACE="$2"; shift 2 ;;
	--ip | --address) IP="$2"; shift 2 ;;
	--backend) BACKEND="$2"; shift 2 ;;
	--zone) ZONE="$2"; shift 2 ;;
	--dry-run) DRY_RUN=1; shift ;;
	-h | --help) sed -n '2,40p' "$0"; exit 0 ;;
	-*) die "unknown option: $1 (see --help)" ;;
	*) [ -z "$CONFIG" ] && CONFIG="$1" && shift || die "unexpected argument: $1" ;;
	esac
done

[ -n "$CONFIG" ] || die "no config given — pass -c <file> (see --help)"
[ -f "$CONFIG" ] || die "config not found: $CONFIG"

# --- 1. Extract proto:port from the listeners: section -----------------------
# Scoped to the top-level `listeners:` block so the ui.bind / honeynet entries
# are not swept in. Defaults proto to tcp when a listener omits it.
extract_ports() {
	awk '
	function emit() {
		if (port == "") return
		pr = (proto == "" ? "tcp" : proto)
		if (port+0 > 0 && port+0 < 65536) print pr ":" port
	}
	BEGIN { in_l=0; proto=""; port=""; have=0 }
	# A column-0 key starts a new top-level section.
	/^[A-Za-z_][A-Za-z0-9_]*:/ {
		if (in_l && have) { emit(); proto=""; port=""; have=0 }
		in_l = ($0 ~ /^listeners:/) ? 1 : 0
		next
	}
	in_l {
		# New list item → flush the previous one, reset.
		if ($0 ~ /^[[:space:]]*-[[:space:]{]/) {
			if (have) emit()
			proto=""; port=""; have=0
		}
		if (match($0, /proto:[[:space:]]*[A-Za-z]+/)) {
			s=substr($0,RSTART,RLENGTH); sub(/proto:[[:space:]]*/,"",s); proto=tolower(s)
		}
		if (match($0, /bind:[[:space:]]*[^,}#]*/)) {
			b=substr($0,RSTART,RLENGTH); sub(/bind:[[:space:]]*/,"",b)
			gsub(/[" '"'"']/,"",b)
			n=split(b, a, ":"); p=a[n]
			if (p ~ /^[0-9]+$/) { port=p; have=1 }
		}
	}
	END { if (in_l && have) emit() }
	' "$CONFIG" | sort -u
}

PORTS="$(extract_ports || true)"
[ -n "$PORTS" ] || die "no listener ports found in $CONFIG — is this a tarpit-honeypot config?"

tcp_n=$(printf '%s\n' "$PORTS" | grep -c '^tcp:' || true)
udp_n=$(printf '%s\n' "$PORTS" | grep -c '^udp:' || true)
info "Config $CONFIG exposes $((tcp_n + udp_n)) decoy port(s): $tcp_n tcp, $udp_n udp"
printf '%s\n' "$PORTS" | sed 's/^/      /'

# --- 2. Resolve the scope (interface / destination IP) ----------------------
# A bare value is an IP if it looks like one (IPv4 dotted-quad or contains ':'),
# otherwise it's treated as an interface name.
ip_family() { case "$1" in *:*) printf 6 ;; *.*.*.*) printf 4 ;; *) printf '' ;; esac; }
looks_like_ip() { printf '%s' "$1" | grep -qE '^[0-9]+(\.[0-9]+){3}$' || printf '%s' "$1" | grep -q ':'; }

if [ -z "$INTERFACE" ] && [ -z "$IP" ]; then
	if [ -t 0 ]; then
		if command -v ip >/dev/null 2>&1; then
			info "Interfaces on this host:"
			ip -o addr show 2>/dev/null | awk '$3=="inet"||$3=="inet6"{print "      "$2"\t"$4}' | sort -u
		fi
		printf 'Apply the rules to which interface or IP? (e.g. eth0 / 10.0.0.5, blank = all): '
		read -r ans || true
		if [ -n "${ans:-}" ]; then
			if looks_like_ip "$ans"; then IP="$ans"; else INTERFACE="$ans"; fi
		fi
	else
		info "No --interface/--ip and no TTY to ask — opening on all interfaces/addresses."
	fi
fi

if [ -n "$INTERFACE" ] && command -v ip >/dev/null 2>&1 && ! ip link show "$INTERFACE" >/dev/null 2>&1; then
	warn "interface '$INTERFACE' is not present right now — continuing (rules apply once it appears)."
fi
SCOPE="all interfaces/addresses"
[ -n "$INTERFACE" ] && SCOPE="interface $INTERFACE"
[ -n "$IP" ] && SCOPE="${SCOPE/all interfaces\/addresses/}${INTERFACE:+ + }destination $IP"
info "Scope: $SCOPE"

# --- 3. Pick the firewall backend -------------------------------------------
detect_backend() {
	case "$BACKEND" in
	firewalld | ufw | iptables) printf '%s' "$BACKEND"; return ;;
	esac
	if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
		printf 'firewalld'; return
	fi
	if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi 'status: active'; then
		printf 'ufw'; return
	fi
	if command -v iptables >/dev/null 2>&1; then printf 'iptables'; return; fi
	printf 'none'
}
BK="$(detect_backend)"
[ "$BK" != none ] && [ -n "$BK" ] || die "no supported firewall found (need firewalld, ufw, or iptables)"
info "Firewall backend: $BK"

# Effective firewalld zone: an explicit --zone wins; else the interface's own
# zone (so --interface rules land where that NIC's traffic is handled); else the
# default zone is used implicitly.
FW_ZONE="$ZONE"
if [ "$BK" = firewalld ] && [ -z "$FW_ZONE" ] && [ -n "$INTERFACE" ]; then
	z="$(firewall-cmd --get-zone-of-interface="$INTERFACE" 2>/dev/null || true)"
	case "$z" in "" | "no zone") : ;; *) FW_ZONE="$z" ;; esac
fi

[ "$DRY_RUN" = 1 ] || [ "$(id -u)" = 0 ] || die "must run as root to change the firewall (or use --dry-run)"

# run executes a command, or just prints it under --dry-run. The real command's
# stdout is muted (we print our own progress); stderr + exit code pass through.
run() {
	if [ "$DRY_RUN" = 1 ]; then printf '      + %s\n' "$*"; return 0; fi
	"$@" >/dev/null
}

# --- 4. Add an allow rule per port (scoped to --interface / --ip) -----------
add_port() { # proto port
	local proto="$1" port="$2"
	case "$BK" in
	firewalld)
		# firewalld can't bind a port rule to a destination IP, so use a rich
		# rule for --ip; --interface is honoured by adding to that NIC's zone
		# (FW_ZONE, computed above).
		local zopt="" rr
		[ -n "$FW_ZONE" ] && zopt="--zone=$FW_ZONE"
		if [ -n "$IP" ]; then
			local fam=ipv4
			[ "$(ip_family "$IP")" = 6 ] && fam=ipv6
			rr="rule family=\"$fam\" destination address=\"$IP\" port port=\"$port\" protocol=\"$proto\" accept"
			run firewall-cmd $zopt --permanent --add-rich-rule="$rr" || warn "firewalld: rich-rule $port/$proto failed"
		else
			run firewall-cmd $zopt --permanent --add-port="$port/$proto" || warn "firewalld: add $port/$proto failed"
		fi
		;;
	ufw)
		if [ -z "$INTERFACE" ] && [ -z "$IP" ]; then
			run ufw allow "$port/$proto" || warn "ufw: allow $port/$proto failed"
		else
			set -- allow in
			[ -n "$INTERFACE" ] && set -- "$@" on "$INTERFACE"
			if [ -n "$IP" ]; then set -- "$@" to "$IP"; else set -- "$@" to any; fi
			set -- "$@" port "$port" proto "$proto"
			run ufw "$@" || warn "ufw: allow $port/$proto failed"
		fi
		;;
	iptables)
		local ipt fam
		for ipt in iptables ip6tables; do
			command -v "$ipt" >/dev/null 2>&1 || continue
			# A v4/v6 destination IP belongs only in the matching table.
			if [ -n "$IP" ]; then
				fam="$(ip_family "$IP")"
				if [ "$ipt" = iptables ] && [ "$fam" = 6 ]; then continue; fi
				if [ "$ipt" = ip6tables ] && [ "$fam" = 4 ]; then continue; fi
			fi
			set -- INPUT
			[ -n "$INTERFACE" ] && set -- "$@" -i "$INTERFACE"
			[ -n "$IP" ] && set -- "$@" -d "$IP"
			set -- "$@" -p "$proto" --dport "$port" -j ACCEPT
			if [ "$DRY_RUN" = 1 ]; then printf '      + %s -I %s\n' "$ipt" "$*"; continue; fi
			"$ipt" -C "$@" 2>/dev/null && continue # idempotent: identical rule exists
			"$ipt" -I "$@" || warn "$ipt: insert $port/$proto failed"
		done
		;;
	esac
}

info "Opening ports…"
while IFS=: read -r proto port; do
	[ -n "$port" ] || continue
	add_port "$proto" "$port"
done <<EOF
$(printf '%s\n' "$PORTS")
EOF

# --- 5. Reload / persist so the rules are active ----------------------------
case "$BK" in
firewalld)
	info "Reloading firewalld to activate the permanent rules…"
	run firewall-cmd --reload
	;;
ufw)
	info "Reloading ufw…"
	run ufw reload
	;;
iptables)
	# iptables rules are live the instant they're inserted — there is no reload;
	# persist them so they also survive a reboot, using whatever the distro has.
	info "iptables rules are already active; persisting them across reboots…"
	if command -v netfilter-persistent >/dev/null 2>&1; then
		run netfilter-persistent save
	elif [ -d /etc/iptables ]; then
		run sh -c 'iptables-save > /etc/iptables/rules.v4'
		command -v ip6tables-save >/dev/null 2>&1 && run sh -c 'ip6tables-save > /etc/iptables/rules.v6'
	elif command -v service >/dev/null 2>&1 && service iptables status >/dev/null 2>&1; then
		run service iptables save
	else
		warn "could not persist iptables rules automatically — save them with your distro's mechanism (e.g. 'iptables-save > /etc/iptables/rules.v4')"
	fi
	;;
esac

info "Done. The decoy ports are now allowed through the firewall."
