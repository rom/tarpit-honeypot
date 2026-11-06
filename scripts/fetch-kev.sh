#!/usr/bin/env bash
#
# fetch-kev.sh — download the CISA Known Exploited Vulnerabilities (KEV) catalog
# and (optionally) inject it into a sensor for the OFFLINE / air-gapped case.
#
# The sensor can sync KEV live over the network (config: kev.enabled + kev.poll;
# see docs/usage.md). When the sensor can't reach cisa.gov, run this on an
# internet-connected box instead, transfer the JSON, and point the sensor at it
# with `kev.file` (loaded at start + on SIGHUP). KEV membership marks a
# cve:<id> event as actively-exploited and powers `tarpit-honeypot kev-gap`
# (which CVEs the catalog does not yet model).
#
# Usage:
#   scripts/fetch-kev.sh [OPTIONS] [OUTPUT_DIR]
#     OUTPUT_DIR         where to write (default: ./kev-data); the file lands at
#                        <dir>/kev/known_exploited_vulnerabilities.json so it
#                        drops straight into an enrichment bundle.
#   -i, --install        after fetching, install into THIS host's sensor
#                        (copies to the configured kev.file + reloads)
#   -c, --config PATH    sensor config for --install (default
#                        /etc/tarpit-honeypot/config.yaml)
#       --bin PATH       tarpit-honeypot binary for --install (auto-detected)
#       --reload-cmd C   reload command for --install (e.g. "systemctl reload tarpit-honeypot")
#       --ics            keep only ICS/OT/SCADA-relevant entries (needs jq)
#   -q, --quiet          terse output
#   -h, --help           this help
#
# Environment:
#   KEV_URL              override the feed (default: the CISA KEV JSON)
#   KEV_HEADER           optional "Name: value" request header
#   INSECURE=1           pass -k / --no-check-certificate (not recommended)
#
# The feed is public; nothing here is sensor-specific.

if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
set -euo pipefail

OUT=""
INSTALL=0
CONFIG="/etc/tarpit-honeypot/config.yaml"
RELOAD_CMD=""
BIN=""
QUIET=0
ICS=0
URL="${KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}"
while [ $# -gt 0 ]; do
	case "$1" in
	-i | --install) INSTALL=1; shift ;;
	-c | --config) CONFIG="$2"; shift 2 ;;
	--bin) BIN="$2"; shift 2 ;;
	--reload-cmd) RELOAD_CMD="$2"; shift 2 ;;
	--ics) ICS=1; shift ;;
	-q | --quiet) QUIET=1; shift ;;
	-h | --help) sed -n '2,38p' "$0"; exit 0 ;;
	-*) echo "unknown option: $1" >&2; exit 2 ;;
	*) OUT="$1"; shift ;;
	esac
done
OUT="${OUT:-./kev-data}"
DEST="$OUT/kev/known_exploited_vulnerabilities.json"
say() { [ "$QUIET" = 1 ] || echo "$@"; }

# ---- portable downloader (curl or wget) ------------------------------------
DL_UA="tarpit-honeypot-kevsync"
if command -v curl >/dev/null 2>&1; then
	_dl() {
		if [ -n "${3:-}" ]; then
			curl -fsSL -A "$DL_UA" ${INSECURE:+-k} --retry 3 --connect-timeout 20 -H "$3" -o "$1" "$2"
		else
			curl -fsSL -A "$DL_UA" ${INSECURE:+-k} --retry 3 --connect-timeout 20 -o "$1" "$2"
		fi
	}
elif command -v wget >/dev/null 2>&1; then
	_dl() {
		if [ -n "${3:-}" ]; then
			wget -q -U "$DL_UA" ${INSECURE:+--no-check-certificate} --header="$3" -O "$1" "$2"
		else
			wget -q -U "$DL_UA" ${INSECURE:+--no-check-certificate} -O "$1" "$2"
		fi
	}
else
	echo "error: need curl or wget on PATH" >&2
	exit 1
fi

mkdir -p "$OUT/kev"
tmp="$DEST.tmp.$$"
say "Fetching CISA KEV → $DEST"
if ! _dl "$tmp" "$URL" "${KEV_HEADER:-}"; then
	echo "error: KEV download failed ($URL)" >&2
	rm -f "$tmp"; exit 1
fi
if [ ! -s "$tmp" ]; then echo "error: empty KEV download" >&2; rm -f "$tmp"; exit 1; fi

# Optional ICS/OT/SCADA-only filter (preserves the {catalogVersion,
# vulnerabilities:[...]} shape so the sensor loads it unchanged). Needs jq.
if [ "$ICS" = 1 ]; then
	if ! command -v jq >/dev/null 2>&1; then
		echo "error: --ics needs jq" >&2; rm -f "$tmp"; exit 1
	fi
	jq '.vulnerabilities |= map(select(
	      ([.vendorProject, .product, .vulnerabilityName, .shortDescription]
	       | join(" ") | ascii_downcase)
	      | test("scada|plc|hmi|ics|rtu|modbus|dnp3|iec ?6185|bacnet|profinet|ethernet/ip|opc|siemens|schneider|rockwell|allen.bradley|advantech|moxa|codesys|wago|omron|mitsubishi|ge |honeywell|emerson|yokogawa|wonderware|ignition|iconics|unitronics|openplc|tridium|niagara|delta electronics|phoenix contact|hitachi energy")
	    )) | .count = (.vulnerabilities | length)' "$tmp" >"$tmp.x" 2>/dev/null || {
		echo "error: jq filter failed" >&2; rm -f "$tmp" "$tmp.x"; exit 1; }
	mv "$tmp.x" "$tmp"
fi

mv "$tmp" "$DEST"
# Count entries (jq if present, else a cheap grep of cveID occurrences).
if command -v jq >/dev/null 2>&1; then
	n=$(jq '.vulnerabilities | length' "$DEST" 2>/dev/null || echo "?")
else
	n=$(grep -oc '"cveID"' "$DEST" 2>/dev/null || echo "?")
fi
sz=$(wc -c <"$DEST" | tr -d ' ')
say "  ok: $n entries, ${sz} bytes${ICS:+ (ICS-filtered)}"
[ "$ICS" = 1 ] && say "  (ICS/OT filter applied)"

# ---- same-host install -----------------------------------------------------
if [ "$INSTALL" = 1 ]; then
	HERE="$(cd "$(dirname "$0")" && pwd)"
	if [ -z "$BIN" ]; then
		if command -v tarpit-honeypot >/dev/null 2>&1; then BIN="tarpit-honeypot"; else
			for c in "$HERE/../bin/tarpit-honeypot" "/usr/local/bin/tarpit-honeypot" "/usr/bin/tarpit-honeypot"; do
				[ -x "$c" ] && { BIN="$c"; break; }
			done
		fi
	fi
	if [ -z "$BIN" ]; then
		echo "warning: --install: no tarpit-honeypot binary found to resolve kev.file" >&2
		echo "         set kev.file in $CONFIG and copy $DEST there manually." >&2
		exit 1
	fi
	# Resolve the configured kev.file path from the sensor's own view.
	kevpath="$("$BIN" list-paths -c "$CONFIG" 2>/dev/null | awk -F'\t' '$2=="kev.file"{print $NF}' | head -n1 || true)"
	if [ -z "$kevpath" ]; then
		echo "warning: kev.file is not set in $CONFIG — add it (kev.file: /etc/tarpit-honeypot/enrichment/kev/known_exploited_vulnerabilities.json) and re-run." >&2
		exit 1
	fi
	mkdir -p "$(dirname "$kevpath")"
	cp "$DEST" "$kevpath.tmp.$$" && mv "$kevpath.tmp.$$" "$kevpath"
	say "Installed → $kevpath"
	if [ -n "$RELOAD_CMD" ]; then
		say "Reload: $RELOAD_CMD"; eval "$RELOAD_CMD"
	elif command -v pkill >/dev/null 2>&1 && pkill -HUP -x tarpit-honeypot 2>/dev/null; then
		say "Sent SIGHUP to tarpit-honeypot (it reloads kev.file)."
	else
		say "Send SIGHUP to the sensor (or use --reload-cmd) to apply."
	fi
	exit 0
fi

# ---- air-gapped guidance + gap-scan hint -----------------------------------
say
say "Transfer + load on the sensor:"
say "  scp '$DEST' sensor:/etc/tarpit-honeypot/enrichment/kev/"
say "  # config.yaml: kev: { enabled: true, file: /etc/tarpit-honeypot/enrichment/kev/known_exploited_vulnerabilities.json }"
say "  ssh sensor 'kill -HUP \$(pidof tarpit-honeypot)'"
say
say "See which exploited CVEs the catalog does NOT yet model:"
say "  tarpit-honeypot kev-gap --file '$DEST'"
