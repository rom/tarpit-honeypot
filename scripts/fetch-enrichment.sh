#!/usr/bin/env bash
#
# fetch-enrichment.sh — download the enrichment databases tarpit-honeypot can
# consume into a local directory, so they can be transferred to an air-gapped
# or restricted-egress sensor and loaded from disk:
#   * Tor exit list, IP-reputation feeds, GeoIP/ASN, IEEE MAC-vendor OUI
#   * extra no-auth reputation feeds: IPsum (aggregate), Emerging Threats
#     compromised-ips, CINS Army, SANS ISC DShield — the more lists an IP is on,
#     the higher the sensor's threat_confidence for it
#   * cloud-provider IP ranges (AWS / GCP / Cloudflare / DigitalOcean)
#   * abuse.ch malware hashes (ThreatFox + MalwareBazaar, with family) + URLhaus
#     — these REQUIRE a free ABUSE_CH_AUTH_KEY since 2025-06-30 (see below);
#     without one they are skipped, not failed
#   * FoxIO JA4DB (fingerprint -> client/tool attribution; needs jq)
#
# It can run two ways:
#   * AIR-GAPPED  — run on an internet-connected machine that is NOT the sensor,
#                   then copy the printed bundle/archive to the sensor and run
#                   install-enrichment.sh there.
#   * SAME HOST   — run on a sensor that HAS internet access with `--install`,
#                   and it fetches + installs + reloads in one step (no archive,
#                   no transfer). This is the common single-box case; pair it
#                   with scripts/update-enrichment.sh for a cron / systemd timer.
# It needs only bash + curl-or-wget (+ tar/gunzip for the GeoIP archives).
#
# Usage:
#   scripts/fetch-enrichment.sh [OPTIONS] [OUTPUT_DIR]
#     OUTPUT_DIR        where to write the databases (default: ./enrichment-data)
#   -i, --install       after fetching, install into THIS host's sensor config
#                       (runs install-enrichment.sh; implies --no-archive)
#   -c, --config PATH   sensor config for --install (default /etc/tarpit-honeypot/config.yaml)
#       --bin PATH      tarpit-honeypot binary for --install (auto-detected:
#                       PATH, ../bin, /usr/local/bin, /usr/bin)
#       --reload-cmd C  reload command passed to --install (e.g. "systemctl reload tarpit-honeypot")
#   -q, --quiet         terse output (cron/timer friendly)
#   -h, --help          this help
#
# Environment:
#   MAXMIND_LICENSE_KEY  if set, GeoLite2 City+ASN are fetched from MaxMind;
#                        otherwise the no-key DB-IP "lite" .mmdb files are used
#                        (same MaxMind-DB format, readable by the sensor).
#   ABUSE_CH_AUTH_KEY    abuse.ch Auth-Key, REQUIRED since 2025-06-30 for the
#                        ThreatFox / MalwareBazaar / URLhaus exports (401 and
#                        "FAILED (download)" without it). Get one free at
#                        https://auth.abuse.ch/. Alternatively set it in the
#                        sensor config (-c) under sensor.enrichment:
#                          abuse_ch_auth_key: "KEY"        # inline, or
#                          abuse_ch_auth_key_env: VAR_NAME # name of an env var
#                        The env var wins, then the inline key, then the named
#                        env var. Without any of them these three feeds are
#                        skipped (not failed).
#   THREATFOX_URL /      optional overrides for the abuse.ch export URLs, in
#   MALWAREBAZAAR_URL /  case abuse.ch relocates them (e.g. to a *-api.abuse.ch
#   URLHAUS_URL          host). The Auth-Key header is sent to whatever URL.
#   JA4DB_URL            override the JA4+ fingerprint DB source (default: the
#                        FoxIO ja4plus-mapping.csv on GitHub). CSV or JSON
#                        (ja4db.com export) is auto-detected; JSON needs jq.
#   SKIP_GEOIP=1         skip the (large) GeoIP downloads
#   NO_ARCHIVE=1         don't build the single-file .tar.gz (implied by --install)
#   INSECURE=1           pass -k/--no-check-certificate (not recommended)
#
# Nothing here is sensor-specific; every file is a public feed.

# This is a bash script (uses `local`, etc.). If invoked via `sh script.sh`,
# re-exec under bash so it behaves identically regardless of how it's launched.
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi

set -euo pipefail

OUT=""
INSTALL=0
CONFIG="/etc/tarpit-honeypot/config.yaml"
RELOAD_CMD=""
BIN=""
QUIET=0
while [ $# -gt 0 ]; do
	case "$1" in
	-i | --install) INSTALL=1; export NO_ARCHIVE=1; shift ;;
	-c | --config) CONFIG="$2"; shift 2 ;;
	--bin) BIN="$2"; shift 2 ;;
	--reload-cmd) RELOAD_CMD="$2"; shift 2 ;;
	-q | --quiet) QUIET=1; shift ;;
	-h | --help) sed -n '2,62p' "$0"; exit 0 ;;
	-*) echo "unknown option: $1" >&2; exit 2 ;;
	*) OUT="$1"; shift ;;
	esac
done
OUT="${OUT:-./enrichment-data}"

# resolve_abuse_key <config> — the abuse.ch Auth-Key, resolved in order from:
#   1. the ABUSE_CH_AUTH_KEY environment variable,
#   2. an inline `sensor.enrichment.abuse_ch_auth_key` in the sensor config, or
#   3. the env var named by `sensor.enrichment.abuse_ch_auth_key_env`.
# So the key can live in the config file (passed with -c, default
# /etc/tarpit-honeypot/config.yaml) instead of an env var — convenient for the
# single-box `--install` run where the config is already present. Always
# succeeds (prints nothing when no key is configured).
resolve_abuse_key() {
	if [ -n "${ABUSE_CH_AUTH_KEY:-}" ]; then printf '%s' "$ABUSE_CH_AUTH_KEY"; return 0; fi
	local cfg="$1" v name
	[ -f "$cfg" ] || return 0
	v="$(sed -nE 's/^[[:space:]]*abuse_ch_auth_key:[[:space:]]*"?([^"#[:space:]]+)"?.*/\1/p' "$cfg" | head -n1 || true)"
	if [ -n "$v" ]; then printf '%s' "$v"; return 0; fi
	name="$(sed -nE 's/^[[:space:]]*abuse_ch_auth_key_env:[[:space:]]*"?([^"#[:space:]]+)"?.*/\1/p' "$cfg" | head -n1 || true)"
	[ -n "$name" ] && printf '%s' "${!name:-}"
	return 0
}
ABUSE_KEY="$(resolve_abuse_key "$CONFIG")" # abuse.ch Auth-Key: env var, else sensor config (-c)
say() { [ "$QUIET" = 1 ] || echo "$@"; }
THREAT_DIR="$OUT/threat"
GEO_DIR="$OUT/geoip"
CLOUD_DIR="$OUT/cloud"
FP_DIR="$OUT/fingerprints"
MAL_DIR="$OUT/malware"
MANIFEST="$OUT/MANIFEST.txt"

# ---- tiny portable downloader (curl or wget) -------------------------------
# _dl <dest> <url> [extra_header] — a 3rd arg sends one request header (e.g.
# "Auth-Key: ..."). A browser-ish User-Agent avoids UA-based blocking (ja4db).
DL_UA="Mozilla/5.0 (X11; Linux x86_64) tarpit-honeypot-enrichment"
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

ok=0
fail=0
skip=0

# skip_feed <label> <reason> — record a source we deliberately did NOT fetch
# (e.g. one that now needs an API key we weren't given). Not counted as a
# failure, so the summary and the script's exit status stay clean for the
# expected "no key configured" case.
skip_feed() {
	printf '  %-22s skipped (%s)\n' "$1" "$2"
	skip=$((skip + 1))
}

# fetch <label> <url> <dest> [--gz] [header]
# Downloads to a temp file, optionally gunzips, and moves into place only on
# success so a failed/partial feed never overwrites a good copy. The optional
# 5th arg is a single request header (e.g. "Auth-Key: ...").
fetch() {
	local label="$1" url="$2" dest="$3" gz="${4:-}" hdr="${5:-}"
	local tmp="$dest.tmp.$$"
	printf '  %-22s ' "$label"
	if ! _dl "$tmp" "$url" "$hdr" 2>/dev/null; then
		echo "FAILED (download)"
		rm -f "$tmp"
		fail=$((fail + 1))
		return 1
	fi
	if [ "$gz" = "--gz" ]; then
		if ! gunzip -c "$tmp" >"$tmp.x" 2>/dev/null; then
			echo "FAILED (gunzip)"
			rm -f "$tmp" "$tmp.x"
			fail=$((fail + 1))
			return 1
		fi
		mv "$tmp.x" "$tmp"
	fi
	if [ ! -s "$tmp" ]; then
		echo "FAILED (empty)"
		rm -f "$tmp"
		fail=$((fail + 1))
		return 1
	fi
	mv "$tmp" "$dest"
	local sz
	sz=$(wc -c <"$dest" | tr -d ' ')
	echo "ok (${sz} bytes)"
	echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  $label  $url  ${sz}B  $dest" >>"$MANIFEST"
	ok=$((ok + 1))
	return 0
}

# prev_month prints YYYY-MM for last month (GNU date or BSD/macOS date).
prev_month() {
	date -u -d 'last month' +%Y-%m 2>/dev/null || date -u -v-1m +%Y-%m 2>/dev/null || true
}

# fetch_dbip <city|asn> <dest> — no-key DB-IP "lite" .mmdb (MaxMind-DB format).
# Tries the current month, then last month (early-in-month fallback).
fetch_dbip() {
	local kind="$1" dest="$2" base="https://download.db-ip.com/free"
	local tmp="$dest.tmp.$$" m url sz
	printf '  %-22s ' "dbip-$kind"
	for m in "$(date -u +%Y-%m)" "$(prev_month)"; do
		[ -n "$m" ] || continue
		url="$base/dbip-$kind-lite-$m.mmdb.gz"
		if _dl "$tmp.gz" "$url" 2>/dev/null && gunzip -c "$tmp.gz" >"$tmp" 2>/dev/null && [ -s "$tmp" ]; then
			mv "$tmp" "$dest"
			rm -f "$tmp.gz"
			sz=$(wc -c <"$dest" | tr -d ' ')
			echo "ok (${sz} bytes, $m)"
			echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  dbip-$kind  $url  ${sz}B  $dest" >>"$MANIFEST"
			ok=$((ok + 1))
			return 0
		fi
		rm -f "$tmp" "$tmp.gz"
	done
	echo "FAILED"
	fail=$((fail + 1))
	return 1
}

# fetch_maxmind <edition_id> <dest> — GeoLite2 via a MaxMind license key.
fetch_maxmind() {
	local edition="$1" dest="$2"
	local url="https://download.maxmind.com/app/geoip_download?edition_id=$edition&license_key=$MAXMIND_LICENSE_KEY&suffix=tar.gz"
	local tmp="$dest.tar.gz.$$" dir="$dest.x.$$" mmdb sz
	printf '  %-22s ' "maxmind-$edition"
	if ! _dl "$tmp" "$url" 2>/dev/null; then
		echo "FAILED (download — check key)"
		rm -f "$tmp"
		fail=$((fail + 1))
		return 1
	fi
	mkdir -p "$dir"
	if ! tar -xzf "$tmp" -C "$dir" 2>/dev/null; then
		echo "FAILED (extract)"
		rm -rf "$tmp" "$dir"
		fail=$((fail + 1))
		return 1
	fi
	mmdb=$(find "$dir" -name '*.mmdb' 2>/dev/null | head -1 || true)
	if [ -z "$mmdb" ] || [ ! -s "$mmdb" ]; then
		echo "FAILED (no mmdb)"
		rm -rf "$tmp" "$dir"
		fail=$((fail + 1))
		return 1
	fi
	mv "$mmdb" "$dest"
	rm -rf "$tmp" "$dir"
	sz=$(wc -c <"$dest" | tr -d ' ')
	echo "ok (${sz} bytes)"
	echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  maxmind-$edition  (license key)  ${sz}B  $dest" >>"$MANIFEST"
	ok=$((ok + 1))
	return 0
}

# fetch_cloud <provider> <url> <json_field> — download a cloud provider's
# range file and extract CIDRs (one per line) into $CLOUD_DIR/<provider>.txt.
# json_field is the JSON key holding a prefix ("" for a plain-text list).
fetch_cloud() {
	local prov="$1" url="$2" field="${3:-}"
	local dest="$CLOUD_DIR/$prov.txt"
	local tmp="$dest.tmp.$$" sz
	printf '  %-22s ' "$prov"
	if ! _dl "$tmp" "$url" 2>/dev/null || [ ! -s "$tmp" ]; then
		echo "FAILED (download)"; rm -f "$tmp"; fail=$((fail + 1)); return 1
	fi
	if [ -n "$field" ]; then
		# Extract "field": "<cidr>" values (IPv4 + IPv6), no jq needed.
		grep -oE "\"$field\"[[:space:]]*:[[:space:]]*\"[^\"]+\"" "$tmp" \
			| grep -oE '[0-9a-fA-F:.]+/[0-9]+' >"$tmp.x" 2>/dev/null || true
		mv "$tmp.x" "$tmp"
	else
		# Plain-text list: keep CIDR-looking lines only.
		grep -oE '^[0-9a-fA-F:.]+/[0-9]+' "$tmp" >"$tmp.x" 2>/dev/null || true
		mv "$tmp.x" "$tmp"
	fi
	if [ ! -s "$tmp" ]; then echo "FAILED (no cidrs)"; rm -f "$tmp"; fail=$((fail + 1)); return 1; fi
	mv "$tmp" "$dest"
	sz=$(wc -l <"$dest" | tr -d ' ')
	echo "ok (${sz} prefixes)"
	echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  cloud-$prov  $url  ${sz} prefixes  $dest" >>"$MANIFEST"
	ok=$((ok + 1)); return 0
}

# fetch_abuse_csv <label> <url> <dest> — download an abuse.ch CSV (ThreatFox /
# MalwareBazaar) and emit "sha256[,family]" lines. Extraction is separator-
# agnostic (the CSVs vary between ',' and ', '): grep the sha256 hashes, and
# pair each with a malware family on the same line when one is present (the
# abuse.ch "platform.name" convention, e.g. win.agent_tesla). An optional
# ABUSE_CH_AUTH_KEY env var is sent as the Auth-Key header (some exports now
# require it).
fetch_abuse_csv() {
	local label="$1" url="$2" dest="$3"
	local tmp="$dest.tmp.$$" sz
	printf '  %-22s ' "$label"
	if ! _dl "$tmp" "$url" "${ABUSE_KEY:+Auth-Key: $ABUSE_KEY}" 2>/dev/null || [ ! -s "$tmp" ]; then
		echo "FAILED (download)"; rm -f "$tmp"; fail=$((fail + 1)); return 1
	fi
	# Per line: extract the sha256 + a same-line family token (best effort).
	awk '
		/^#/ { next }
		{
			line = $0; h = ""
			if (match(line, /[a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]/)) {
				h = tolower(substr(line, RSTART, 64))
				fam = ""
				if (match(line, /(win|elf|osx|apk|js|vbs|ps1|jar|doc|xls|py|sh|other)\.[a-z0-9_.]+/)) fam = substr(line, RSTART, RLENGTH)
				print h (fam != "" ? "," fam : "")
			}
		}
	' "$tmp" | sort -u >"$tmp.x" 2>/dev/null || true
	# Fallback: bare sha256 via grep if awk found nothing.
	if [ ! -s "$tmp.x" ]; then
		grep -oiE '[a-f0-9]{64}' "$tmp" 2>/dev/null | tr 'A-F' 'a-f' | sort -u >"$tmp.x" || true
	fi
	mv "$tmp.x" "$tmp"
	if [ ! -s "$tmp" ]; then
		if [ -z "${ABUSE_KEY:-}" ]; then
			echo "FAILED (no hashes — abuse.ch may require ABUSE_CH_AUTH_KEY)"
		else
			echo "FAILED (no hashes)"
		fi
		rm -f "$tmp"; fail=$((fail + 1)); return 1
	fi
	mv "$tmp" "$dest"
	sz=$(wc -l <"$dest" | tr -d ' ')
	echo "ok (${sz} hashes)"
	echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  $label  $url  ${sz} hashes  $dest" >>"$MANIFEST"
	ok=$((ok + 1)); return 0
}

# fetch_dshield — SANS ISC recommended block list. Its native format is
# "startIP<TAB>endIP<TAB>netmask ...", so convert each row to a start/netmask
# CIDR that the enricher's IP-list loader consumes like any other reputation
# list. No auth required.
fetch_dshield() {
	local url="https://feeds.dshield.org/block.txt" dest="$THREAT_DIR/dshield.txt"
	local tmp="$dest.tmp.$$" sz
	printf '  %-22s ' "dshield"
	if ! _dl "$tmp" "$url" 2>/dev/null || [ ! -s "$tmp" ]; then
		echo "FAILED (download)"; rm -f "$tmp"; fail=$((fail + 1)); return 1
	fi
	awk -F'\t' '!/^#/ && NF>=3 && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $1"/"$3 }' \
		"$tmp" | sort -u >"$tmp.x" 2>/dev/null || true
	mv "$tmp.x" "$tmp"
	if [ ! -s "$tmp" ]; then echo "FAILED (no cidrs)"; rm -f "$tmp"; fail=$((fail + 1)); return 1; fi
	mv "$tmp" "$dest"
	sz=$(wc -l <"$dest" | tr -d ' ')
	echo "ok (${sz} prefixes)"
	echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  dshield  $url  ${sz} prefixes  $dest" >>"$MANIFEST"
	ok=$((ok + 1)); return 0
}

# fetch_ja4db — download a FoxIO JA4+ database and emit normalized
# "fingerprint,label" files per kind (ja4 + ja4h, which the enricher consumes).
#
# Source is $JA4DB_URL (default: FoxIO's ja4plus-mapping.csv on GitHub — plain
# CSV, no jq, reachable). Override it to point at a larger DB, e.g. the full
# ja4db.com JSON export. The format is auto-detected: a payload starting with
# '{' or '[' is parsed as JA4DB JSON (needs jq); otherwise as the FoxIO CSV
#   Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes
# labeling each fingerprint with the first non-empty Application/Library/Device.
fetch_ja4db() {
	local url="${JA4DB_URL:-https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv}"
	local tmp="$FP_DIR/ja4db.$$"
	printf '  %-22s ' "foxio-ja4db"
	if ! _dl "$tmp" "$url" 2>/dev/null || [ ! -s "$tmp" ]; then
		echo "FAILED (download)"; rm -f "$tmp"; fail=$((fail + 1)); return 1
	fi
	# Sniff format from the first non-blank byte.
	local first
	first=$(tr -d ' \t\r\n' <"$tmp" | head -c1)
	if [ "$first" = "{" ] || [ "$first" = "[" ]; then
		# JA4DB JSON export (needs jq): {ja4_fingerprint, ja4h_fingerprint,
		# application/library/device, ...}.
		if ! command -v jq >/dev/null 2>&1; then
			echo "FAILED (JSON source needs jq)"; rm -f "$tmp"; fail=$((fail + 1)); return 1
		fi
		local field
		for spec in "ja4_fingerprint ja4" "ja4h_fingerprint ja4h"; do
			set -- $spec
			jq -r ".[]? | select(.$1 != null and .$1 != \"\") | \"\(.$1),\(.application // .library // .device // \"unknown\")\"" \
				"$tmp" 2>/dev/null | sort -u >"$FP_DIR/$2.txt" || true
		done
	else
		# FoxIO mapping CSV: ja4 = col 5, ja4h = col 7.
		for spec in "5 ja4" "7 ja4h"; do
			set -- $spec
			awk -F, -v col="$1" '
				NR == 1 { next }                        # header
				{ gsub(/\r/, ""); fp = $col; if (fp == "") next;
				  lab = $1; if (lab == "") lab = $2; if (lab == "") lab = $3;
				  if (lab == "") lab = "unknown";
				  print fp "," lab }
			' "$tmp" | sort -u >"$FP_DIR/$2.txt" || true
		done
	fi
	rm -f "$tmp"
	local n
	n=$(wc -l <"$FP_DIR/ja4.txt" 2>/dev/null | tr -d ' ' || echo 0)
	if [ "${n:-0}" -eq 0 ]; then
		echo "FAILED (no fingerprints parsed)"; fail=$((fail + 1)); return 1
	fi
	echo "ok (${n} ja4)"
	echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  foxio-ja4db  $url  ${n} ja4  $FP_DIR" >>"$MANIFEST"
	ok=$((ok + 1)); return 0
}

mkdir -p "$OUT" "$THREAT_DIR" "$GEO_DIR" "$CLOUD_DIR" "$FP_DIR" "$MAL_DIR"
: >"$MANIFEST"
echo "tarpit-honeypot enrichment fetch — $(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$MANIFEST"

say "Fetching into $OUT"

say "[tor]"
fetch "tor-exit-nodes" "https://check.torproject.org/torbulkexitlist" "$OUT/tor-exits.txt" || true

say "[mac-oui]"
fetch "ieee-oui" "https://standards-oui.ieee.org/oui/oui.csv" "$OUT/oui.csv" || true

say "[reputation]"
fetch "blocklist-de"   "https://lists.blocklist.de/lists/all.txt"               "$THREAT_DIR/blocklist-de.txt"   || true
fetch "abuse-ch-feodo" "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" "$THREAT_DIR/abuse-ch-feodo.txt" || true
fetch "spamhaus-drop"  "https://www.spamhaus.org/drop/drop.txt"                  "$THREAT_DIR/spamhaus-drop.txt"  || true
fetch "firehol-level1" "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" "$THREAT_DIR/firehol-level1.txt" || true

# Additional no-auth reputation feeds. These all land as ordinary threat_intel
# lists; the more independent lists an IP appears on, the higher the sensor's
# threat_confidence (threat_intel_count) for it. IPsum in particular is an
# aggregate of ~30 public blocklists, so it corroborates well with the others.
say "[reputation-extra]  (aggregated / no-auth feeds)"
fetch "ipsum"          "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt" "$THREAT_DIR/ipsum.txt"          || true
fetch "et-compromised" "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"  "$THREAT_DIR/et-compromised.txt" || true
fetch "cins-army"      "https://cinsscore.com/list/ci-badguys.txt"                          "$THREAT_DIR/cins-army.txt"      || true
fetch_dshield || true

say "[cloud-ranges]"
fetch_cloud "aws"        "https://ip-ranges.amazonaws.com/ip-ranges.json"   "ip_prefix"   || true
fetch_cloud "aws-v6"     "https://ip-ranges.amazonaws.com/ip-ranges.json"   "ipv6_prefix" || true
fetch_cloud "gcp"        "https://www.gstatic.com/ipranges/cloud.json"      "ipv4Prefix"  || true
fetch_cloud "gcp-v6"     "https://www.gstatic.com/ipranges/cloud.json"      "ipv6Prefix"  || true
fetch_cloud "cloudflare" "https://www.cloudflare.com/ips-v4"                ""            || true
fetch_cloud "digitalocean" "https://www.digitalocean.com/geo/google.csv"   ""            || true
# Merge the AWS/GCP IPv4+IPv6 halves into one file per provider.
for p in aws gcp; do
	[ -f "$CLOUD_DIR/$p.txt" ] && [ -f "$CLOUD_DIR/$p-v6.txt" ] && \
		cat "$CLOUD_DIR/$p-v6.txt" >>"$CLOUD_DIR/$p.txt" && rm -f "$CLOUD_DIR/$p-v6.txt"
done

# abuse.ch feeds (ThreatFox / MalwareBazaar / URLhaus). Since 2025-06-30 EVERY
# abuse.ch export requires a (free) account Auth-Key: unauthenticated requests
# are rejected with HTTP 401, which is exactly why these report
# "FAILED (download)" when no key is set. We send the key as the Auth-Key header
# (and fix URLhaus, which previously sent none); without a key we SKIP them —
# that is expected, not a failure. Get a free key at https://auth.abuse.ch/ and
# export ABUSE_CH_AUTH_KEY=... before running. The export URLs are overridable
# (THREATFOX_URL / MALWAREBAZAAR_URL / URLHAUS_URL) in case abuse.ch moves them.
say "[malware-hashes]  (abuse.ch — needs ABUSE_CH_AUTH_KEY since 2025-06-30)"
if [ -n "$ABUSE_KEY" ]; then
	fetch_abuse_csv "threatfox"     "${THREATFOX_URL:-https://threatfox.abuse.ch/export/csv/recent/}"     "$MAL_DIR/threatfox.txt"     || true
	fetch_abuse_csv "malwarebazaar" "${MALWAREBAZAAR_URL:-https://bazaar.abuse.ch/export/csv/recent/}"    "$MAL_DIR/malwarebazaar.txt" || true
	# URLhaus malicious URLs (reference / future host matching) — also key-gated.
	fetch "urlhaus-urls" "${URLHAUS_URL:-https://urlhaus.abuse.ch/downloads/text_recent/}" "$MAL_DIR/urlhaus-urls.txt" "" "Auth-Key: $ABUSE_KEY" || true
else
	skip_feed "threatfox"     "set ABUSE_CH_AUTH_KEY (free: https://auth.abuse.ch/)"
	skip_feed "malwarebazaar" "set ABUSE_CH_AUTH_KEY (free: https://auth.abuse.ch/)"
	skip_feed "urlhaus-urls"  "set ABUSE_CH_AUTH_KEY (free: https://auth.abuse.ch/)"
fi
# Combine whatever hash feeds succeeded into one known-malware hash set.
cat "$MAL_DIR/threatfox.txt" "$MAL_DIR/malwarebazaar.txt" 2>/dev/null | sort -u >"$MAL_DIR/known-hashes.txt" || true

say "[fingerprints]  (FoxIO JA4+ mapping — client/tool attribution)"
fetch_ja4db || true

say "[p0f]  (passive OS fingerprint signatures)"
fetch "p0f.fp" "https://raw.githubusercontent.com/p0f/p0f/master/p0f.fp" "$OUT/p0f.fp" || true

if [ "${SKIP_GEOIP:-}" != "1" ]; then
	echo "[geoip]"
	if [ -n "${MAXMIND_LICENSE_KEY:-}" ]; then
		fetch_maxmind GeoLite2-City "$GEO_DIR/city.mmdb" || true
		fetch_maxmind GeoLite2-ASN  "$GEO_DIR/asn.mmdb"  || true
	else
		echo "  (no MAXMIND_LICENSE_KEY; using no-key DB-IP lite databases)"
		fetch_dbip city "$GEO_DIR/city.mmdb" || true
		fetch_dbip asn  "$GEO_DIR/asn.mmdb"  || true
	fi
else
	say "[geoip] skipped (SKIP_GEOIP=1)"
fi

# ---- write a suggested config snippet into the bundle ----------------------
# (The install step reads the sensor's REAL config for destinations; this is
# a starting point for a fresh sensor. File names below are the canonical
# bundle names the installer maps from.)
SNIPPET="$OUT/suggested-config.yaml"
cat >"$SNIPPET" <<'YAML'
sensor:
  oui_file: /etc/tarpit-honeypot/enrichment/oui.csv
  # abuse.ch Auth-Key for the ThreatFox / MalwareBazaar / URLhaus exports
  # (free at https://auth.abuse.ch/). fetch-enrichment.sh reads it from here
  # when the ABUSE_CH_AUTH_KEY env var isn't set. Prefer abuse_ch_auth_key_env
  # (a plaintext key in config is a secret at rest).
  enrichment:
    # abuse_ch_auth_key: "YOUR-ABUSE-CH-KEY"
    abuse_ch_auth_key_env: ABUSE_CH_AUTH_KEY
  geoip:
    city_db: /etc/tarpit-honeypot/enrichment/geoip/city.mmdb
    asn_db:  /etc/tarpit-honeypot/enrichment/geoip/asn.mmdb
  tor:
    enabled: true
    exit_file: /etc/tarpit-honeypot/enrichment/tor-exits.txt
  net_class:
    enabled: true
  threat_intel:
    enabled: true
    lists:
      - { label: blocklist-de,   file: /etc/tarpit-honeypot/enrichment/threat/blocklist-de.txt }
      - { label: abuse-ch-feodo, file: /etc/tarpit-honeypot/enrichment/threat/abuse-ch-feodo.txt }
      - { label: spamhaus-drop,  file: /etc/tarpit-honeypot/enrichment/threat/spamhaus-drop.txt }
      - { label: firehol-level1, file: /etc/tarpit-honeypot/enrichment/threat/firehol-level1.txt }
      # Aggregated / no-auth feeds (added v1.1). The more of these an IP appears
      # on, the higher its threat_confidence (threat_intel_count on the event).
      - { label: ipsum,          file: /etc/tarpit-honeypot/enrichment/threat/ipsum.txt }
      - { label: et-compromised, file: /etc/tarpit-honeypot/enrichment/threat/et-compromised.txt }
      - { label: cins-army,      file: /etc/tarpit-honeypot/enrichment/threat/cins-army.txt }
      - { label: dshield,        file: /etc/tarpit-honeypot/enrichment/threat/dshield.txt }
  # Authoritative cloud-provider tagging (cloud_provider on events).
  cloud_ranges:
    enabled: true
    lists:
      - { provider: aws,          file: /etc/tarpit-honeypot/enrichment/cloud/aws.txt }
      - { provider: gcp,          file: /etc/tarpit-honeypot/enrichment/cloud/gcp.txt }
      - { provider: cloudflare,   file: /etc/tarpit-honeypot/enrichment/cloud/cloudflare.txt }
      - { provider: digitalocean, file: /etc/tarpit-honeypot/enrichment/cloud/digitalocean.txt }
  # JA3/JA4/HASSH -> client/tool attribution (<kind>_client on events).
  fingerprint_db:
    enabled: true
    sources:
      - { kind: ja4,  file: /etc/tarpit-honeypot/enrichment/fingerprints/ja4.txt }
      - { kind: ja4h, file: /etc/tarpit-honeypot/enrichment/fingerprints/ja4h.txt }
  # Static analysis of captured artifacts + known-malware hash attribution.
  payloads:
    enabled: true
    analyze: true
    yara_rules:    /etc/tarpit-honeypot/enrichment/yara          # drop .yar packs here
    malware_hashes: /etc/tarpit-honeypot/enrichment/malware/known-hashes.txt

# Passive OS fingerprinting refinement. NOTE: `sniffer` is a TOP-LEVEL key
# (not under `sensor`). Requires the AF_PACKET sniffer (Linux + CAP_NET_RAW).
sniffer:
  enabled: true
  p0f_db: /etc/tarpit-honeypot/enrichment/p0f.fp
YAML

# ---- checksums + single-file archive for easy transfer ---------------------
if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"
elif command -v shasum >/dev/null 2>&1; then SHA="shasum -a 256"
else SHA=""; fi
if [ -n "$SHA" ]; then
	(cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 $SHA >SHA256SUMS) || true
fi

ARCHIVE=""
if [ "${NO_ARCHIVE:-}" != "1" ]; then
	ARCHIVE="${OUT%/}.tar.gz"
	# Capture tar's own message (instead of discarding it) so a failure is
	# actionable. tar rc=1 is "files differ / changed while reading" — the
	# archive is still valid, so keep it with a warning; rc>=2 is fatal, so
	# drop the partial file and point at the bundle dir for a direct rsync. The
	# bundle is large (the GeoIP City DB alone is ~130 MB), so a full disk /
	# tmpfs is the usual cause of a fatal failure here.
	set +e
	tar_err="$(tar -czf "$ARCHIVE" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>&1)"; rc=$?
	set -e
	if [ "$rc" -eq 0 ]; then
		[ -n "$SHA" ] && $SHA "$ARCHIVE" >"$ARCHIVE.sha256" || true
	elif [ "$rc" -eq 1 ] && [ -s "$ARCHIVE" ]; then
		echo "warning: archive created with tar warnings (rc=1)${tar_err:+: $tar_err}" >&2
		[ -n "$SHA" ] && $SHA "$ARCHIVE" >"$ARCHIVE.sha256" || true
	else
		echo "warning: failed to create archive $ARCHIVE (tar rc=$rc)${tar_err:+: $tar_err}" >&2
		echo "         The bundle dir is complete; transfer it directly instead:" >&2
		echo "           rsync -a '$OUT/' sensor:/tmp/$(basename "${OUT%/}")/" >&2
		rm -f "$ARCHIVE"
		ARCHIVE=""
	fi
fi

# ---- summary ---------------------------------------------------------------
say
say "Done: $ok ok, $fail failed, $skip skipped."
[ "$skip" -gt 0 ] && say "  (skipped feeds need an API key — e.g. abuse.ch: set ABUSE_CH_AUTH_KEY, free at https://auth.abuse.ch/)"
say "  bundle dir : $OUT"
say "  manifest   : $MANIFEST"
say "  checksums  : $OUT/SHA256SUMS"
say "  config     : $SNIPPET"
[ -n "$ARCHIVE" ] && say "  archive    : $ARCHIVE  (+ ${ARCHIVE}.sha256)"

# ---- same-host install (--install) -----------------------------------------
# When this sensor has internet access, fetch + install in one step. Locates
# install-enrichment.sh next to this script.
if [ "$INSTALL" = 1 ]; then
	HERE="$(cd "$(dirname "$0")" && pwd)"
	INST="$HERE/install-enrichment.sh"
	if [ ! -x "$INST" ]; then
		echo "error: --install given but $INST not found/executable" >&2
		exit 1
	fi
	# Resolve the sensor binary for the install step (list-paths). sudo resets
	# PATH and a source checkout puts the binary in ../bin, so look there too;
	# forward it to the installer via --bin. --bin on our own CLI wins.
	if [ -z "$BIN" ]; then
		if command -v tarpit-honeypot >/dev/null 2>&1; then
			BIN="tarpit-honeypot"
		else
			for cand in \
				"$HERE/../bin/tarpit-honeypot" \
				"$HERE/../tarpit-honeypot" \
				"$HERE/tarpit-honeypot" \
				"./bin/tarpit-honeypot" \
				"/usr/local/bin/tarpit-honeypot" \
				"/usr/bin/tarpit-honeypot"; do
				if [ -x "$cand" ]; then BIN="$cand"; break; fi
			done
		fi
	fi
	say
	say "Installing into this host's sensor (config: $CONFIG)…"
	set -- "$OUT" -c "$CONFIG" --skip-verify
	[ -n "$BIN" ] && set -- "$@" --bin "$BIN"
	[ -n "$RELOAD_CMD" ] && set -- "$@" --reload-cmd "$RELOAD_CMD"
	"$INST" "$@"
	exit $?
fi

# ---- otherwise: print the air-gapped transfer + install guidance -----------
say
say "Transfer to the sensor, then run the install/update step there:"
if [ -n "$ARCHIVE" ]; then
	say "  scp '$ARCHIVE'* sensor:/tmp/"
	say "  ssh sensor 'tar -xzf /tmp/$(basename "$ARCHIVE") -C /tmp"
	say "              sudo scripts/install-enrichment.sh /tmp/$(basename "${OUT%/}") -c /etc/tarpit-honeypot/config.yaml'"
else
	say "  rsync -a '$OUT/' sensor:/tmp/$(basename "${OUT%/}")/"
	say "  ssh sensor 'sudo scripts/install-enrichment.sh /tmp/$(basename "${OUT%/}") -c /etc/tarpit-honeypot/config.yaml'"
fi

[ "$fail" -eq 0 ]
