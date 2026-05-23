#!/usr/bin/env bash
#
# fetch-enrichment.sh — download the enrichment databases tarpit-honeypot can
# consume (Tor exit list, IP-reputation feeds, GeoIP/ASN, IEEE MAC-vendor OUI)
# into a local directory, so they can be transferred to an air-gapped or
# restricted-egress sensor and loaded from disk.
#
# This is a STANDALONE operator tool: run it on an internet-connected machine
# (not the sensor). It needs only bash + curl-or-wget (+ tar/gunzip for the
# GeoIP archives). Then copy the output directory to the sensor and point the
# config at the files (a ready-to-paste snippet is printed at the end).
#
# Usage:
#   scripts/fetch-enrichment.sh [OUTPUT_DIR]
#     OUTPUT_DIR  where to write the databases (default: ./enrichment-data)
#
# Environment:
#   MAXMIND_LICENSE_KEY  if set, GeoLite2 City+ASN are fetched from MaxMind;
#                        otherwise the no-key DB-IP "lite" .mmdb files are used
#                        (same MaxMind-DB format, readable by the sensor).
#   SKIP_GEOIP=1         skip the (large) GeoIP downloads
#   INSECURE=1           pass -k/--no-check-certificate (not recommended)
#
# Nothing here is sensor-specific; every file is a public feed. Re-run on a
# schedule (cron) to keep the databases fresh, then re-sync to the sensor.

set -euo pipefail

OUT="${1:-./enrichment-data}"
THREAT_DIR="$OUT/threat"
GEO_DIR="$OUT/geoip"
MANIFEST="$OUT/MANIFEST.txt"

# ---- tiny portable downloader (curl or wget) -------------------------------
if command -v curl >/dev/null 2>&1; then
	_dl() { curl -fsSL ${INSECURE:+-k} --retry 3 --connect-timeout 20 -o "$1" "$2"; }
elif command -v wget >/dev/null 2>&1; then
	_dl() { wget -q ${INSECURE:+--no-check-certificate} -O "$1" "$2"; }
else
	echo "error: need curl or wget on PATH" >&2
	exit 1
fi

ok=0
fail=0

# fetch <label> <url> <dest> [--gz]
# Downloads to a temp file, optionally gunzips, and moves into place only on
# success so a failed/partial feed never overwrites a good copy.
fetch() {
	local label="$1" url="$2" dest="$3" gz="${4:-}"
	local tmp="$dest.tmp.$$"
	printf '  %-22s ' "$label"
	if ! _dl "$tmp" "$url" 2>/dev/null; then
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

mkdir -p "$OUT" "$THREAT_DIR" "$GEO_DIR"
: >"$MANIFEST"
echo "tarpit-honeypot enrichment fetch — $(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$MANIFEST"

echo "Fetching into $OUT"

echo "[tor]"
fetch "tor-exit-nodes" "https://check.torproject.org/torbulkexitlist" "$OUT/tor-exits.txt" || true

echo "[mac-oui]"
fetch "ieee-oui" "https://standards-oui.ieee.org/oui/oui.csv" "$OUT/oui.csv" || true

echo "[reputation]"
fetch "blocklist-de"   "https://lists.blocklist.de/lists/all.txt"               "$THREAT_DIR/blocklist-de.txt"   || true
fetch "abuse-ch-feodo" "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" "$THREAT_DIR/abuse-ch-feodo.txt" || true
fetch "spamhaus-drop"  "https://www.spamhaus.org/drop/drop.txt"                  "$THREAT_DIR/spamhaus-drop.txt"  || true
fetch "firehol-level1" "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" "$THREAT_DIR/firehol-level1.txt" || true

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
	echo "[geoip] skipped (SKIP_GEOIP=1)"
fi

# ---- write a suggested config snippet into the bundle ----------------------
# (The install step reads the sensor's REAL config for destinations; this is
# a starting point for a fresh sensor. File names below are the canonical
# bundle names the installer maps from.)
SNIPPET="$OUT/suggested-config.yaml"
cat >"$SNIPPET" <<'YAML'
sensor:
  oui_file: /etc/tarpit-honeypot/enrichment/oui.csv
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
	if tar -czf "$ARCHIVE" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null; then
		[ -n "$SHA" ] && $SHA "$ARCHIVE" >"$ARCHIVE.sha256" || true
	else
		echo "warning: failed to create archive $ARCHIVE" >&2
		ARCHIVE=""
	fi
fi

# ---- summary ---------------------------------------------------------------
echo
echo "Done: $ok ok, $fail failed."
echo "  bundle dir : $OUT"
echo "  manifest   : $MANIFEST"
echo "  checksums  : $OUT/SHA256SUMS"
echo "  config     : $SNIPPET"
[ -n "$ARCHIVE" ] && echo "  archive    : $ARCHIVE  (+ ${ARCHIVE}.sha256)"
echo
echo "Transfer to the sensor, then run the install/update step there:"
if [ -n "$ARCHIVE" ]; then
	echo "  scp '$ARCHIVE'* sensor:/tmp/"
	echo "  ssh sensor 'tar -xzf /tmp/$(basename "$ARCHIVE") -C /tmp"
	echo "              sudo scripts/install-enrichment.sh /tmp/$(basename "${OUT%/}") -c /etc/tarpit-honeypot/config.yaml'"
else
	echo "  rsync -a '$OUT/' sensor:/tmp/$(basename "${OUT%/}")/"
	echo "  ssh sensor 'sudo scripts/install-enrichment.sh /tmp/$(basename "${OUT%/}") -c /etc/tarpit-honeypot/config.yaml'"
fi

[ "$fail" -eq 0 ]
