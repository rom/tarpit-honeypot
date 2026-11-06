#!/usr/bin/env bash
#
# install-enrichment.sh — the "install/update step" of the enrichment workflow.
# Run this ON THE SENSOR (by hand, cron, or systemd timer) against a bundle
# produced by fetch-enrichment.sh. It:
#
#   1. (optionally) verifies the bundle's SHA256SUMS,
#   2. asks the running sensor's config where each enrichment file belongs —
#      via `tarpit-honeypot list-paths --format tsv` — so destinations always
#      match the live config, no hard-coded paths,
#   3. atomically copies each downloaded file into its configured destination,
#   4. signals the running sensor to re-read the files (SIGHUP).
#
# Usage:
#   install-enrichment.sh <BUNDLE>  [-c CONFIG] [options]
#     BUNDLE        the fetch-enrichment.sh output directory, or its .tar.gz
#   -c CONFIG       sensor config path (default /etc/tarpit-honeypot/config.yaml)
#   --bin PATH      tarpit-honeypot binary (default: $PATH, then ./bin/...)
#   --dry-run       show what would happen; change nothing
#   --no-reload     install files but don't signal the sensor
#   --reload-cmd C  run C to reload (e.g. "systemctl reload tarpit-honeypot")
#   --skip-verify   don't verify SHA256SUMS
#
# Bundle file names are the canonical ones fetch-enrichment.sh writes:
#   oui.csv, tor-exits.txt, geoip/city.mmdb, geoip/asn.mmdb, threat/<label>.txt,
#   cloud/<provider>.txt, fingerprints/<kind>.txt, malware/known-hashes.txt,
#   p0f.fp
#
# Exit status is non-zero if verification fails or nothing could be installed.

# This is a bash script. If invoked via `sh script.sh`, re-exec under bash so
# it behaves identically (POSIX sh lacks `set -o pipefail`, etc.).
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi

set -euo pipefail

BUNDLE=""
CONFIG="/etc/tarpit-honeypot/config.yaml"
BIN=""
DRYRUN=0
NO_RELOAD=0
RELOAD_CMD=""
SKIP_VERIFY=0

while [ $# -gt 0 ]; do
	case "$1" in
	-c) CONFIG="$2"; shift 2 ;;
	--bin) BIN="$2"; shift 2 ;;
	--dry-run) DRYRUN=1; shift ;;
	--no-reload) NO_RELOAD=1; shift ;;
	--reload-cmd) RELOAD_CMD="$2"; shift 2 ;;
	--skip-verify) SKIP_VERIFY=1; shift ;;
	-h | --help) sed -n '2,40p' "$0"; exit 0 ;;
	-*) echo "unknown option: $1" >&2; exit 2 ;;
	*) BUNDLE="$1"; shift ;;
	esac
done

[ -n "$BUNDLE" ] || { echo "error: BUNDLE (dir or .tar.gz) is required" >&2; exit 2; }

# Accept a tarball: extract to a temp dir and use that.
CLEANUP=""
if [ -f "$BUNDLE" ] && case "$BUNDLE" in *.tar.gz | *.tgz) true ;; *) false ;; esac; then
	tmp="$(mktemp -d)"
	CLEANUP="$tmp"
	tar -xzf "$BUNDLE" -C "$tmp"
	# the tarball wraps a single top dir
	inner="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d | head -1)"
	BUNDLE="${inner:-$tmp}"
fi
trap '[ -n "$CLEANUP" ] && rm -rf "$CLEANUP"' EXIT

[ -d "$BUNDLE" ] || { echo "error: bundle dir not found: $BUNDLE" >&2; exit 2; }

# Resolve the binary (for list-paths). Search PATH, then the repo layout
# relative to this script (scripts/ -> ../bin), the CWD, and common install
# locations — so it works from a source checkout and under sudo (which resets
# PATH). Override with --bin.
if [ -z "$BIN" ]; then
	HERE="$(cd "$(dirname "$0")" && pwd)"
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
	if [ -z "$BIN" ]; then
		echo "error: tarpit-honeypot binary not found (searched PATH, ../bin, /usr/local/bin, /usr/bin; use --bin PATH)" >&2
		exit 2
	fi
fi

# 1. Verify checksums.
if [ "$SKIP_VERIFY" != 1 ] && [ -f "$BUNDLE/SHA256SUMS" ]; then
	VERIFY=""
	if command -v sha256sum >/dev/null 2>&1; then VERIFY="sha256sum -c"
	elif command -v shasum >/dev/null 2>&1; then VERIFY="shasum -a 256 -c"; fi
	if [ -n "$VERIFY" ]; then
		echo "Verifying SHA256SUMS..."
		if ! (cd "$BUNDLE" && $VERIFY SHA256SUMS >/dev/null 2>&1); then
			echo "ERROR: checksum verification failed; refusing to install. (--skip-verify to override)" >&2
			exit 1
		fi
		echo "  checksums OK"
	fi
fi

# 2. Ask the live config where each enrichment file belongs.
echo "Reading destinations from: $BIN list-paths -c $CONFIG"
TSV="$("$BIN" list-paths -c "$CONFIG" --format tsv)"

installed=0
skipped=0
planned=0

bundle_src() { # key -> canonical bundle path (empty if not an enrichment input)
	case "$1" in
	oui_file) echo "$BUNDLE/oui.csv" ;;
	tor.exit_file) echo "$BUNDLE/tor-exits.txt" ;;
	geoip.city_db) echo "$BUNDLE/geoip/city.mmdb" ;;
	geoip.asn_db) echo "$BUNDLE/geoip/asn.mmdb" ;;
	threat_intel:*) echo "$BUNDLE/threat/${1#threat_intel:}.txt" ;;
	cloud_ranges:*) echo "$BUNDLE/cloud/${1#cloud_ranges:}.txt" ;;
	anonymizer_ranges:*) echo "$BUNDLE/anon/${1#anonymizer_ranges:}.txt" ;;
	asn_reputation:*) echo "$BUNDLE/asn/${1#asn_reputation:}.txt" ;;
	fingerprint_db:*) echo "$BUNDLE/fingerprints/${1#fingerprint_db:}.txt" ;;
	payloads.malware_hashes) echo "$BUNDLE/malware/known-hashes.txt" ;;
	cred_intel.passwords_file) echo "$BUNDLE/creds/top-passwords.txt" ;;
	domain_intel.blocklist_file) echo "$BUNDLE/domains/blocklist.txt" ;;
	asn_info.file) echo "$BUNDLE/asn/asn-info.csv" ;;
	kev.file) echo "$BUNDLE/kev/known_exploited_vulnerabilities.json" ;;
	sniffer.p0f_db) echo "$BUNDLE/p0f.fp" ;;
	*) echo "" ;;
	esac
}

echo "Installing enrichment files:"
while IFS=$'\t' read -r category key access exists path; do
	[ "$access" = "read" ] || continue # never touch sensor-written state
	src="$(bundle_src "$key")"
	[ -n "$src" ] || continue          # not an enrichment input (config/tls/etc.)
	if [ ! -f "$src" ]; then
		echo "  skip    $key  (not in bundle: $src)"
		skipped=$((skipped + 1))
		continue
	fi
	if [ "$DRYRUN" = 1 ]; then
		echo "  would   $key  $src -> $path"
		planned=$((planned + 1))
		continue
	fi
	mkdir -p "$(dirname "$path")"
	cp "$src" "$path.tmp.$$"
	mv "$path.tmp.$$" "$path"
	echo "  install $key  -> $path"
	installed=$((installed + 1))
done <<EOF
$TSV
EOF

# 3. Signal the sensor to re-read.
do_reload() {
	if [ "$NO_RELOAD" = 1 ]; then
		echo "Reload skipped (--no-reload). Send SIGHUP to the sensor to apply."
		return 0
	fi
	if [ -n "$RELOAD_CMD" ]; then
		echo "Reload: $RELOAD_CMD"
		[ "$DRYRUN" = 1 ] || eval "$RELOAD_CMD"
		return 0
	fi
	if [ "$DRYRUN" = 1 ]; then
		echo "Would signal: pkill -HUP -x tarpit-honeypot"
		return 0
	fi
	if command -v pkill >/dev/null 2>&1 && pkill -HUP -x tarpit-honeypot 2>/dev/null; then
		echo "Sent SIGHUP to tarpit-honeypot (it re-reads the enrichment files)."
		return 0
	fi
	echo "warning: no running tarpit-honeypot found to signal." >&2
	echo "         Send SIGHUP manually, use --reload-cmd, or restart the service." >&2
}

echo
if [ "$DRYRUN" = 1 ]; then
	echo "Dry run: $planned file(s) would be installed, $skipped skipped."
	do_reload
	exit 0
fi
echo "Installed $installed file(s), $skipped skipped."
if [ "$installed" -gt 0 ]; then
	do_reload
else
	echo "Nothing installed (no matching enrichment files configured)."
	echo "Configure paths (sensor.oui_file / geoip / tor / threat_intel) and re-run."
	exit 1
fi
