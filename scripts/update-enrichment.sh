#!/usr/bin/env bash
#
# update-enrichment.sh — one-shot "refresh the enrichment data" entry point for
# a SAME-HOST sensor with internet access. Designed to be run unattended by
# cron or a systemd timer: it fetches the latest databases/feeds into a stable
# spool directory and installs them into the live config, under a lock, with
# all output going to a log.
#
# It is just a thin, robust wrapper around fetch-enrichment.sh --install.
#
# Usage:
#   update-enrichment.sh [-c CONFIG] [--reload-cmd CMD] [--spool DIR] [--log FILE]
#   -c CONFIG       sensor config (default /etc/tarpit-honeypot/config.yaml)
#   --reload-cmd C  how to reload the sensor (default: "systemctl reload tarpit-honeypot"
#                   if systemd is present and the unit exists, else SIGHUP)
#   --spool DIR     where to keep the working copy (default /var/lib/tarpit-honeypot/enrichment-spool)
#   --log FILE      append a run log here (default /var/log/tarpit-honeypot/enrichment.log)
#   -h, --help      this help
#
# Environment passthrough: MAXMIND_LICENSE_KEY, SKIP_GEOIP, INSECURE.
#
# Cron example (root):  17 4 * * *  /usr/local/share/tarpit-honeypot/scripts/update-enrichment.sh
# systemd:              install tarpit-enrichment.service + .timer (see packaging/systemd/).

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CONFIG="/etc/tarpit-honeypot/config.yaml"
RELOAD_CMD=""
SPOOL="/var/lib/tarpit-honeypot/enrichment-spool"
LOG="/var/log/tarpit-honeypot/enrichment.log"

while [ $# -gt 0 ]; do
	case "$1" in
	-c) CONFIG="$2"; shift 2 ;;
	--reload-cmd) RELOAD_CMD="$2"; shift 2 ;;
	--spool) SPOOL="$2"; shift 2 ;;
	--log) LOG="$2"; shift 2 ;;
	-h | --help) sed -n '2,23p' "$0"; exit 0 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

mkdir -p "$SPOOL" "$(dirname "$LOG")"

# Default reload: prefer systemd if the unit exists, else SIGHUP the process.
if [ -z "$RELOAD_CMD" ]; then
	if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^tarpit-honeypot\.service'; then
		RELOAD_CMD="systemctl reload-or-restart tarpit-honeypot"
	else
		RELOAD_CMD="pkill -HUP -x tarpit-honeypot"
	fi
fi

run() {
	local rc=0
	echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) update-enrichment start (config=$CONFIG) ==="
	# Fetch + install + reload in one step; quiet so the log stays readable.
	# Don't let a single down feed mirror abort the run under set -e.
	"$HERE/fetch-enrichment.sh" --install -c "$CONFIG" --reload-cmd "$RELOAD_CMD" -q "$SPOOL" || rc=$?
	echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) update-enrichment done (rc=$rc) ==="
	return $rc
}

# Serialize with flock so an overlapping timer/cron run can't race; fall back to
# a plain run if flock is unavailable.
LOCK="$SPOOL/.update.lock"
if command -v flock >/dev/null 2>&1; then
	exec 9>"$LOCK"
	if ! flock -n 9; then
		echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) another update-enrichment run holds the lock; skipping" >>"$LOG"
		exit 0
	fi
	run >>"$LOG" 2>&1
else
	run >>"$LOG" 2>&1
fi
