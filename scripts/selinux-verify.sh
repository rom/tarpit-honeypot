#!/usr/bin/env bash
#
# selinux-verify.sh — diagnose why the tarpit-honeypot daemon is (not) SELinux-
# confined. Run after starting the service. It checks, in order, the things that
# make a service silently run uncontained, and prints the exact fix for the
# first one that fails:
#
#   1. SELinux enforcing?            (Disabled/Permissive can't confine)
#   2. policy module loaded?         (tarpit_honeypot)
#   3. binary labeled exec_t?        (else no domain transition)
#   4. RUNNING process domain        (THE answer: tarpit_honeypot_t vs unconfined)
#   5. recent AVC denials            (what the confined domain is being denied)
#
# Read-only: it changes nothing. Exit 0 = confined, 1 = not confined / unknown.

set -u
BIN="${1:-/usr/local/bin/tarpit-honeypot}"
UNIT="tarpit-honeypot.service"
ok()   { printf '  \033[1;32m[ok]\033[0m %s\n' "$*"; }
bad()  { printf '  \033[1;31m[!!]\033[0m %s\n' "$*"; }
note() { printf '       %s\n' "$*"; }

echo "tarpit-honeypot SELinux containment check"
echo "========================================="

# 1. enforcement mode
if ! command -v getenforce >/dev/null 2>&1; then
	bad "SELinux tools not installed — this host has no SELinux."
	exit 1
fi
mode="$(getenforce)"
case "$mode" in
	Enforcing) ok "SELinux mode: Enforcing" ;;
	Permissive) bad "SELinux mode: Permissive — policy is loaded but NOT enforced (denials are logged, not blocked)."; note "Fix: setenforce 1  (and set SELINUX=enforcing in /etc/selinux/config)" ;;
	*) bad "SELinux mode: $mode — cannot confine anything while disabled."; note "Fix: set SELINUX=enforcing in /etc/selinux/config and reboot."; exit 1 ;;
esac

# 2. module loaded
if semodule -l 2>/dev/null | grep -q '^tarpit_honeypot\b\|^tarpit_honeypot$\|tarpit_honeypot'; then
	ok "policy module 'tarpit_honeypot' is loaded"
else
	bad "policy module 'tarpit_honeypot' is NOT loaded."
	note "Fix: re-run scripts/install.sh (it builds + installs the module), or:"
	note "     cd packaging/selinux && make && sudo semodule -i tarpit_honeypot.pp"
	exit 1
fi

# 3. binary label
if command -v stat >/dev/null 2>&1; then
	lbl="$(stat -c '%C' "$BIN" 2>/dev/null)"
	case "$lbl" in
		*:tarpit_honeypot_exec_t:*) ok "binary labeled: $lbl" ;;
		"") bad "cannot stat $BIN (wrong path? pass it as \$1)" ; exit 1 ;;
		*) bad "binary mislabeled: $lbl (want tarpit_honeypot_exec_t)"
		   note "Fix: sudo semanage fcontext -d '$BIN' 2>/dev/null; sudo restorecon -Fv '$BIN'; sudo systemctl restart $UNIT" ; exit 1 ;;
	esac
fi

# 4. RUNNING process domain — the actual answer
pid="$(systemctl show -p MainPID --value "$UNIT" 2>/dev/null)"
if [ -z "$pid" ] || [ "$pid" = "0" ]; then
	bad "$UNIT is not running — start it first: sudo systemctl start $UNIT"
	exit 1
fi
run="$(tr -d '\0' < /proc/$pid/attr/current 2>/dev/null)"
[ -z "$run" ] && run="$(ps -o label= -p "$pid" 2>/dev/null | tr -d ' ')"
case "$run" in
	*:tarpit_honeypot_t:*)
		ok "running domain (pid $pid): $run"
		echo
		echo "CONFINED ✓ — the daemon is running in tarpit_honeypot_t."
		exit 0 ;;
	*unconfined_service_t*|*:init_t:*)
		bad "running domain (pid $pid): $run — UNCONFINED."
		note "Most likely cause: NoNewPrivileges=yes blocks the domain transition and"
		note "this selinux-policy lacks init_nnp_daemon_domain (process2:nnp_transition)."
		note "Fix A (recommended): re-run scripts/install.sh — it now drops"
		note "  NoNewPrivileges from the unit when the interface is missing."
		note "Fix B (manual): add 'NoNewPrivileges=no' to a drop-in"
		note "  (systemctl edit $UNIT), daemon-reload, restart."
		note "Then re-check; if still wrong, see the AVC denials below." ;;
	"") bad "could not read the running domain for pid $pid (no SELinux label)." ;;
	*)  bad "running domain (pid $pid): $run — not tarpit_honeypot_t." ;;
esac

# 5. recent denials (informational)
echo
echo "recent AVC denials (last 10 min), if any:"
if command -v ausearch >/dev/null 2>&1; then
	ausearch -m avc,user_avc -ts recent 2>/dev/null | grep -i tarpit | tail -20 || note "(none found via ausearch)"
else
	journalctl -t setroubleshoot -t audit --since "-10 min" 2>/dev/null | grep -i tarpit | tail -20 || note "(auditd/ausearch not available)"
fi
exit 1
