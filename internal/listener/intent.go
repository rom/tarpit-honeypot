package listener

import (
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// deriveEventIntent sets ev.Meta["intent"] — a concise "what the attacker is
// doing" label — when a handler hasn't already set a more specific one. It runs
// at the listener (the single point where every handler's Result becomes an
// event), so the intent is authoritative: it lands in every export
// (JSON / CEF / LEEF / OCSF), in search, and in the analytics views — not just
// the per-page UI derivation. Handlers that set their own intent (DNS, SNMP,
// NTP, http, the OT protocols, mysql, …) are left untouched.
func deriveEventIntent(ev *event.Event) {
	if ev == nil || len(ev.Meta) == 0 {
		return
	}
	if v, _ := ev.Meta["intent"].(string); v != "" {
		return
	}
	if it := classifyIntent(ev); it != "" {
		ev.Meta["intent"] = it
	}
}

// classifyIntent derives a label from the event's handler category + the
// signals the handler captured. Empty when nothing meaningful can be said.
func classifyIntent(ev *event.Event) string {
	for _, a := range ev.Anomalies {
		if strings.HasPrefix(a, "cve:") {
			return "exploit attempt (" + strings.TrimPrefix(a, "cve:") + ")"
		}
	}
	m := ev.Meta
	switch intentCategory(ev.Handler) {
	case "remote":
		switch {
		case mStr(m, "exec_command") != "" || len(mStrs(m, "shell_commands")) > 0 || len(mStrs(m, "commands")) > 0 || mStr(m, "keystrokes") != "":
			return "interactive shell session"
		case mStr(m, "user_attempt") != "" || mStr(m, "auth_user") != "" || mStr(m, "accepted_user") != "" || mStr(m, "ntlm_user") != "":
			return "remote-access login attempt"
		default:
			return "remote-access probe"
		}
	case "mail":
		switch {
		case mStr(m, "mail_from") != "" || mStr(m, "rcpt_to") != "":
			return "mail send / relay attempt"
		case mStr(m, "auth_user") != "":
			return "mail login attempt"
		case len(mStrs(m, "expn_list")) > 0:
			return "mail address harvesting (EXPN/VRFY)"
		default:
			return "mail probe / banner-grab"
		}
	case "database":
		switch {
		case m["password"] != nil || m["login7_user"] != nil || mStr(m, "auth_user") != "" || mStr(m, "user") != "":
			return "database auth attempt"
		case len(mStrs(m, "commands")) > 0 || mStr(m, "mongo_command") != "" || mStr(m, "tns_command") != "":
			return "database command / query"
		default:
			return "database probe / banner-grab"
		}
	}
	return ""
}

// intentCategory maps a handler name to the coarse category used for intent
// derivation (kept in sync with the UI's serviceCategory). web is intentionally
// absent: the http handler sets its own, richer intent.
func intentCategory(handler string) string {
	switch handler {
	case "ssh", "ssh_interactive", "telnet", "rdp", "rdp_udp", "vnc", "winrm", "x11", "rlogin", "rsh", "pcanywhere", "teamviewer":
		return "remote"
	case "smtp", "smtp_recv", "smtps", "submission", "pop3", "pop3s", "imap", "imaps":
		return "mail"
	case "mysql", "postgres", "mssql", "mongodb", "redis", "elasticsearch", "oracle_tns", "cassandra", "etcd", "memcached", "memcached_udp":
		return "database"
	}
	return ""
}

func mStr(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func mStrs(m map[string]any, k string) []string {
	switch v := m[k].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
