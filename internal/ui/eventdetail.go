package ui

import (
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// eventCommands gathers every command / query the attacker typed on an event —
// interactive-shell lines, SQL queries (mysql/postgres/mssql), Redis command
// chains, Mongo ops — into one ordered, de-duplicated list so the event-detail
// page can show "what they actually ran" as a clean sequence instead of an
// ugly map[...] blob in the generic meta table.
func eventCommands(ev *event.Event) []string {
	if ev == nil || ev.Meta == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, k := range eventCommandKeys {
		for _, c := range metaStrings(ev.Meta, k) {
			add(c)
		}
	}
	if c, _ := ev.Meta["exec_command"].(string); c != "" {
		add(c)
	}
	return out
}

// eventCommandKeys are the []string meta keys that hold attacker-typed command
// lines / queries. Kept here so both the gatherer and the meta-table excluder
// stay in sync.
var eventCommandKeys = []string{
	"shell_commands", "sql_queries", "pg_queries", "mssql_queries",
	"commands", "mongo_ops", "ldap_queries",
}

// labeledText is one named block of captured attacker content for the detail
// page (a staged payload body, a mail message, a dropper, …).
type labeledText struct {
	Label string
	Text  string
}

// eventBodies collects the larger free-text blobs an attacker transferred —
// staged payloads, mail bodies, deobfuscated droppers — so they render as
// readable blocks rather than one-line meta cells.
func eventBodies(ev *event.Event) []labeledText {
	if ev == nil || ev.Meta == nil {
		return nil
	}
	var out []labeledText
	for _, kv := range []struct{ key, label string }{
		{"redis_set_payload", "Redis staged payload (SET value)"},
		{"redis_drop_path", "Redis drop target path"},
		{"message_head", "SMTP message body"},
		{"bdat_chunk", "SMTP BDAT chunk"},
		{"deobfuscated", "Deobfuscated payload"},
		{"http_body", "HTTP request body"},
		{"post_body", "POST body"},
	} {
		if s, ok := ev.Meta[kv.key].(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, labeledText{Label: kv.label, Text: s})
		}
	}
	return out
}

// eventSecrets surfaces the attacker's OWN harvested secrets (secretscan) for
// the detail page: kind + a shape-preserving redaction, so the operator sees
// what was leaked without the full value shouting on screen.
func eventSecrets(ev *event.Event) []secretRow {
	if ev == nil || ev.Meta == nil {
		return nil
	}
	var out []secretRow
	for _, sc := range metaMapList(ev.Meta, "secrets") {
		kind, _ := sc["kind"].(string)
		val, _ := sc["value"].(string)
		if kind == "" || val == "" {
			continue
		}
		hint, _ := sc["hint"].(string)
		out = append(out, secretRow{Kind: kind, Redacted: redactSecret(val), Hint: hint})
	}
	return out
}

type secretRow struct {
	Kind     string
	Redacted string
	Hint     string
}

// redactSecret keeps a value's shape (prefix … suffix + length) so it is
// recognisable but not fully exposed in the UI.
func redactSecret(v string) string {
	if len(v) <= 10 {
		return strings.Repeat("•", len(v))
	}
	return v[:4] + "…" + v[len(v)-4:] + " (" + itoa(len(v)) + " chars)"
}
