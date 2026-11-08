package ui

import (
	"fmt"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// protoField is one labeled request field for the event-detail protocol section.
type protoField struct {
	Label string
	Value string
}

// protoGroup is a titled set of protocol request fields (e.g. "DNS query",
// "SSH handshake"), the non-HTTP counterpart of the detail page's HTTP-request
// section.
type protoGroup struct {
	Title  string
	Fields []protoField
}

// protoFieldSpec maps a captured meta key to the human label shown for it.
type protoFieldSpec struct {
	key, label string
}

// protoSpecs defines, per (normalized) handler, the title and the ordered
// request fields to surface on the detail page. The HTTP handler keeps its own
// bespoke section in the template; these cover the other protocols the honeypot
// speaks so their captured fields read as a labeled table instead of a raw meta
// blob. Keys that aren't present on a given event are simply skipped.
var protoSpecs = map[string]struct {
	title  string
	fields []protoFieldSpec
}{
	"dns": {"DNS query", []protoFieldSpec{
		{"qname", "query name"}, {"qtype_name", "query type"}, {"qtype", "type code"},
		{"dns_queries", "all queries"}, {"zone_transfer_served", "AXFR zone transfer served"},
		{"malformed_dns", "malformed packet"},
	}},
	"ssh": {"SSH handshake & client", []protoFieldSpec{
		{"client_id", "client banner"}, {"ssh_client_openssh_version", "OpenSSH version"},
		{"hassh", "HASSH"}, {"ssh_kex_negotiated", "negotiated KEX"},
		{"ssh_kex_ciphers_c2s", "ciphers (c→s)"}, {"ssh_kex_macs_c2s", "MACs (c→s)"},
		{"ssh_kex_hostkeys", "host-key algs"}, {"ssh_subsystem", "subsystem"},
		{"max_password_len", "max password length"}, {"accepted_user", "accepted login"},
	}},
	"smtp": {"SMTP envelope", []protoFieldSpec{
		{"helo", "HELO/EHLO"}, {"mail_from", "MAIL FROM"}, {"rcpt_to", "RCPT TO"},
		{"mail_header_from", "header From"}, {"mail_subject", "subject"},
		{"vrfy_user", "VRFY user"}, {"expn_list", "EXPN list"}, {"starttls", "STARTTLS"},
	}},
	"snmp": {"SNMP request", []protoFieldSpec{
		{"snmp_version", "version"}, {"community", "community"}, {"snmp_pdu", "PDU type"},
		{"varbind_oids", "requested OIDs"}, {"snmp_set", "SET write"},
		{"snmp_v3_user", "v3 user"}, {"trap_type", "trap type"},
		{"snmp_default_community", "default community"},
	}},
	"ntp": {"NTP request", []protoFieldSpec{
		{"ntp_request", "request"}, {"ntp_impl", "mode-7 implementation"},
		{"ntp_request_code", "mode-7 request code"}, {"ntp_control", "mode-6 control"},
		{"ntp_control_opcode", "mode-6 opcode"}, {"ntp_authenticated", "authenticated"},
	}},
	"rdp": {"RDP client", []protoFieldSpec{
		{"cookie", "mstshash cookie"}, {"username", "username"}, {"ntlm_user", "NTLM user"},
		{"ntlm_domain", "NTLM domain"}, {"nla", "NLA/CredSSP"}, {"tls_version", "TLS version"},
	}},
	"ftp": {"FTP session", []protoFieldSpec{
		{"user", "username"}, {"pass", "password"}, {"ftp_upload_name", "uploaded file"},
		{"ftp_upload_size", "upload size"}, {"ftp_upload_sha256", "upload sha256"},
		{"ftp_bounce_target", "FXP/bounce target"}, {"retrieved", "retrieved file"},
		{"authed", "authenticated"},
	}},
	"telnet": {"Telnet session", []protoFieldSpec{
		{"user_attempt", "username"}, {"pass_attempt", "password"},
		{"terminal_type", "terminal type"}, {"terminal_speed", "terminal speed"},
		{"window_size", "window size"}, {"accepted_user", "accepted login"},
	}},
}

// normalizeHandlerForProto folds TLS / variant handler names onto the base
// protocol whose field spec applies.
func normalizeHandlerForProto(h string) string {
	switch h {
	case "dns_tcp":
		return "dns"
	case "ssh_interactive":
		return "ssh"
	case "smtp_recv", "smtps", "submission":
		return "smtp"
	case "ftps":
		return "ftp"
	}
	return h
}

// protocolDetailKeys is every meta key surfaced by protocolFields, so the
// catch-all meta table drops them (they already show in a labeled section).
var protocolDetailKeys = func() map[string]bool {
	m := map[string]bool{}
	for _, spec := range protoSpecs {
		for _, f := range spec.fields {
			m[f.key] = true
		}
	}
	return m
}()

// protocolFields returns the labeled request-field groups for a non-HTTP event,
// the counterpart of the detail page's HTTP-request section. It is empty for
// handlers without a spec (their fields stay in the generic meta table) and for
// any field not captured on this event.
func protocolFields(ev *event.Event) []protoGroup {
	if ev == nil || ev.Meta == nil {
		return nil
	}
	spec, ok := protoSpecs[normalizeHandlerForProto(ev.Handler)]
	if !ok {
		return nil
	}
	var fields []protoField
	for _, f := range spec.fields {
		if v := metaDisplay(ev.Meta, f.key); v != "" {
			fields = append(fields, protoField{Label: f.label, Value: v})
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return []protoGroup{{Title: spec.title, Fields: fields}}
}

// metaDisplay renders one meta value as a single display string: scalars via
// %v, string/any slices joined, "" when absent or empty. Long values are clipped
// so a stray large field can't blow out the table.
func metaDisplay(meta map[string]any, key string) string {
	v, ok := meta[key]
	if !ok || v == nil {
		return ""
	}
	var s string
	switch t := v.(type) {
	case string:
		s = t
	case []string:
		s = strings.Join(t, ", ")
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, fmt.Sprintf("%v", e))
		}
		s = strings.Join(parts, ", ")
	case bool:
		if !t {
			return ""
		}
		s = "yes"
	default:
		s = fmt.Sprintf("%v", t)
	}
	s = strings.TrimSpace(s)
	if len(s) > 2048 {
		s = s[:2048] + "…"
	}
	return s
}

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
