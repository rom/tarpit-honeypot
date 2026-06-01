// Package ioc turns the heterogeneous information the sensor already collects on
// every event — source IPs, TLS/SSH fingerprints, ASNs, DNS names, CVE ids,
// captured-payload hashes, harvested C2 URLs, credentials, MACs — into typed,
// de-duplicated indicators of compromise. The sensor records each indicator in
// the IOC store (powering the web UI's IOC tab and offline export) and, for the
// high-value types, emits a one-off ioc:<type> event the first time it's seen so
// the indicator is stored locally and forwarded to aggregators like any event.
package ioc

import (
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Indicator is one typed IOC extracted from an event.
type Indicator struct {
	Type  string // ip | sha256 | url | domain | ja3 | ja4 | ja4h | ja4t | hassh | ssh-key | ssh-client | user-agent | email | cve | asn | credential | mac
	Value string
}

// DefaultEmitTypes are the high-value indicator types whose first sighting emits
// a stored+forwarded ioc:<type> event. Bare IPs / ASNs / MACs / OS-level TCP
// fingerprints / User-Agents / SSH client strings / sender emails are tracked
// in the store but not emitted (too voluminous, and already on every event).
var DefaultEmitTypes = []string{"sha256", "url", "domain", "ja3", "ja4", "ja4h", "hassh", "ssh-key", "cve", "credential"}

// knownTypes is the set of indicator types the sensor itself produces; we
// refuse forwarded ioc:* events that declare a type outside this set, so a
// misbehaving child can't poison the upstream store with arbitrary kinds.
var knownTypes = map[string]bool{
	"ip": true, "asn": true, "ja3": true, "ja4": true, "ja4h": true,
	"ja4t": true, "hassh": true, "user-agent": true,
	"ssh-key": true, "ssh-client": true, "email": true,
	"domain": true, "cve": true, "sha256": true, "url": true,
	"credential": true, "mac": true,
}

// maxIOCValueLen caps the length of a forwarded indicator value. Realistic
// values fit well within this (SHA-256 hex = 64 chars, JA3/JA4 ~32-64, even a
// long URL ~1-2 KiB). 4 KiB is a generous ceiling against a child sensor
// trying to bloat the IOC store with multi-MB "indicators".
const maxIOCValueLen = 4096

// Extract returns every indicator an event carries. Pure (no side effects). A
// forwarded ioc:<type> event re-yields its carried indicator (so an aggregator
// harvests IOCs from child ioc: events, even in rollup mode); the volume-only
// fleet rollup/trust operational events carry no indicator.
func Extract(ev *event.Event) []Indicator {
	if ev == nil {
		return nil
	}
	if strings.HasPrefix(ev.RuleID, "ioc:") {
		t, v := metaStr(ev, "ioc_type"), metaStr(ev, "ioc_value")
		if t == "" || v == "" || !knownTypes[t] || len(v) > maxIOCValueLen {
			return nil
		}
		return []Indicator{{Type: t, Value: v}}
	}
	if ev.RuleID == "fleet:rollup" || ev.RuleID == "fleet:sensor-untrusted" {
		return nil
	}
	var out []Indicator
	add := func(typ, val string) {
		if val != "" {
			out = append(out, Indicator{Type: typ, Value: val})
		}
	}
	add("ip", ev.Source.IP)
	add("asn", metaStr(ev, "asn"))
	add("ja3", metaStr(ev, "ja3"))
	add("ja4", metaStr(ev, "ja4"))
	add("ja4h", metaStr(ev, "ja4h")) // HTTP client fingerprint — tool-stable, high reuse
	add("ja4t", metaStr(ev, "ja4t")) // client TCP-stack fingerprint (OS-level)
	add("hassh", metaStr(ev, "hassh"))
	add("user-agent", metaStr(ev, "user_agent"))
	add("ssh-client", metaStr(ev, "client_id")) // SSH client version (tool attribution)
	for _, fp := range metaStrings(ev, "ssh_pubkey_fps") {
		add("ssh-key", fp) // offered SSH public-key fingerprint (type:SHA256:…)
	}
	// SMTP envelope sender — a reusable spam/phishing attribution indicator.
	// Strip the SMTP angle brackets and skip the null sender / non-addresses.
	if from := strings.Trim(metaStr(ev, "mail_from"), "<> "); strings.Contains(from, "@") {
		add("email", from)
	}
	add("domain", metaStr(ev, "qname"))
	// The SNI a client offered is what it believes it is connecting to — a
	// domain-shaped intent indicator alongside DNS query names.
	add("domain", metaStr(ev, "sni"))
	for _, k := range []string{"client_mac", "sender_mac", "mac"} {
		if m := metaStr(ev, k); m != "" {
			add("mac", m)
			break
		}
	}
	if strings.HasPrefix(ev.RuleID, "cve:") {
		add("cve", strings.TrimPrefix(ev.RuleID, "cve:"))
	}
	for _, d := range metaStrings(ev, "payload_artifacts") {
		if h := artifactHash(d); h != "" {
			add("sha256", h)
		}
	}
	for _, u := range metaStrings(ev, "harvested_urls") {
		add("url", u)
	}
	user := metaStr(ev, "username")
	if user == "" {
		user = metaStr(ev, "user")
	}
	if user != "" {
		pass := metaStr(ev, "password")
		if pass == "" {
			pass = metaStr(ev, "pass")
		}
		add("credential", user+":"+pass)
	}
	return out
}

// artifactHash pulls the sha256 out of a "<kind>:<sha256>[ -> file]" descriptor.
func artifactHash(desc string) string {
	if i := strings.Index(desc, " -> "); i >= 0 {
		desc = desc[:i]
	}
	_, hash, ok := strings.Cut(desc, ":")
	if !ok {
		return ""
	}
	return strings.TrimSpace(hash)
}

func metaStr(ev *event.Event, key string) string {
	if ev.Meta == nil {
		return ""
	}
	s, _ := ev.Meta[key].(string)
	return s
}

func metaStrings(ev *event.Event, key string) []string {
	if ev.Meta == nil {
		return nil
	}
	switch t := ev.Meta[key].(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
