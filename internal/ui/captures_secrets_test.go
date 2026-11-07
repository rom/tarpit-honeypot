package ui

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestParsePcapNameRoundTrip(t *testing.T) {
	ip, port := parsePcapName("abc123_203.0.113.42_22.pcap")
	if ip != "203.0.113.42" || port != "22" {
		t.Errorf("ipv4 parse = %q %q", ip, port)
	}
	ip, port = parsePcapName("deadbeef_2001-db8--1_443.pcap")
	if ip != "2001:db8::1" || port != "443" {
		t.Errorf("ipv6 parse = %q %q", ip, port)
	}
	if ip, port := parsePcapName("legacyid.pcap"); ip != "" || port != "" {
		t.Errorf("legacy name should yield empty, got %q %q", ip, port)
	}
}

func TestExtractCredsSecrets(t *testing.T) {
	// A login pair plus a standalone bearer token + SNMP community.
	ev := &event.Event{
		Handler: "http",
		Meta: map[string]any{
			"auth_user":    "admin",
			"auth_pass":    "hunter2",
			"bearer_token": "eyJhbGciOi.x.y",
			"community":    "public",
		},
	}
	got := extractCreds(ev)
	kinds := map[string]string{} // kind -> secret
	for _, c := range got {
		kinds[c.Kind] = c.Pass
	}
	if kinds["password"] != "hunter2" {
		t.Errorf("login not extracted: %+v", got)
	}
	if kinds["token"] != "eyJhbGciOi.x.y" {
		t.Errorf("bearer token not extracted: %+v", got)
	}
	if kinds["snmp-community"] != "public" {
		t.Errorf("snmp community not extracted: %+v", got)
	}
}

// Secrets harvested by internal/secretscan land in ev.Meta["secrets"] as a list
// of {kind,value,hint} maps; extractCreds must surface each as its own row, and
// decode a basic-auth hint into user/pass.
func TestExtractCredsFromSecretsMeta(t *testing.T) {
	ev := &event.Event{
		Handler: "http",
		Meta: map[string]any{
			"secrets": []map[string]any{
				{"kind": "github-token", "value": "ghp_abcdefghijklmnop"},
				{"kind": "private-key", "value": "-----BEGIN RSA PRIVATE KEY-----\n..."},
				{"kind": "basic-auth", "value": "YWxpY2U6czNjcjN0", "hint": "alice:s3cr3t"},
			},
		},
	}
	got := extractCreds(ev)
	byKind := map[string]credPair{}
	for _, c := range got {
		byKind[c.Kind] = c
	}
	if byKind["github-token"].Pass != "ghp_abcdefghijklmnop" {
		t.Errorf("github-token not surfaced: %+v", got)
	}
	if _, ok := byKind["private-key"]; !ok {
		t.Errorf("private-key not surfaced: %+v", got)
	}
	// basic-auth hint decodes into a password row.
	pw := byKind["password"]
	if pw.User != "alice" || pw.Pass != "s3cr3t" {
		t.Errorf("basic-auth hint not decoded into user/pass: %+v", got)
	}
	for _, c := range got {
		if c.Service != "http" {
			t.Errorf("secret row missing service: %+v", c)
		}
	}
}
