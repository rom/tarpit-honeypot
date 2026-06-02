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
