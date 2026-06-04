package ui

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// SSH credentials live in the auth_attempts list (per-attempt maps), not flat
// string keys — extractCreds must surface them so they reach the captures page.
func TestExtractCredsFromAuthAttempts(t *testing.T) {
	ev := &event.Event{Handler: "ssh_interactive", Meta: map[string]any{
		"auth_attempts": []map[string]any{
			{"method": "password", "user": "appuser", "password": "12345", "client": "SSH-2.0-Go"},
			{"method": "publickey", "user": "root", "key_type": "ssh-ed25519", "key_fp_sha256": "SHA256:abc"},
		},
	}}
	creds := extractCreds(ev)
	var gotPw, gotKey bool
	for _, c := range creds {
		if c.Kind == "password" && c.User == "appuser" && c.Pass == "12345" {
			gotPw = true
		}
		if c.Kind == "ssh-pubkey" && c.User == "root" && c.Pass == "ssh-ed25519 SHA256:abc" {
			gotKey = true
		}
	}
	if !gotPw {
		t.Errorf("password attempt not extracted: %+v", creds)
	}
	if !gotKey {
		t.Errorf("pubkey attempt not extracted: %+v", creds)
	}

	// JSON round-trip shape: []any of map[string]any.
	ev2 := &event.Event{Handler: "ssh", Meta: map[string]any{
		"auth_attempts": []any{
			map[string]any{"method": "password", "user": "admin", "password": "pw"},
		},
	}}
	if cs := extractCreds(ev2); len(cs) == 0 || cs[0].User != "admin" {
		t.Errorf("round-tripped auth_attempts not extracted: %+v", cs)
	}
}
