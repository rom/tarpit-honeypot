package handler

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	xssh "golang.org/x/crypto/ssh"
)

// With accept_creds=defaults, a known weak credential (root:root) is accepted
// on the FIRST attempt — the decoy behaves like a real box with that weak
// password — and the accepted user + policy are recorded.
func TestSSHAcceptCredsDefaultsFirstTry(t *testing.T) {
	client, server := loopbackPair(t)
	h := &sshInteractive{dir: t.TempDir(), acceptCreds: "defaults"}

	resC := make(chan Result, 1)
	go func() {
		res, _ := h.Handle(context.Background(), server, config.Listener{Handler: "ssh_interactive"})
		resC <- res
	}()

	c, _, _, err := xssh.NewClientConn(client, "host:22", passwordClientConfig("root", "root"))
	if err != nil {
		t.Fatalf("accept_creds=defaults should accept root:root on the first try, got: %v", err)
	}
	_ = c.Close()
	_ = client.Close()

	select {
	case res := <-resC:
		if res.Meta["accepted_user"] != "root" {
			t.Errorf("accepted_user = %v; want root", res.Meta["accepted_user"])
		}
		if res.Meta["accept_policy"] != "defaults" {
			t.Errorf("accept_policy = %v; want defaults", res.Meta["accept_policy"])
		}
		// Exactly one auth attempt — accepted on the first try, not the 3rd.
		if a, _ := res.Meta["auth_attempts"].([]map[string]any); len(a) != 1 {
			t.Errorf("auth_attempts = %d; want 1 (first-try accept)", len(a))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handler did not return")
	}
}

// A non-default credential is NOT accepted on the first try under
// accept_creds=defaults (it falls back to the attempt-count path).
func TestSSHAcceptCredsDefaultsRejectsUnknownFirstTry(t *testing.T) {
	client, server := loopbackPair(t)
	h := &sshInteractive{dir: t.TempDir(), acceptCreds: "defaults"}

	resC := make(chan Result, 1)
	go func() {
		res, _ := h.Handle(context.Background(), server, config.Listener{Handler: "ssh_interactive"})
		resC <- res
	}()

	// One odd credential, then close: should not be accepted.
	_, _, _, err := xssh.NewClientConn(client, "host:22", passwordClientConfig("alice", "n0t-a-default"))
	if err == nil {
		t.Error("accept_creds=defaults should reject a non-default credential on the first try")
	}
	_ = client.Close()

	select {
	case res := <-resC:
		if res.Meta["accepted_user"] != nil {
			t.Errorf("accepted_user = %v; want nil (not a default cred)", res.Meta["accepted_user"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handler did not return")
	}
}

// accept_creds=any accepts an arbitrary credential on the first attempt.
func TestSSHAcceptCredsAnyFirstTry(t *testing.T) {
	client, server := loopbackPair(t)
	h := &sshInteractive{dir: t.TempDir(), acceptCreds: "any"}

	resC := make(chan Result, 1)
	go func() {
		res, _ := h.Handle(context.Background(), server, config.Listener{Handler: "ssh_interactive"})
		resC <- res
	}()

	c, _, _, err := xssh.NewClientConn(client, "host:22", passwordClientConfig("whoever", "whatever"))
	if err != nil {
		t.Fatalf("accept_creds=any should accept any credential on the first try, got: %v", err)
	}
	_ = c.Close()
	_ = client.Close()

	select {
	case res := <-resC:
		if res.Meta["accepted_user"] != "whoever" {
			t.Errorf("accepted_user = %v; want whoever", res.Meta["accepted_user"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handler did not return")
	}
}
