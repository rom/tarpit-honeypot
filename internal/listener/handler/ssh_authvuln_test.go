package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func pwAttempt(user string, n int) map[string]any {
	return map[string]any{"method": "password", "user": user, "pass_len": n}
}

func TestScanSSHAuthThreats(t *testing.T) {
	cases := []struct {
		name     string
		attempts []map[string]any
		anoms    []string
		cves     []string
		noAnoms  []string
	}{
		{
			name:     "normal password",
			attempts: []map[string]any{pwAttempt("admin", 12)},
			noAnoms:  []string{"ssh-oversized-password", "ssh-sshole-attempt"},
		},
		{
			name:     "exactly 256 is fine",
			attempts: []map[string]any{pwAttempt("admin", 256)},
			noAnoms:  []string{"ssh-oversized-password"},
		},
		{
			name:     "sshole window 300",
			attempts: []map[string]any{pwAttempt("root", 300)},
			anoms:    []string{"ssh-oversized-password", "ssh-sshole-attempt"},
			cves:     []string{"SSHHOLE-2026"},
		},
		{
			name:     "oversized beyond sshole window 1500",
			attempts: []map[string]any{pwAttempt("bob", 1500)},
			anoms:    []string{"ssh-oversized-password"},
			cves:     []string{"SSHHOLE-2026"},
			noAnoms:  []string{"ssh-sshole-attempt"},
		},
		{
			name:     "giant password user-enum 20000",
			attempts: []map[string]any{pwAttempt("bob", 20000)},
			anoms:    []string{"ssh-oversized-password", "ssh-user-enum-timing"},
			cves:     []string{"SSHHOLE-2026", "CVE-2016-6210"},
		},
		{
			name:     "alpine blank root",
			attempts: []map[string]any{pwAttempt("root", 0)},
			anoms:    []string{"ssh-alpine-blank-root"},
			cves:     []string{"CVE-2019-5021"},
			noAnoms:  []string{"ssh-oversized-password"},
		},
		{
			name:     "blank password to a normal user is not the alpine bug",
			attempts: []map[string]any{pwAttempt("alice", 0)},
			noAnoms:  []string{"ssh-alpine-blank-root"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := Result{Meta: map[string]any{}}
			scanSSHAuthThreats(&res, c.attempts)
			anoms, _ := res.Meta["anomalies"].([]string)
			for _, a := range c.anoms {
				if !containsStr(anoms, a) {
					t.Errorf("want anomaly %q; got %v", a, anoms)
				}
			}
			for _, a := range c.noAnoms {
				if containsStr(anoms, a) {
					t.Errorf("did not want anomaly %q; got %v", a, anoms)
				}
			}
			for _, cv := range c.cves {
				if !containsStr(res.CVEHits, cv) {
					t.Errorf("want CVE hit %q; got %v", cv, res.CVEHits)
				}
			}
		})
	}
}

func TestSSHBypassAccept(t *testing.T) {
	cases := []struct {
		user string
		n    int
		want bool
	}{
		{"root", 300, true},   // sshole window
		{"alice", 1024, true}, // sshole window, any user
		{"alice", 1025, false},
		{"alice", 256, false},
		{"root", 0, true},   // alpine blank root
		{"alice", 0, false}, // blank password, non-privileged → not accepted
	}
	for _, c := range cases {
		if got := sshBypassAccept(c.user, c.n); got != c.want {
			t.Errorf("sshBypassAccept(%q,%d) = %v; want %v", c.user, c.n, got, c.want)
		}
	}
}

func passwordClientConfig(user, pass string) *xssh.ClientConfig {
	return &xssh.ClientConfig{
		User:            user,
		Auth:            []xssh.AuthMethod{xssh.Password(pass)},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
}

// Detection fires on a failed handshake too: a single >256-byte password to a
// non-privileged user with vuln emulation OFF is rejected, but the oversized /
// *sshole signals must still be stamped.
func TestSSHOversizedPasswordDetectedOnReject(t *testing.T) {
	client, server := loopbackPair(t)
	h := &sshInteractive{dir: t.TempDir()} // vuln: false

	resC := make(chan Result, 1)
	go func() {
		res, _ := h.Handle(context.Background(), server, config.Listener{Handler: "ssh_interactive"})
		resC <- res
	}()

	_, _, _, _ = xssh.NewClientConn(client, "host:22", passwordClientConfig("bob", strings.Repeat("A", 300)))
	_ = client.Close()

	select {
	case res := <-resC:
		anoms, _ := res.Meta["anomalies"].([]string)
		if !containsStr(anoms, "ssh-oversized-password") || !containsStr(anoms, "ssh-sshole-attempt") {
			t.Errorf("anomalies = %v; want ssh-oversized-password + ssh-sshole-attempt", anoms)
		}
		if !containsStr(res.CVEHits, "SSHHOLE-2026") {
			t.Errorf("CVEHits = %v; want SSHHOLE-2026", res.CVEHits)
		}
		if res.Meta["max_password_len"] != 300 {
			t.Errorf("max_password_len = %v; want 300", res.Meta["max_password_len"])
		}
		if res.Meta["accepted_user"] != nil {
			t.Errorf("auth should have been rejected (vuln off); accepted_user=%v", res.Meta["accepted_user"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handler did not return")
	}
}

// With vuln emulation ON, the *sshole 257–1024 byte password is accepted on the
// first attempt (the trap): the handshake succeeds and the attacker is dropped
// into the fake shell.
func TestSSHoleTrapAcceptsWhenVuln(t *testing.T) {
	client, server := loopbackPair(t)
	h := &sshInteractive{dir: t.TempDir(), vuln: true}

	resC := make(chan Result, 1)
	go func() {
		res, _ := h.Handle(context.Background(), server, config.Listener{Handler: "ssh_interactive"})
		resC <- res
	}()

	c, _, _, err := xssh.NewClientConn(client, "host:22", passwordClientConfig("root", strings.Repeat("A", 300)))
	if err != nil {
		t.Fatalf("expected the *sshole trap to accept the 300-byte password, got: %v", err)
	}
	_ = c.Close()
	_ = client.Close()

	select {
	case res := <-resC:
		if res.Meta["accepted_user"] != "root" {
			t.Errorf("accepted_user = %v; want root (trap accepted)", res.Meta["accepted_user"])
		}
		if !containsStr(res.CVEHits, "SSHHOLE-2026") {
			t.Errorf("CVEHits = %v; want SSHHOLE-2026", res.CVEHits)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handler did not return")
	}
}
