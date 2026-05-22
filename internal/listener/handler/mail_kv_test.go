package handler

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// runConn drives a banner-mode TCP handler over net.Pipe: it drains the
// handler's writes (net.Pipe is synchronous, so writes would otherwise
// block), sends input, and returns the captured Result once Handle returns.
func runConn(t *testing.T, h Handler, input string) Result {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: time.Second}
	var res Result
	done := make(chan struct{})
	go func() { defer close(done); res, _ = h.Handle(context.Background(), server, cfg) }()
	go func() { _, _ = io.Copy(io.Discard, client) }()
	if _, err := io.WriteString(client, input); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return")
	}
	return res
}

func TestPOP3CapturesCredentials(t *testing.T) {
	res := runConn(t, &pop3{}, "USER alice\r\nPASS s3cret\r\nQUIT\r\n")
	if res.Meta["auth_user"] != "alice" || res.Meta["auth_pass"] != "s3cret" {
		t.Errorf("pop3 creds: user=%v pass=%v", res.Meta["auth_user"], res.Meta["auth_pass"])
	}
}

func TestIMAPCapturesCredentials(t *testing.T) {
	// Quoted form must be unwrapped.
	res := runConn(t, &imap{}, "a1 LOGIN \"bob\" \"hunter2\"\r\na2 LOGOUT\r\n")
	if res.Meta["auth_user"] != "bob" || res.Meta["auth_pass"] != "hunter2" {
		t.Errorf("imap creds: user=%v pass=%v", res.Meta["auth_user"], res.Meta["auth_pass"])
	}
}

func TestMemcachedFlagsAbuse(t *testing.T) {
	res := runConn(t, &memcached{}, "version\r\nstats\r\nset k 0 0 3\r\nabc\r\nflush_all\r\nquit\r\n")
	anoms, _ := res.Meta["anomalies"].([]string)
	for _, want := range []string{"memcached-stats-probe", "memcached-write-attempt", "memcached-flush"} {
		if !containsStr(anoms, want) {
			t.Errorf("memcached missing anomaly %q; got %v", want, anoms)
		}
	}
}

func TestParseIMAPLogin(t *testing.T) {
	cases := []struct{ in, u, p string }{
		{`"user" "pass"`, "user", "pass"},
		{`user pass`, "user", "pass"},
		{`"a b" c`, "a b", "c"},
	}
	for _, c := range cases {
		if u, p := parseIMAPLogin(c.in); u != c.u || p != c.p {
			t.Errorf("parseIMAPLogin(%q) = (%q,%q); want (%q,%q)", c.in, u, p, c.u, c.p)
		}
	}
}
