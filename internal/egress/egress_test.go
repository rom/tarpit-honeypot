package egress

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestPolicyAllowed(t *testing.T) {
	p := New()
	p.Allow("collector.example:443")
	p.Allow("bare.host")
	p.Allow("10.0.0.0/8")
	cases := []struct {
		addr string
		want bool
	}{
		{"collector.example:443", true}, // exact host:port
		{"collector.example:80", false}, // same host, different port (port-specific entry)
		{"bare.host:9999", true},        // bare host allows any port
		{"10.1.2.3:5514", true},         // inside the CIDR
		{"11.1.2.3:5514", false},        // outside the CIDR
		{"evil.example:443", false},     // not listed
	}
	for _, c := range cases {
		if got := p.Allowed(c.addr); got != c.want {
			t.Errorf("Allowed(%q) = %v; want %v", c.addr, got, c.want)
		}
	}
}

func TestPolicyDialDenyAndAllow(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	p := New()
	var denied string
	p.SetOnDeny(func(_, addr, _ string) { denied = addr })

	// Not allowlisted -> refused + hook fired.
	if _, err := p.DialContext(context.Background(), "tcp", ln.Addr().String()); err == nil {
		t.Error("dial to a non-allowlisted address should be refused")
	}
	if denied != ln.Addr().String() {
		t.Errorf("onDeny addr = %q; want %q", denied, ln.Addr().String())
	}

	// Allowlisted -> dials.
	p.Allow(ln.Addr().String())
	c, err := p.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("allowlisted dial failed: %v", err)
	}
	_ = c.Close()
}

func TestHTTPClientGovernedByPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	host := mustHost(t, srv.URL)

	p := New()
	// Denied before the destination is allowlisted.
	if _, err := p.HTTPClient(2 * time.Second).Get(srv.URL); err == nil {
		t.Error("HTTP GET to a non-allowlisted host should fail")
	}
	// Allowed once the destination is on the list.
	p.Allow(host)
	resp, err := p.HTTPClient(2 * time.Second).Get(srv.URL)
	if err != nil {
		t.Fatalf("allowlisted HTTP GET failed: %v", err)
	}
	_ = resp.Body.Close()
}

func TestDefaultUnrestrictedWhenUnset(t *testing.T) {
	SetDefault(nil)
	defer SetDefault(nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e == nil {
			_ = c.Close()
		}
	}()
	c, err := DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("with no default policy egress must be unrestricted: %v", err)
	}
	_ = c.Close()
}

func TestDefaultEnforces(t *testing.T) {
	p := New() // empty allowlist
	SetDefault(p)
	defer SetDefault(nil)
	if _, err := DialContext(context.Background(), "tcp", "203.0.113.1:443"); err == nil {
		t.Error("default policy with empty allowlist should refuse the dial")
	}
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}
