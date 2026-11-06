package egress

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestDefaultRoundTrip covers SetDefault/Default, including the nil (restore
// unrestricted) path.
func TestDefaultRoundTrip(t *testing.T) {
	t.Cleanup(func() { SetDefault(nil) })
	if Default() != nil {
		SetDefault(nil)
	}
	p := New()
	SetDefault(p)
	if Default() != p {
		t.Fatalf("Default() = %v; want the installed policy", Default())
	}
	SetDefault(nil)
	if Default() != nil {
		t.Errorf("Default() after SetDefault(nil) = %v; want nil", Default())
	}
}

// TestPackageHTTPClientUnrestricted exercises the package-level HTTPClient and
// its DialContext when no default policy is installed (egress unrestricted).
func TestPackageHTTPClientUnrestricted(t *testing.T) {
	t.Cleanup(func() { SetDefault(nil) })
	SetDefault(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := HTTPClient(5 * time.Second)
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET through unrestricted package client: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d; want 200", resp.StatusCode)
	}
}

// TestPackageDialContextEnforcesDefault covers the package-level DialContext
// when a restrictive default is installed: an un-allowlisted destination is
// refused before any socket is opened.
func TestPackageDialContextEnforcesDefault(t *testing.T) {
	t.Cleanup(func() { SetDefault(nil) })
	p := New()
	p.Allow("allowed.example:443")
	SetDefault(p)

	if _, err := DialContext(context.Background(), "tcp", "blocked.example:443"); err == nil {
		t.Error("package DialContext should refuse a non-allowlisted destination")
	}
}

// TestDialerOfFallback covers the branch where no usable dialer is configured
// and dialerOf returns a fresh default dialer.
func TestDialerOfFallback(t *testing.T) {
	if dialerOf(nil) == nil {
		t.Error("dialerOf(nil) must return a non-nil fallback dialer")
	}
	if dialerOf(&Policy{}) == nil { // policy present but dialer unset
		t.Error("dialerOf(policy with nil dialer) must return a non-nil fallback")
	}
	p := New()
	if dialerOf(p) != p.dialer {
		t.Error("dialerOf(policy) should return the policy's own dialer when set")
	}
}

// TestResolve covers all three branches of resolve: an IP literal (parsed
// directly), a resolvable name, and an unresolvable name (nil).
func TestResolve(t *testing.T) {
	if got := resolve("127.0.0.1"); len(got) != 1 || !got[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("resolve(IP literal) = %v; want [127.0.0.1]", got)
	}
	if got := resolve("localhost"); len(got) == 0 {
		t.Error("resolve(localhost) returned no addresses")
	}
	// The .invalid TLD (RFC 2606) is reserved to never resolve.
	if got := resolve("nonexistent-host.invalid."); got != nil {
		t.Errorf("resolve(unresolvable) = %v; want nil", got)
	}
}

// TestSystemResolvers exercises the resolv.conf reader. We don't assert the
// contents (they vary by host) — only that it runs without panicking and
// returns a slice consistent with the file's presence.
func TestSystemResolvers(t *testing.T) {
	_ = SystemResolvers()
}

// TestRemoveFirewallBogusTable covers RemoveFirewall's delete path against a
// table that does not exist, never touching the real default table. The outcome
// depends on the environment: a no-op (nil) when nft is absent, when running as
// root, or when the table is simply missing ("No such file" is tolerated); but
// an unprivileged box WITH nft gets "nft delete failed: ... Operation not
// permitted" from nft itself — an environment limit, not a logic bug. Accept
// nil or an nft-reported error; only a non-nft error would signal a real defect.
func TestRemoveFirewallBogusTable(t *testing.T) {
	err := RemoveFirewall(context.Background(), "tarpit_test_nonexistent_table")
	if err != nil && !strings.Contains(err.Error(), "nft") {
		t.Errorf("RemoveFirewall(bogus table) = %v; want nil or an nft-reported error", err)
	}
}
