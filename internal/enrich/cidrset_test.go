package enrich

import (
	"net/netip"
	"testing"
)

func mustPrefix(s string) netip.Prefix { p := netip.MustParsePrefix(s); return p }
func mustAddr(s string) netip.Addr     { return netip.MustParseAddr(s) }

func TestCIDRSetContains(t *testing.T) {
	set := newCIDRSet([]netip.Prefix{
		mustPrefix("10.0.0.0/8"),
		mustPrefix("192.168.1.0/24"),
		mustPrefix("203.0.113.128/25"),
		mustPrefix("2001:db8::/32"),
		mustPrefix("2001:db8:dead::/48"),
	})
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},      // inside /8
		{"192.168.1.42", true},  // inside /24
		{"192.168.2.1", false},  // just outside the /24
		{"203.0.113.200", true}, // inside the upper /25
		{"203.0.113.10", false}, // lower half, outside the /25
		{"8.8.8.8", false},      // nothing
		{"2001:db8::1", true},   // inside v6 /32
		{"2001:db8:dead:beef::1", true},
		{"2001:dead::1", false}, // outside v6
	}
	for _, c := range cases {
		if got := set.contains(mustAddr(c.ip)); got != c.want {
			t.Errorf("contains(%s) = %v; want %v", c.ip, got, c.want)
		}
	}
}

func TestCIDRSetFamilyStrict(t *testing.T) {
	// A v4 /24 and a v6 /24 share a numeric length but must not cross-match —
	// same behaviour as netip.Prefix.Contains.
	set := newCIDRSet([]netip.Prefix{mustPrefix("1.2.3.0/24")})
	if set.contains(mustAddr("102:304::")) { // v6 addr whose /24 differs in family
		t.Error("v6 address matched a v4 /24 prefix")
	}
	if !set.contains(mustAddr("1.2.3.4")) {
		t.Error("v4 address did not match its v4 /24 prefix")
	}
}

func TestCIDRSetEmpty(t *testing.T) {
	var empty cidrSet
	if empty.contains(mustAddr("1.2.3.4")) {
		t.Error("empty set should contain nothing")
	}
	if newCIDRSet(nil).contains(mustAddr("::1")) {
		t.Error("nil-built set should contain nothing")
	}
}

// Parity: the bucketed set must agree with a linear netip.Prefix.Contains scan
// over the same prefixes, for every probe.
func TestCIDRSetParityWithLinearScan(t *testing.T) {
	prefixes := []netip.Prefix{
		mustPrefix("172.16.0.0/12"), mustPrefix("172.20.5.0/24"),
		mustPrefix("100.64.0.0/10"), mustPrefix("198.51.100.0/24"),
		mustPrefix("2001:db8::/32"), mustPrefix("fe80::/10"),
	}
	set := newCIDRSet(prefixes)
	probes := []string{
		"172.16.0.1", "172.20.5.99", "172.21.0.1", "172.32.0.1",
		"100.64.1.1", "100.128.0.1", "198.51.100.7", "198.51.101.7",
		"8.8.8.8", "2001:db8:1::1", "2001:dead::1", "fe80::1234", "fdff::1",
	}
	for _, s := range probes {
		a := mustAddr(s)
		linear := false
		for _, p := range prefixes {
			if p.Contains(a) {
				linear = true
				break
			}
		}
		if got := set.contains(a); got != linear {
			t.Errorf("parity mismatch for %s: cidrSet=%v linear=%v", s, got, linear)
		}
	}
}
