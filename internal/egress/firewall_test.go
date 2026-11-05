package egress

import (
	"os/exec"
	"strings"
	"testing"
)

func TestBuildRulesetContents(t *testing.T) {
	rs := BuildRuleset(FirewallConfig{
		UID:       1000,
		Entries:   []string{"203.0.113.10:443", "10.20.0.0/16", "[2001:db8::1]:6514", "198.51.100.5"},
		Resolvers: []string{"8.8.8.8"},
	})
	for _, want := range []string{
		"table inet tarpit_egress",
		"delete table inet tarpit_egress", // idempotent replace
		"meta skuid != 1000 accept",       // only govern the sensor's uid
		"ct state established,related accept",
		"oifname \"lo\" accept",
		"ip daddr 8.8.8.8 udp dport 53 accept",       // DNS to resolver
		"ip daddr 203.0.113.10 th dport 443 accept",  // host:port entry
		"ip daddr 10.20.0.0/16 accept",               // CIDR entry
		"ip6 daddr 2001:db8::1 th dport 6514 accept", // v6 host:port
		"ip daddr 198.51.100.5 accept",               // bare IP
		"meta skuid 1000 drop",                       // drop the rest of the sensor's egress
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset missing %q:\n%s", want, rs)
		}
	}
}

// TestBuildRulesetValidNft feeds the generated ruleset to `nft -c` (check mode,
// no privilege) to confirm the kernel's nftables parser accepts it.
func TestBuildRulesetValidNft(t *testing.T) {
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not installed")
	}
	rs := BuildRuleset(FirewallConfig{
		UID:       0,
		Entries:   []string{"203.0.113.10:443", "10.20.0.0/16", "[2001:db8::1]:6514", "198.51.100.5", "fd00::/8"},
		Resolvers: []string{"8.8.8.8", "2001:4860:4860::8888"},
	})
	cmd := exec.Command(nft, "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(rs)
	if out, err := cmd.CombinedOutput(); err != nil {
		// `nft -c` still initializes a netlink cache on some kernels; an
		// unprivileged runner (no CAP_NET_ADMIN, e.g. a sandboxed CI job)
		// can't, and fails with "cache initialization failed: Operation not
		// permitted" before it ever parses the ruleset. That's an environment
		// limitation, not a ruleset defect — skip rather than report a false
		// failure. A genuine syntax rejection (no netlink markers) still fails.
		o := string(out)
		lo := strings.ToLower(o)
		if strings.Contains(lo, "operation not permitted") ||
			strings.Contains(lo, "cache initialization failed") ||
			strings.Contains(lo, "netlink") {
			t.Skipf("nft cannot validate without netlink access in this environment: %v\n%s", err, o)
		}
		t.Fatalf("nft rejected the generated ruleset: %v\n%s\n--- ruleset ---\n%s", err, out, rs)
	}
}

func TestParseResolvers(t *testing.T) {
	data := []byte("# comment\nnameserver 8.8.8.8\nsearch corp.local\nnameserver 1.1.1.1\noptions ndots:2\n")
	got := parseResolvers(data)
	if len(got) != 2 || got[0] != "8.8.8.8" || got[1] != "1.1.1.1" {
		t.Errorf("parseResolvers = %v; want [8.8.8.8 1.1.1.1]", got)
	}
}

func TestPolicyEntries(t *testing.T) {
	p := New()
	p.Allow("siem.example:8443")
	p.Allow("10.0.0.0/8")
	got := map[string]bool{}
	for _, e := range p.Entries() {
		got[e] = true
	}
	if !got["siem.example:8443"] || !got["10.0.0.0/8"] {
		t.Errorf("Entries = %v; want siem.example:8443 + 10.0.0.0/8", p.Entries())
	}
}

func TestValidPort(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"80", true}, {"1", true}, {"65535", true},
		{"", false}, {"0", false}, {"65536", false}, {"99999", false},
		{"abc", false}, {"80 ", false}, {"-1", false}, {"80\n", false},
		{"80;evil", false}, {"80\taccept", false},
	}
	for _, c := range cases {
		if got := validPort(c.in); got != c.ok {
			t.Errorf("validPort(%q) = %v; want %v", c.in, got, c.ok)
		}
	}
}

func TestValidHost(t *testing.T) {
	good := []string{
		"example.com", "siem.corp", "host-1.sub.example.com",
		"10.0.0.1", "2001:db8::1", "[2001:db8::1]",
		"a_record.example", "x",
	}
	for _, h := range good {
		if !validHost(h) {
			t.Errorf("validHost(%q) should be true", h)
		}
	}
	bad := []string{
		"", "foo bar", "evil;rm -rf", "evil\nrule", "evil/path",
		"evil$(cmd)", "evil|nft", "evil\taccept", "evil`cmd`",
		// over 253 chars
		strings.Repeat("a", 254),
	}
	for _, h := range bad {
		if validHost(h) {
			t.Errorf("validHost(%q) should be false", h)
		}
	}
}

// TestEntryRulesRejectsInjection guards H1: a malformed allowlist entry must
// not inject extra lines into the nft script that gets piped to `nft -f -`.
func TestEntryRulesRejectsInjection(t *testing.T) {
	cases := []string{
		"example.com:80\naccept", // newline in port
		"example.com:80;flush",   // semicolon in port
		"evil;rm -rf:443",        // shell metacharacter in host
		"evil host:443",          // space in host
		"example.com:abc",        // non-numeric port
		"example.com:0",          // out-of-range port
		"example.com:99999",      // out-of-range port
		"evil\n.example.com",     // newline in bare host
	}
	for _, e := range cases {
		rules := entryRules(e)
		for _, r := range rules {
			if strings.ContainsAny(r, "\n;`$") {
				t.Errorf("entryRules(%q) produced dangerous rule: %q", e, r)
			}
		}
	}
}
