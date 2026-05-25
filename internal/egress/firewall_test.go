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
