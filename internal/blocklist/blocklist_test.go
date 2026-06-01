package blocklist

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fakeRunner records the nft invocations instead of executing them.
type fakeRunner struct {
	calls []call
}

type call struct {
	stdin string
	args  []string
}

func (f *fakeRunner) Run(_ context.Context, stdin string, args ...string) error {
	f.calls = append(f.calls, call{stdin: stdin, args: args})
	return nil
}

func newTestBlocker(c Config) (*Blocker, *fakeRunner) {
	fr := &fakeRunner{}
	c.Runner = fr
	return New(c), fr
}

func TestBaseRulesetHasTimeoutSetsAndDrop(t *testing.T) {
	rs := BaseRuleset(Config{Enabled: true, TTL: 10 * time.Minute})
	for _, want := range []string{
		"set blocked4 {", "set blocked6 {", "flags timeout", "timeout 600s",
		"ip saddr @blocked4 drop", "ip6 saddr @blocked6 drop",
		"hook input",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("BaseRuleset missing %q:\n%s", want, rs)
		}
	}
}

func TestShouldBlockThreshold(t *testing.T) {
	b, _ := newTestBlocker(Config{Enabled: true, Level: "high"})
	if b.ShouldBlock("203.0.113.5", "elevated") {
		t.Error("elevated should not meet a high threshold")
	}
	if !b.ShouldBlock("203.0.113.5", "high") {
		t.Error("high should meet a high threshold")
	}
	if !b.ShouldBlock("203.0.113.5", "critical") {
		t.Error("critical should exceed a high threshold")
	}
}

func TestShouldBlockDisabled(t *testing.T) {
	b, _ := newTestBlocker(Config{Enabled: false, Level: "critical"})
	if b.ShouldBlock("203.0.113.5", "critical") {
		t.Error("disabled blocker must never block")
	}
}

func TestShouldBlockExempt(t *testing.T) {
	b, _ := newTestBlocker(Config{Enabled: true, Level: "critical", NeverBlock: []string{"10.0.0.0/8", "192.0.2.7"}})
	cases := map[string]bool{
		"127.0.0.1":   false, // always-exempt loopback
		"169.254.1.1": false, // always-exempt link-local
		"10.5.5.5":    false, // operator CIDR
		"192.0.2.7":   false, // operator bare IP
		"203.0.113.9": true,  // a real external source
		"not-an-ip":   false,
	}
	for ip, want := range cases {
		if got := b.ShouldBlock(ip, "critical"); got != want {
			t.Errorf("ShouldBlock(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestBlockAddsV4Element(t *testing.T) {
	b, fr := newTestBlocker(Config{Enabled: true, Level: "critical", Table: "tt"})
	if err := b.Block(context.Background(), "203.0.113.9", "critical"); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 1 {
		t.Fatalf("expected 1 nft call, got %d", len(fr.calls))
	}
	got := strings.Join(fr.calls[0].args, " ")
	if !strings.Contains(got, "add element inet tt blocked4") || !strings.Contains(got, "203.0.113.9") {
		t.Errorf("unexpected nft args: %q", got)
	}
}

func TestBlockAddsV6Element(t *testing.T) {
	b, fr := newTestBlocker(Config{Enabled: true, Level: "critical"})
	if err := b.Block(context.Background(), "2001:db8::1", "critical"); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(fr.calls[0].args, " ")
	if !strings.Contains(got, "blocked6") || !strings.Contains(got, "2001:db8::1") {
		t.Errorf("expected v6 element, got %q", got)
	}
}

func TestBlockExemptIsNoOp(t *testing.T) {
	b, fr := newTestBlocker(Config{Enabled: true, Level: "critical"})
	if err := b.Block(context.Background(), "127.0.0.1", "critical"); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 0 {
		t.Errorf("blocking an exempt IP must not call nft; got %d calls", len(fr.calls))
	}
}

func TestInstallAndRemove(t *testing.T) {
	b, fr := newTestBlocker(Config{Enabled: true, Level: "critical", Table: "tt"})
	if err := b.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 2 {
		t.Fatalf("expected install+remove = 2 calls, got %d", len(fr.calls))
	}
	if fr.calls[0].stdin == "" || !strings.Contains(fr.calls[0].stdin, "table inet tt") {
		t.Errorf("install should pipe the ruleset on stdin")
	}
	if strings.Join(fr.calls[1].args, " ") != "delete table inet tt" {
		t.Errorf("remove args = %q", fr.calls[1].args)
	}
}

func TestDisabledInstallIsNoOp(t *testing.T) {
	b, fr := newTestBlocker(Config{Enabled: false})
	if err := b.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 0 {
		t.Error("disabled Install must be a no-op")
	}
}
