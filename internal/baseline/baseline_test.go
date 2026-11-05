package baseline

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func ev(ip string, port int, meta map[string]any, tactics ...string) *event.Event {
	return &event.Event{
		ID: "x", Sensor: "s", RuleID: "listener:test", Severity: event.SeverityMedium,
		Source: event.Endpoint{IP: ip}, Dest: event.Endpoint{Port: port},
		Meta: meta, MitreTactics: tactics,
	}
}

func hasRule(evs []*event.Event, rule string) bool {
	for _, e := range evs {
		if e.RuleID == rule {
			return true
		}
	}
	return false
}

func TestNewEntityWarmup(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	d := New(Config{Warmup: time.Hour, now: func() time.Time { return now }})

	// During warmup: value is learned but NOT flagged.
	out := d.Observe(ev("1.1.1.1", 22, map[string]any{"asn": float64(64500), "geo_country": "CN"}))
	if hasRule(out, "baseline:new-asn") || hasRule(out, "baseline:new-country") {
		t.Fatalf("new-entity flagged during warmup: %v", ruleIDs(out))
	}

	// After warmup: a brand-new ASN/port/country flags; a learned one does not.
	now = now.Add(2 * time.Hour)
	out = d.Observe(ev("2.2.2.2", 445, map[string]any{"asn": float64(64501), "geo_country": "RU"}))
	for _, want := range []string{"baseline:new-asn", "baseline:new-port", "baseline:new-country"} {
		if !hasRule(out, want) {
			t.Errorf("want %s; got %v", want, ruleIDs(out))
		}
	}
	// The warmup-learned ASN 64500 / country CN must NOT re-flag now.
	out = d.Observe(ev("3.3.3.3", 22, map[string]any{"asn": float64(64500), "geo_country": "CN"}))
	if hasRule(out, "baseline:new-asn") || hasRule(out, "baseline:new-country") || hasRule(out, "baseline:new-port") {
		t.Errorf("learned entity re-flagged: %v", ruleIDs(out))
	}
}

func TestVolumeSpike(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	d := New(Config{
		Warmup: 0, SpikeWindow: time.Minute, SpikeK: 3, SpikeMin: 5, SpikeWarmup: 3,
		now: func() time.Time { return now },
	})
	feed := func(n int) []*event.Event {
		var out []*event.Event
		for i := 0; i < n; i++ {
			out = append(out, d.Observe(ev("9.9.9.9", 80, map[string]any{}))...)
		}
		return out
	}
	// Establish a low baseline over several minutes (~2/bucket).
	for b := 0; b < 6; b++ {
		feed(2)
		now = now.Add(time.Minute)
	}
	// A huge bucket, then advance so it closes and is evaluated.
	feed(200)
	now = now.Add(time.Minute)
	out := feed(1)
	if !hasRule(out, "baseline:volume-spike") {
		t.Errorf("want baseline:volume-spike after a 200-event bucket; got %v", ruleIDs(out))
	}
}

func TestKillChainMultistage(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	d := New(Config{Warmup: 0, KillChainStages: 3, KillChainWindow: 30 * time.Minute, now: func() time.Time { return now }})
	ip := "7.7.7.7"
	_ = d.Observe(ev(ip, 80, nil, "reconnaissance"))
	_ = d.Observe(ev(ip, 80, nil, "initial-access"))
	out := d.Observe(ev(ip, 80, nil, "execution"))
	if !hasRule(out, "killchain:multistage") {
		t.Fatalf("want killchain:multistage at 3 distinct tactics; got %v", ruleIDs(out))
	}
	// It fires once, not on every subsequent event.
	out = d.Observe(ev(ip, 80, nil, "exfiltration"))
	if hasRule(out, "killchain:multistage") {
		t.Errorf("kill-chain re-emitted within the same window")
	}
	// A source with too few stages does not trigger.
	out = d.Observe(ev("8.8.8.8", 80, nil, "reconnaissance", "reconnaissance"))
	if hasRule(out, "killchain:multistage") {
		t.Errorf("kill-chain fired on a single-stage source: %v", ruleIDs(out))
	}
}

func ruleIDs(evs []*event.Event) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.RuleID
	}
	return out
}

// TestKillChainEviction verifies the per-source kill-chain table is bounded:
// idle sources (seen before the window) are swept, so a high-cardinality flood
// of distinct IPs can't grow d.chain without limit.
func TestKillChainEviction(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	d := New(Config{
		Warmup: 0, KillChainStages: 3, KillChainWindow: time.Minute, MaxSources: 100,
		now: func() time.Time { return now },
	})
	// 500 distinct sources, each a single-tactic event, spread over 10 minutes
	// (>> the 1m window). Without eviction d.chain would hold all 500.
	for i := 0; i < 500; i++ {
		now = now.Add(2 * time.Second)
		d.Observe(ev("10.1."+itoa(i/256)+"."+itoa(i%256), 22, nil, "discovery"))
	}
	d.mu.Lock()
	n := len(d.chain)
	d.mu.Unlock()
	if n > 100 {
		t.Errorf("chain table grew to %d; want <= MaxSources (100) after idle sweep", n)
	}
	if n == 0 {
		t.Error("chain table is empty; sweep should keep recent entries")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [3]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
