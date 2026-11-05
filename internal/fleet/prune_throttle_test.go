package fleet

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestFleetPruneInterval(t *testing.T) {
	cases := []struct {
		window time.Duration
		want   time.Duration
	}{
		{time.Hour, 30 * time.Second},         // 1h/16 = 225s, clamped to 30s
		{160 * time.Second, 10 * time.Second}, // 160s/16 = 10s
		{8 * time.Second, time.Second},        // 0.5s, clamped up to 1s
		{0, time.Second},                      // degenerate, clamped up to 1s
	}
	for _, c := range cases {
		if got := fleetPruneInterval(c.window); got != c.want {
			t.Errorf("fleetPruneInterval(%v) = %v; want %v", c.window, got, c.want)
		}
	}
}

// The idle-state sweep must be throttled: a second event arriving within the
// prune interval must not re-run the O(N) sweep (observable via lastPrune),
// while one past the interval must.
func TestFleetPruneThrottled(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	// Window 160s → interval 10s.
	c := New(Config{Enabled: true, SourceSensors: 99, Window: 160 * time.Second})
	c.now = func() time.Time { return now }

	feed := func() {
		c.Observe(&event.Event{Source: event.Endpoint{IP: "203.0.113.1"}, SensorID: "s1", RuleID: "listener:x"})
	}

	feed() // first event: sweep always runs (lastPrune was zero)
	if !c.lastPrune.Equal(now) {
		t.Fatalf("first event did not run the sweep: lastPrune=%v want %v", c.lastPrune, now)
	}

	first := now
	now = now.Add(5 * time.Second) // within the 10s interval
	feed()
	if !c.lastPrune.Equal(first) {
		t.Errorf("sweep ran within the interval: lastPrune advanced to %v (want %v)", c.lastPrune, first)
	}

	now = now.Add(6 * time.Second) // now 11s past the last sweep, over the interval
	feed()
	if !c.lastPrune.Equal(now) {
		t.Errorf("sweep did not run past the interval: lastPrune=%v want %v", c.lastPrune, now)
	}
}

// Throttling must not keep idle actors forever: once the window (plus at most
// one interval) has elapsed, the next sweep still evicts them.
func TestFleetPruneStillEvictsIdle(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	c := New(Config{Enabled: true, SourceSensors: 99, Window: 160 * time.Second})
	c.now = func() time.Time { return now }

	c.Observe(&event.Event{Source: event.Endpoint{IP: "203.0.113.1"}, SensorID: "s1", RuleID: "listener:x"})
	if len(c.sources) != 1 {
		t.Fatalf("sources = %d; want 1", len(c.sources))
	}
	now = now.Add(200 * time.Second) // past window + interval
	c.Observe(&event.Event{Source: event.Endpoint{IP: "203.0.113.2"}, SensorID: "s1", RuleID: "listener:x"})
	if _, ok := c.sources["203.0.113.1"]; ok {
		t.Error("idle actor 203.0.113.1 not evicted after window + interval")
	}
	if _, ok := c.sources["203.0.113.2"]; !ok {
		t.Error("active actor 203.0.113.2 missing")
	}
}
