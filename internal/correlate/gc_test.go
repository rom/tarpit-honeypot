package correlate

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// Idle per-source state must be evicted so the maps don't grow unbounded
// under many distinct source IPs over a long-running sensor.
func TestCorrelatorEvictsIdleState(t *testing.T) {
	c, err := New(config.Correlate{
		PortScan: config.CorrPortScan{Enabled: true, DistinctPorts: 100, Window: time.Minute, Severity: "high"},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0).UTC()
	c.Observe(&event.Event{Source: event.Endpoint{IP: "203.0.113.1"}, Dest: event.Endpoint{Port: 80}, RuleID: "listener:x", Time: base})
	if len(c.scan) != 1 {
		t.Fatalf("scan map = %d; want 1", len(c.scan))
	}
	// A new source after the window + GC throttle triggers the sweep,
	// which must drop the now-idle first source.
	later := base.Add(corrGCInterval + 2*time.Minute)
	c.Observe(&event.Event{Source: event.Endpoint{IP: "203.0.113.2"}, Dest: event.Endpoint{Port: 80}, RuleID: "listener:x", Time: later})
	if _, ok := c.scan["203.0.113.1"]; ok {
		t.Error("idle scan state for 203.0.113.1 was not evicted")
	}
	if _, ok := c.scan["203.0.113.2"]; !ok {
		t.Error("active scan state for 203.0.113.2 missing")
	}
}
