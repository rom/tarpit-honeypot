package scananalysis

import (
	"testing"
	"time"
)

// Idle sources must be evicted so the Tracker's map doesn't grow
// unbounded under many distinct/spoofed source IPs.
func TestTrackerEvictsIdleSources(t *testing.T) {
	tr := NewTracker(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	tr.Observe(Observation{SourceIP: "203.0.113.1", DestPort: 80, Time: base})
	if len(tr.srcs) != 1 {
		t.Fatalf("srcs = %d; want 1", len(tr.srcs))
	}
	// A new source after the window triggers the sweep, evicting the
	// idle first source.
	tr.Observe(Observation{SourceIP: "203.0.113.2", DestPort: 80, Time: base.Add(2 * time.Minute)})
	if _, ok := tr.srcs["203.0.113.1"]; ok {
		t.Error("idle source 203.0.113.1 was not evicted")
	}
	if _, ok := tr.srcs["203.0.113.2"]; !ok {
		t.Error("active source 203.0.113.2 missing")
	}
}
