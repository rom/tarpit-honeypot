package correlate

import (
	"fmt"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// A distinct-source flood whose entries are all still in-window (so idle
// eviction can't reclaim them) must not grow a detector table without bound:
// the emergency hard cap sheds live entries once a table reaches maxSources.
func TestCorrelatorHardCapsUnderFlood(t *testing.T) {
	const max = 100
	c, err := New(config.Correlate{
		MaxSources: max,
		// DistinctPorts far above 1 so no scan aggregate ever emits — we only
		// want the per-source table to grow.
		PortScan: config.CorrPortScan{Enabled: true, DistinctPorts: 100000, Window: time.Hour, Severity: "high"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// All events share one timestamp: nothing is ever "idle", so only the hard
	// cap can bound the table.
	base := time.Unix(1_700_000_000, 0).UTC()
	const fed = 10 * max
	for i := 0; i < fed; i++ {
		c.Observe(&event.Event{
			Source: event.Endpoint{IP: fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)},
			Dest:   event.Endpoint{Port: 80}, RuleID: "listener:x", Time: base,
		})
	}
	// Without the cap the table would hold all `fed` distinct sources. With it,
	// a forced sweep fires every maxSources events and sheds to 3/4, so the live
	// set stays within ~1.75×maxSources and far below what was fed.
	if len(c.scan) > 2*max {
		t.Errorf("scan table = %d; want <= %d (hard cap not enforced)", len(c.scan), 2*max)
	}
	if len(c.scan) >= fed {
		t.Errorf("scan table = %d; nothing was shed (fed %d distinct sources)", len(c.scan), fed)
	}
}

// MaxSources <= 0 falls back to the built-in default rather than disabling the
// cap (0 would otherwise shed every entry on the first sweep).
func TestCorrelatorMaxSourcesDefault(t *testing.T) {
	c, err := New(config.Correlate{})
	if err != nil {
		t.Fatal(err)
	}
	if c.maxSources != defaultCorrMaxSources {
		t.Errorf("maxSources = %d; want default %d", c.maxSources, defaultCorrMaxSources)
	}
	c2, err := New(config.Correlate{MaxSources: 1234})
	if err != nil {
		t.Fatal(err)
	}
	if c2.maxSources != 1234 {
		t.Errorf("maxSources = %d; want 1234", c2.maxSources)
	}
}

// shedMap only acts at/above the cap and leaves 3/4 headroom.
func TestShedMap(t *testing.T) {
	m := map[string]int{}
	for i := 0; i < 80; i++ {
		m[fmt.Sprintf("k%d", i)] = i
	}
	shedMap(m, 100) // under cap → no-op
	if len(m) != 80 {
		t.Fatalf("under-cap map shed to %d; want 80", len(m))
	}
	for i := 80; i < 100; i++ {
		m[fmt.Sprintf("k%d", i)] = i
	}
	shedMap(m, 100) // at cap → shed to 3/4
	if len(m) != 75 {
		t.Fatalf("at-cap map shed to %d; want 75", len(m))
	}
	// A zero/negative cap never sheds (default-fallback is handled in New).
	shedMap(m, 0)
	if len(m) != 75 {
		t.Fatalf("cap=0 shed to %d; want 75 (no-op)", len(m))
	}
}
