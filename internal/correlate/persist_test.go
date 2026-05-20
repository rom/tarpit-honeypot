package correlate

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestCorrelatorPersistRoundTrip(t *testing.T) {
	cfg := config.Correlate{
		PortScan:   config.CorrPortScan{Enabled: true, DistinctPorts: 100, Window: time.Hour, Severity: "high"},
		BruteForce: config.CorrBruteForce{Enabled: true, Attempts: 100, Window: time.Hour, Severity: "high"},
		SlowScan:   config.CorrSlowScan{Enabled: true, DistinctPorts: 100, Window: 24 * time.Hour, Severity: "high"},
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	c.Observe(&event.Event{Source: event.Endpoint{IP: "203.0.113.1"}, Dest: event.Endpoint{Port: 22}, RuleID: "listener:ssh", Time: now,
		Meta: map[string]any{"auth_user": "root", "auth_pass": "toor"}})
	c.Observe(&event.Event{Source: event.Endpoint{IP: "203.0.113.1"}, Dest: event.Endpoint{Port: 80}, RuleID: "listener:http", Time: now})

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := c.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Fresh correlator restores the prior state.
	c2, _ := New(cfg)
	if err := c2.Restore(path); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(c2.scan["203.0.113.1"].ports) != 2 {
		t.Errorf("restored scan ports = %v; want 2", c2.scan["203.0.113.1"].ports)
	}
	if c2.slow["203.0.113.1"] == nil {
		t.Error("slow-scan state not restored")
	}
	// brute creds survive the round trip.
	bk := "203.0.113.1"
	if c2.brute[bk] == nil || len(c2.brute[bk].creds) == 0 {
		t.Errorf("brute creds not restored: %+v", c2.brute[bk])
	}
}

func TestRestoreMissingFileIsNoError(t *testing.T) {
	c, _ := New(config.Correlate{})
	if err := c.Restore(filepath.Join(t.TempDir(), "nope.json")); err != nil {
		t.Errorf("missing state file should be a no-op; got %v", err)
	}
}
