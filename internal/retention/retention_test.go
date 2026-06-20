package retention

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// TestRunnerPrunesStaleIOCs drives the retention runner against a real SQLite
// store through the engine-neutral Pruner, confirming a stale indicator is
// dropped and a fresh one survives.
func TestRunnerPrunesStaleIOCs(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	// Stale: last seen 10 days ago. Fresh: seen now.
	if _, err := st.UpsertIOC(ctx, "sha256", "stale", "malware:capture", "s", "1.1.1.1", event.SeverityHigh, now.Add(-10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertIOC(ctx, "sha256", "fresh", "malware:capture", "s", "2.2.2.2", event.SeverityHigh, now); err != nil {
		t.Fatal(err)
	}

	// A 7-day retention window: tick() prunes anything last seen before the cutoff.
	r := &Runner{Days: 7, Store: st}
	r.tick(ctx)

	rows, err := st.QueryIOCs(ctx, store.IOCFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Value != "fresh" {
		t.Errorf("survivors = %v; want only [fresh]", rows)
	}
}

// TestPruneBeforeCounts checks the primitive reports rows removed from each table.
func TestPruneBeforeCounts(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := st.UpsertIOC(ctx, "sha256", "stale", "r", "s", "1.1.1.1", event.SeverityHigh, now.Add(-10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, iocs, err := st.PruneBefore(ctx, now.Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if iocs != 1 {
		t.Fatalf("pruned %d IOCs; want 1", iocs)
	}
}
