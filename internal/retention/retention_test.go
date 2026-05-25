package retention

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func TestPruneIOCs(t *testing.T) {
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
	n := pruneIOCs(ctx, st.DB(), now.Add(-7*24*time.Hour))
	if n != 1 {
		t.Fatalf("pruned %d; want 1 (the stale indicator)", n)
	}
	rows, err := st.QueryIOCs(ctx, store.IOCFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Value != "fresh" {
		t.Errorf("survivors = %v; want only [fresh]", rows)
	}
	// nil DB is a safe no-op.
	if got := pruneIOCs(ctx, nil, now); got != 0 {
		t.Errorf("nil db pruned %d; want 0", got)
	}
}
