package pgstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// These tests run only when TARPIT_PG_TEST_DSN points at a *disposable*
// PostgreSQL database (they reset the events/iocs tables). Without it they skip,
// so the suite stays green on machines with no Postgres; CI sets the DSN to
// exercise the backend against a real server (docs/database-backend.md §6).
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("TARPIT_PG_TEST_DSN")
	if dsn == "" {
		t.Skip("set TARPIT_PG_TEST_DSN to a disposable Postgres database to run pgstore tests")
	}
	st, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	// Reset to a clean slate via the public API: prune everything older than a
	// future cutoff removes all rows.
	if _, _, err := st.PruneBefore(context.Background(), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("reset: %v", err)
	}
	return st
}

func TestPgRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	mk := func(id, src, handler string, sev event.Severity, when time.Time, meta map[string]any) *event.Event {
		return &event.Event{
			ID: id, Time: when, Sensor: "s1", RuleID: "rule:" + handler, Severity: sev,
			Source: event.Endpoint{IP: src, Port: 4444}, Dest: event.Endpoint{IP: "10.0.0.1", Port: 22},
			Proto: "tcp", Handler: handler, BannerSent: "SSH-2.0-x", PayloadLen: 3, Meta: meta,
		}
	}
	e1 := mk("a", "1.1.1.1", "ssh", event.SeverityHigh, now.Add(-2*time.Minute),
		map[string]any{"geo_country": "DE", "asn": 12345, "ja3": "abc", "geo_city": "Berlin"})
	e2 := mk("b", "2.2.2.2", "http", event.SeverityMedium, now.Add(-1*time.Minute),
		map[string]any{"geo_country": "US", "asn": 67890})

	if err := st.InsertBatch(ctx, []*event.Event{e1, e2}); err != nil {
		t.Fatalf("insert batch: %v", err)
	}

	// Query newest-first.
	evs, err := st.Query(ctx, store.Filter{Since: now.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(evs) != 2 || evs[0].ID != "b" || evs[1].ID != "a" {
		t.Fatalf("query order = %v; want [b a]", ids(evs))
	}
	if evs[1].Meta["geo_country"] != "DE" {
		t.Errorf("meta round-trip lost geo_country: %v", evs[1].Meta)
	}

	// Get by id.
	got, err := st.Get(ctx, "a")
	if err != nil || got.Handler != "ssh" {
		t.Fatalf("get a: %v / %+v", err, got)
	}

	// Filters: handler, country (materialized), ASN (jsonb), text.
	checkCount(t, st, store.Filter{Handler: "http"}, 1)
	checkCount(t, st, store.Filter{Country: "DE"}, 1)
	checkCount(t, st, store.Filter{ASN: 12345}, 1)
	checkCount(t, st, store.Filter{Text: "berlin"}, 1) // case-insensitive in meta

	// Summary.
	sum, err := st.Summary(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if sum.Total != 2 || sum.ByHandler["ssh"] != 1 || sum.ByCountry["US"] != 1 {
		t.Errorf("summary = %+v", sum)
	}

	// Fingerprints (ja3 in meta).
	fps, err := st.Fingerprints(ctx, now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatalf("fingerprints: %v", err)
	}
	if len(fps) != 1 || fps[0].Kind != "ja3" || fps[0].Value != "abc" {
		t.Errorf("fingerprints = %+v", fps)
	}

	// IOC upsert/dedup.
	first, err := st.UpsertIOC(ctx, "sha256", "deadbeef", "malware:capture", "s1", "1.1.1.1", event.SeverityHigh, now)
	if err != nil || !first {
		t.Fatalf("first upsert: first=%v err=%v", first, err)
	}
	again, err := st.UpsertIOC(ctx, "sha256", "deadbeef", "malware:capture", "s1", "1.1.1.1", event.SeverityCritical, now)
	if err != nil || again {
		t.Fatalf("second upsert: first=%v err=%v (want first=false)", again, err)
	}
	iocs, err := st.QueryIOCs(ctx, store.IOCFilter{})
	if err != nil || len(iocs) != 1 || iocs[0].Count != 2 {
		t.Fatalf("query iocs: %v / %+v", err, iocs)
	}

	// PruneBefore removes everything older than a future cutoff.
	delE, delI, err := st.PruneBefore(ctx, now.Add(time.Hour))
	if err != nil || delE != 2 || delI != 1 {
		t.Fatalf("prune: events=%d iocs=%d err=%v", delE, delI, err)
	}
}

func ids(evs []*event.Event) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.ID
	}
	return out
}

func checkCount(t *testing.T, st *Store, f store.Filter, want int) {
	t.Helper()
	evs, err := st.Query(context.Background(), f)
	if err != nil {
		t.Fatalf("query %+v: %v", f, err)
	}
	if len(evs) != want {
		t.Errorf("filter %+v matched %d; want %d", f, len(evs), want)
	}
}

// TestPgPartitionRetention checks that an event lands in its month's partition
// and that PruneBefore drops the whole partition once it is older than the cut.
func TestPgPartitionRetention(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.AddDate(0, -3, 0) // three months ago

	// Provision the old + current months so each event lands in a dedicated
	// partition rather than DEFAULT.
	st.ensurePartitions(ctx, old)
	st.ensurePartitions(ctx, now)

	oldEv := &event.Event{ID: "old", Time: old, Sensor: "s", RuleID: "r", Severity: event.SeverityHigh,
		Source: event.Endpoint{IP: "1.1.1.1"}, Proto: "tcp", Handler: "ssh"}
	newEv := &event.Event{ID: "new", Time: now, Sensor: "s", RuleID: "r", Severity: event.SeverityHigh,
		Source: event.Endpoint{IP: "2.2.2.2"}, Proto: "tcp", Handler: "ssh"}
	if err := st.InsertBatch(ctx, []*event.Event{oldEv, newEv}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	_, _, oldName := monthBounds(old)
	if !hasPartition(t, st, oldName) {
		t.Fatalf("expected partition %s to exist after insert", oldName)
	}

	// Retain one month: the three-month-old partition is fully expired and must
	// be dropped; the current month survives.
	if _, _, err := st.PruneBefore(ctx, now.AddDate(0, -1, 0)); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if hasPartition(t, st, oldName) {
		t.Errorf("partition %s should have been dropped", oldName)
	}
	evs, err := st.Query(ctx, store.Filter{Since: now.AddDate(-1, 0, 0)})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(evs) != 1 || evs[0].ID != "new" {
		t.Errorf("after prune survivors = %v; want [new]", ids(evs))
	}
}

func hasPartition(t *testing.T, st *Store, name string) bool {
	t.Helper()
	var n int
	if err := st.db.QueryRowContext(context.Background(), `
SELECT COUNT(*) FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid
JOIN pg_class p ON p.oid = i.inhparent
WHERE p.relname = 'events' AND c.relname = $1`, name).Scan(&n); err != nil {
		t.Fatalf("hasPartition: %v", err)
	}
	return n > 0
}
