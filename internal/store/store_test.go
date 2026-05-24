package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestAnomaliesRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	e := mkEvent("x", "9.9.9.9", "listener:ssh", event.SeverityHigh, time.Now().UTC())
	e.Anomalies = []string{"ssh-id-not-ssh", "ssh-id-non-printable"}
	if err := s.Insert(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Anomalies) != 2 || got.Anomalies[0] != "ssh-id-not-ssh" {
		t.Errorf("anomalies lost in Get round trip: %v", got.Anomalies)
	}
	rows, err := s.Query(ctx, Filter{Since: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || len(rows[0].Anomalies) != 2 {
		t.Errorf("anomalies lost in Query round trip: %+v", rows)
	}
}

func TestMigrateAddsAnomaliesColumn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.db")
	// Create a DB with the pre-anomalies schema (no anomalies column).
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE events (
  id TEXT PRIMARY KEY, time INTEGER NOT NULL, sensor TEXT, rule_id TEXT,
  severity INTEGER, src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
  proto TEXT, handler TEXT, banner_sent TEXT, payload_b64 TEXT, payload_len INTEGER,
  meta_json TEXT)`); err != nil {
		t.Fatal(err)
	}
	// A realistic old row: the pre-migration Insert always wrote every column
	// (empty strings, not NULL), so mirror that.
	if _, err := db.Exec(`INSERT INTO events
(id, time, sensor, rule_id, severity, src_ip, src_port, dst_ip, dst_port,
 proto, handler, banner_sent, payload_b64, payload_len, meta_json)
VALUES ('old', 1, 's', 'r', 1, '', 0, '', 0, 'tcp', '', '', '', 0, '')`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// Opening via the store must migrate (add the column) without error.
	s, err := Open(dir, 0)
	if err != nil {
		t.Fatalf("open/migrate old db: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	old, err := s.Get(ctx, "old")
	if err != nil {
		t.Fatalf("read old row after migration: %v", err)
	}
	if len(old.Anomalies) != 0 {
		t.Errorf("old row should have no anomalies, got %v", old.Anomalies)
	}
	e := mkEvent("new", "1.2.3.4", "listener:http", event.SeverityHigh, time.Now().UTC())
	e.Anomalies = []string{"http-method-unknown"}
	if err := s.Insert(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "new")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Anomalies) != 1 || got.Anomalies[0] != "http-method-unknown" {
		t.Errorf("post-migration anomalies round trip failed: %v", got.Anomalies)
	}
}

func mkEvent(id, srcIP, rule string, sev event.Severity, t time.Time) *event.Event {
	return &event.Event{
		ID:       id,
		Time:     t,
		Sensor:   "test",
		RuleID:   rule,
		Severity: sev,
		Source:   event.Endpoint{IP: srcIP, Port: 12345},
		Dest:     event.Endpoint{IP: "10.0.0.1", Port: 22},
		Proto:    "tcp",
		Handler:  "ssh",
		Meta:     map[string]any{"note": "test"},
	}
}

func TestQueryTextAndEventsPerHour(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	e1 := mkEvent("a", "1.1.1.1", "webapp:sqli", event.SeverityHigh, now.Add(-30*time.Minute))
	e1.Meta = map[string]any{"tools": []string{"sqlmap"}}
	e2 := mkEvent("b", "2.2.2.2", "listener:ssh", event.SeverityLow, now.Add(-90*time.Minute))
	e2.BannerSent = "SSH-2.0-OpenSSH_9.2"
	_ = s.Insert(ctx, e1)
	_ = s.Insert(ctx, e2)

	since := now.Add(-3 * time.Hour)
	check := func(text, wantID string) {
		got, err := s.Query(ctx, Filter{Since: since, Text: text})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].ID != wantID {
			t.Errorf("text %q = %v; want one event %q", text, got, wantID)
		}
	}
	check("sqlmap", "a")      // meta
	check("OpenSSH", "b")     // banner
	check("webapp:sqli", "a") // rule_id

	buckets, err := s.EventsPerHour(ctx, since)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, b := range buckets {
		total += b.Count
	}
	if total != 2 {
		t.Errorf("EventsPerHour total = %d; want 2", total)
	}
	if len(buckets) < 3 {
		t.Errorf("expected zero-filled hourly buckets, got %d", len(buckets))
	}
}

func TestSourceAggregates(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	// 1.1.1.1: 2 high + 1 critical (distinct rules r1, r2); 2.2.2.2: 1 low.
	_ = s.Insert(ctx, mkEvent("a", "1.1.1.1", "r1", event.SeverityHigh, now.Add(-3*time.Minute)))
	_ = s.Insert(ctx, mkEvent("b", "1.1.1.1", "r1", event.SeverityHigh, now.Add(-2*time.Minute)))
	_ = s.Insert(ctx, mkEvent("c", "1.1.1.1", "r2", event.SeverityCritical, now.Add(-time.Minute)))
	_ = s.Insert(ctx, mkEvent("d", "2.2.2.2", "r3", event.SeverityLow, now))

	aggs, err := s.SourceAggregates(ctx, now.Add(-time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(aggs) != 2 {
		t.Fatalf("aggregates = %d; want 2", len(aggs))
	}
	// Ordered by severity-weighted threat score: 1.1.1.1 (9+9+16=34) first.
	top := aggs[0]
	if top.IP != "1.1.1.1" {
		t.Errorf("top source = %q; want 1.1.1.1", top.IP)
	}
	if top.Count != 3 {
		t.Errorf("count = %d; want 3", top.Count)
	}
	if top.MaxSeverity != event.SeverityCritical {
		t.Errorf("max severity = %v; want critical", top.MaxSeverity)
	}
	if top.DistinctRules != 2 {
		t.Errorf("distinct rules = %d; want 2", top.DistinctRules)
	}
	if top.Weight != 34 {
		t.Errorf("weight = %d; want 34", top.Weight)
	}
}

func TestInsertAndQuery(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	evs := []*event.Event{
		mkEvent("a", "1.1.1.1", "listener:ssh", event.SeverityHigh, now.Add(-3*time.Minute)),
		mkEvent("b", "2.2.2.2", "listener:http", event.SeverityMedium, now.Add(-2*time.Minute)),
		mkEvent("c", "1.1.1.1", "listener:ssh", event.SeverityHigh, now.Add(-1*time.Minute)),
	}
	for _, e := range evs {
		if err := s.Insert(ctx, e); err != nil {
			t.Fatalf("insert %s: %v", e.ID, err)
		}
	}

	got, err := s.Query(ctx, Filter{Since: now.Add(-1 * time.Hour), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 events; got %d", len(got))
	}
	// Newest first
	if got[0].ID != "c" {
		t.Errorf("expected c first; got %s", got[0].ID)
	}

	got, _ = s.Query(ctx, Filter{Since: now.Add(-1 * time.Hour), SourceIP: "1.1.1.1", Limit: 100})
	if len(got) != 2 {
		t.Errorf("source filter: expected 2; got %d", len(got))
	}

	got, _ = s.Query(ctx, Filter{Since: now.Add(-1 * time.Hour), RuleID: "listener:http", Limit: 100})
	if len(got) != 1 || got[0].ID != "b" {
		t.Errorf("rule filter: got %v", got)
	}

	got, _ = s.Query(ctx, Filter{Since: now.Add(-1 * time.Hour), MinSeverity: event.SeverityHigh, Limit: 100})
	if len(got) != 2 {
		t.Errorf("severity filter: expected 2; got %d", len(got))
	}

	one, err := s.Get(ctx, "b")
	if err != nil || one.RuleID != "listener:http" {
		t.Errorf("Get b: ev=%+v err=%v", one, err)
	}
	if one.Meta["note"] != "test" {
		t.Errorf("meta lost in round trip; got %v", one.Meta)
	}
}

func TestSummary(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	_ = s.Insert(ctx, mkEvent("a", "1.1.1.1", "r1", event.SeverityHigh, now))
	_ = s.Insert(ctx, mkEvent("b", "1.1.1.1", "r1", event.SeverityHigh, now))
	_ = s.Insert(ctx, mkEvent("c", "2.2.2.2", "r2", event.SeverityLow, now))

	sum, err := s.Summary(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Total != 3 {
		t.Errorf("total: %d", sum.Total)
	}
	if sum.BySeverity["high"] != 2 {
		t.Errorf("by_severity[high]: %d", sum.BySeverity["high"])
	}
	if sum.ByRule["r1"] != 2 {
		t.Errorf("by_rule[r1]: %d", sum.ByRule["r1"])
	}
	if len(sum.TopSources) == 0 || sum.TopSources[0].IP != "1.1.1.1" {
		t.Errorf("top_sources: %v", sum.TopSources)
	}
}

func TestSummaryByProto(t *testing.T) {
	st, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	for i, p := range []string{"tcp", "tcp", "udp", "icmp"} {
		ev := &event.Event{ID: event.NewID(), Time: now, Sensor: "s", RuleID: "r",
			Severity: event.SeverityLow, Proto: p, Source: event.Endpoint{IP: "1.2.3.4"}}
		if err := st.Insert(context.Background(), ev); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	sum, err := st.Summary(context.Background(), now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sum.ByProto["tcp"] != 2 || sum.ByProto["udp"] != 1 || sum.ByProto["icmp"] != 1 {
		t.Errorf("ByProto = %v; want tcp2 udp1 icmp1", sum.ByProto)
	}
}
