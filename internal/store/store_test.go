package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Regression for "unable to open database file (14)" on the per-source profile
// page: the profile query filters by src_ip then ORDER BY time, which spilled
// to an on-disk temp file SQLite could not open under a locked-down runtime.
// temp_store=MEMORY plus the composite (src_ip, time) index remove the temp
// file entirely.
func TestTempStoreMemoryAndProfileQuery(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	var ts int
	if err := s.db.QueryRowContext(ctx, "PRAGMA temp_store").Scan(&ts); err != nil {
		t.Fatal(err)
	}
	if ts != 2 { // 2 == MEMORY
		t.Errorf("PRAGMA temp_store = %d, want 2 (MEMORY)", ts)
	}

	var idx string
	if err := s.db.QueryRowContext(ctx,
		"SELECT name FROM sqlite_master WHERE type='index' AND name='idx_events_src_ip_time'").Scan(&idx); err != nil {
		t.Fatalf("composite (src_ip, time) index missing: %v", err)
	}

	base := time.Now().UTC()
	for i := 0; i < 5; i++ {
		e := mkEvent(fmt.Sprintf("a%d", i), "203.0.113.7", "listener:ssh", event.SeverityHigh, base.Add(time.Duration(i)*time.Minute))
		if err := s.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Insert(ctx, mkEvent("z", "198.51.100.9", "listener:http", event.SeverityLow, base)); err != nil {
		t.Fatal(err)
	}

	rows, err := s.Query(ctx, Filter{SourceIP: "203.0.113.7", Since: base.Add(-time.Hour), Limit: 100})
	if err != nil {
		t.Fatalf("profile-style query failed: %v", err)
	}
	if len(rows) != 5 {
		t.Fatalf("got %d rows for the source, want 5", len(rows))
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1].Time.Before(rows[i].Time) {
			t.Errorf("rows not newest-first at %d: %v then %v", i, rows[i-1].Time, rows[i].Time)
		}
	}
}

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

func TestEnsureIndexesCreatesAll(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.db.Query(`SELECT name FROM sqlite_master WHERE type='index'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		have[n] = true
	}
	// Every named index in indexStmts (the ones we manage) must be present —
	// confirms ensureIndexes runs after migrate so sensor_id's column exists,
	// and that moving them out of the schema const didn't drop any.
	for _, want := range []string{
		"idx_events_time", "idx_events_src_ip", "idx_events_src_ip_time",
		"idx_events_rule_id", "idx_events_severity", "idx_events_severity_time",
		"idx_events_rule_id_time", "idx_events_proto_time", "idx_events_handler_time",
		"idx_events_sensor_id", "idx_iocs_last_seen", "idx_iocs_type",
	} {
		if !have[want] {
			t.Errorf("index %q missing after Open", want)
		}
	}
}

func TestFreeDiskBytes(t *testing.T) {
	// On the test platform (unix) this should resolve; the non-unix stub returns
	// ok=false, which we accept too — we only assert it never reports a bogus
	// negative free count.
	if free, ok := freeDiskBytes(t.TempDir()); ok && free < 0 {
		t.Errorf("freeDiskBytes returned negative free space: %d", free)
	}
}

func TestQueryDstIP(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	for i, dst := range []string{"192.0.2.10", "192.0.2.10", "192.0.2.11"} {
		e := mkEvent(fmt.Sprintf("e%d", i), "9.9.9.9", "r", event.SeverityLow, now)
		e.Dest.IP = dst
		if err := s.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Query(ctx, Filter{Since: now.Add(-time.Hour), DstIP: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("DstIP filter = %d events; want 2", len(got))
	}
	for _, ev := range got {
		if ev.Dest.IP != "192.0.2.10" {
			t.Errorf("got dst %q; want 192.0.2.10", ev.Dest.IP)
		}
	}
}

func TestQueryHandlersAndNoPayload(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	mk := func(id, handler string) *event.Event {
		e := mkEvent(id, "1.1.1.1", "r", event.SeverityLow, now)
		e.Handler = handler
		e.PayloadBase64 = "c2VjcmV0LWJ5dGVz" // base64("secret-bytes")
		e.PayloadLen = 12
		e.BannerSent = "banner-" + handler
		return e
	}
	for _, e := range []*event.Event{
		mk("h1", "http"), mk("h2", "https"), mk("h3", "http2"),
		mk("d1", "dns"), mk("m1", "mysql"), mk("s1", "ssh"),
	} {
		if err := s.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	since := now.Add(-time.Hour)

	// Handlers IN (…) returns only the named handlers (the web-category set).
	got, err := s.Query(ctx, Filter{Since: since, Handlers: []string{"http", "https", "http2"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("web handlers query = %d events; want 3", len(got))
	}
	for _, ev := range got {
		if ev.Handler != "http" && ev.Handler != "https" && ev.Handler != "http2" {
			t.Errorf("unexpected handler %q in web query", ev.Handler)
		}
	}

	// A single-element set behaves like an equality filter.
	dns, err := s.Query(ctx, Filter{Since: since, Handlers: []string{"dns"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(dns) != 1 || dns[0].ID != "d1" {
		t.Errorf("dns handler query = %v; want one event d1", dns)
	}

	// NoPayload elides the payload blob + banner without dropping the row.
	np, err := s.Query(ctx, Filter{Since: since, Handlers: []string{"dns"}, NoPayload: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(np) != 1 {
		t.Fatalf("NoPayload query = %d events; want 1", len(np))
	}
	if np[0].PayloadBase64 != "" || np[0].BannerSent != "" {
		t.Errorf("NoPayload should elide payload/banner, got payload=%q banner=%q", np[0].PayloadBase64, np[0].BannerSent)
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

// TestSummaryHandlerTargetRollups verifies the index-backed by-handler and
// by-target (dst_ip) rollups, and that they read from their covering indexes.
// TestCountryColumn covers the materialized country column: it's filled from
// meta.geo_country at insert, feeds Summary.ByCountry + an indexed country
// filter, and backfillCountry repopulates rows that predate the column.
func TestCountryColumn(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	mk := func(id, cc string) *event.Event {
		ev := &event.Event{ID: id, Time: now, Sensor: "t", RuleID: "r",
			Severity: event.SeverityMedium, Source: event.Endpoint{IP: "1.2.3.4"}, Proto: "tcp"}
		if cc != "" {
			ev.Meta = map[string]any{"geo_country": cc}
		}
		return ev
	}
	_ = s.Insert(ctx, mk("a", "US"))
	_ = s.Insert(ctx, mk("b", "US"))
	_ = s.Insert(ctx, mk("c", "DE"))
	_ = s.Insert(ctx, mk("d", "")) // no geo

	// Summary rollup (index-backed) excludes the no-geo row.
	sum, err := s.Summary(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sum.ByCountry["US"] != 2 || sum.ByCountry["DE"] != 1 {
		t.Errorf("ByCountry = %v; want US:2 DE:1", sum.ByCountry)
	}
	if _, ok := sum.ByCountry[""]; ok {
		t.Errorf("ByCountry should exclude empty country: %v", sum.ByCountry)
	}

	// Indexed country filter returns only matching rows.
	evs, err := s.Query(ctx, Filter{Since: now.Add(-time.Hour), Country: "US"})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Errorf("country=US returned %d events; want 2", len(evs))
	}

	// The filter must use the country index, not a json_extract scan.
	var plan strings.Builder
	rows, _ := s.db.QueryContext(ctx,
		`EXPLAIN QUERY PLAN SELECT id FROM events WHERE time >= ? AND country = ? ORDER BY time DESC`,
		now.Add(-time.Hour).UnixNano(), "US")
	for rows.Next() {
		var a, b, c int
		var detail string
		_ = rows.Scan(&a, &b, &c, &detail)
		plan.WriteString(detail + "\n")
	}
	rows.Close()
	if !strings.Contains(plan.String(), "idx_events_country_time") {
		t.Errorf("country filter not using idx_events_country_time:\n%s", plan.String())
	}

	// Backfill: simulate a pre-column row by nulling its country, then heal it.
	if _, err := s.db.ExecContext(ctx, `UPDATE events SET country = NULL WHERE id = 'c'`); err != nil {
		t.Fatal(err)
	}
	s.backfillCountry(ctx)
	var got string
	if err := s.db.QueryRowContext(ctx, `SELECT country FROM events WHERE id = 'c'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "DE" {
		t.Errorf("backfill country = %q; want DE", got)
	}
}

func TestSummaryHandlerTargetRollups(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	mk := func(id, handler, dst string) *event.Event {
		return &event.Event{ID: id, Time: now, Sensor: "t", RuleID: "r",
			Severity: event.SeverityMedium, Source: event.Endpoint{IP: "1.2.3.4"},
			Dest: event.Endpoint{IP: dst, Port: 80}, Proto: "tcp", Handler: handler}
	}
	_ = s.Insert(ctx, mk("a", "ssh", "10.0.0.1"))
	_ = s.Insert(ctx, mk("b", "ssh", "10.0.0.1"))
	_ = s.Insert(ctx, mk("c", "http", "10.0.0.2"))

	sum, err := s.Summary(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sum.ByHandler["ssh"] != 2 || sum.ByHandler["http"] != 1 {
		t.Errorf("ByHandler = %v; want ssh:2 http:1", sum.ByHandler)
	}
	if sum.ByTarget["10.0.0.1"] != 2 || sum.ByTarget["10.0.0.2"] != 1 {
		t.Errorf("ByTarget = %v; want 10.0.0.1:2 10.0.0.2:1", sum.ByTarget)
	}

	// The rollups must read from their covering (col,time) indexes, not scan.
	for _, c := range []struct{ col, idx string }{
		{"handler", "idx_events_handler_time"}, {"dst_ip", "idx_events_dst_ip_time"},
	} {
		var plan strings.Builder
		rows, err := s.db.QueryContext(ctx, `EXPLAIN QUERY PLAN
SELECT `+c.col+`, COUNT(*) cc FROM events WHERE time >= ? AND `+c.col+` != '' GROUP BY `+c.col+` ORDER BY cc DESC LIMIT 50`,
			now.Add(-time.Hour).UnixNano())
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var a, b, d int
			var detail string
			_ = rows.Scan(&a, &b, &d, &detail)
			plan.WriteString(detail + "\n")
		}
		rows.Close()
		if !strings.Contains(plan.String(), c.idx) {
			t.Errorf("%s rollup not using %s:\n%s", c.col, c.idx, plan.String())
		}
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

func TestInsertBatch(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	evs := []*event.Event{
		mkEvent("ba", "1.1.1.1", "listener:ssh", event.SeverityHigh, now.Add(-3*time.Minute)),
		mkEvent("bb", "2.2.2.2", "listener:http", event.SeverityMedium, now.Add(-2*time.Minute)),
		mkEvent("bc", "3.3.3.3", "cve:CVE-2021-44228", event.SeverityCritical, now.Add(-1*time.Minute)),
	}
	if err := s.InsertBatch(ctx, evs); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}
	got, err := s.Query(ctx, Filter{Since: now.Add(-time.Hour), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("after batch: %d events; want 3", len(got))
	}
	// Empty batch is a no-op, not an error.
	if err := s.InsertBatch(ctx, nil); err != nil {
		t.Errorf("empty batch: %v", err)
	}
}

func TestMitrePersists(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	ev := mkEvent("m1", "1.2.3.4", "cve:CVE-2021-44228", event.SeverityCritical, time.Now().UTC())
	ev.MitreTechniques = []string{"T1190"}
	ev.MitreTactics = []string{"initial-access"}
	ev.MitreDefenses = []string{"D3-NTA", "D3-ITF"}
	if err := s.Insert(ctx, ev); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "m1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.MitreTechniques) != 1 || got.MitreTechniques[0] != "T1190" {
		t.Errorf("techniques = %v; want [T1190]", got.MitreTechniques)
	}
	if len(got.MitreTactics) != 1 || got.MitreTactics[0] != "initial-access" {
		t.Errorf("tactics = %v", got.MitreTactics)
	}
	if len(got.MitreDefenses) != 2 {
		t.Errorf("defenses = %v; want 2", got.MitreDefenses)
	}
	// An event with no mitre tags round-trips with nil slices (not [""]).
	plain := mkEvent("m2", "5.6.7.8", "listener:http", event.SeverityLow, time.Now().UTC())
	if err := s.Insert(ctx, plain); err != nil {
		t.Fatal(err)
	}
	g2, _ := s.Get(ctx, "m2")
	if len(g2.MitreTechniques) != 0 {
		t.Errorf("plain event techniques = %v; want empty", g2.MitreTechniques)
	}
}

func TestUpsertAndQueryIOC(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	isNew, err := s.UpsertIOC(ctx, "sha256", "deadbeef", "malware:capture", "sid", "1.1.1.1", event.SeverityHigh, now)
	if err != nil || !isNew {
		t.Fatalf("first upsert: isNew=%v err=%v; want true/nil", isNew, err)
	}
	isNew, err = s.UpsertIOC(ctx, "sha256", "deadbeef", "malware:capture", "sid", "2.2.2.2", event.SeverityCritical, now.Add(time.Minute))
	if err != nil || isNew {
		t.Fatalf("second upsert: isNew=%v; want false", isNew)
	}
	rows, err := s.QueryIOCs(ctx, IOCFilter{Type: "sha256", Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatalf("query: %d rows err=%v", len(rows), err)
	}
	r := rows[0]
	if r.Count != 2 || r.Severity != event.SeverityCritical || r.LastSource != "2.2.2.2" {
		t.Errorf("row = %+v; want count 2, sev critical, last_source 2.2.2.2", r)
	}
	sum, _ := s.IOCSummary(ctx, time.Time{})
	if sum["sha256"] != 1 {
		t.Errorf("summary sha256 = %d; want 1", sum["sha256"])
	}
}

func TestDiagnosePath(t *testing.T) {
	// Missing parent directory.
	if got := diagnosePath(filepath.Join(t.TempDir(), "nope", "events.db")); got == "" ||
		!contains(got, "does not exist") {
		t.Errorf("missing parent: %q", got)
	}
	// A path whose parent is actually a file, not a directory.
	dir := t.TempDir()
	notdir := filepath.Join(dir, "afile")
	if err := os.WriteFile(notdir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := diagnosePath(filepath.Join(notdir, "events.db")); got == "" ||
		!contains(got, "not a directory") {
		t.Errorf("parent-is-file: %q", got)
	}
	// The DB path itself is a directory.
	asdir := filepath.Join(dir, "events.db")
	if err := os.Mkdir(asdir, 0o750); err != nil {
		t.Fatal(err)
	}
	if got := diagnosePath(asdir); got == "" || !contains(got, "is a directory") {
		t.Errorf("db-is-dir: %q", got)
	}
	// A perfectly fine path yields no complaint.
	if got := diagnosePath(filepath.Join(dir, "fresh.db")); got != "" {
		t.Errorf("healthy path should diagnose clean, got %q", got)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// TestSummaryUsesIndexes guards the dashboard's scalability: each
// "WHERE time >= ? GROUP BY <col>" summary pass must be served by a composite
// (col,time) index, not a full table SCAN — otherwise the summary degrades to
// O(rows) row reads and times out as the events table grows.
func TestSummaryUsesIndexes(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	sinceNS := now.Add(-time.Hour).UnixNano()
	cases := []struct{ name, query, wantIndex string }{
		{"severity", `SELECT severity, COUNT(*) FROM events WHERE time >= ? GROUP BY severity`, "idx_events_severity_time"},
		{"rule_id", `SELECT rule_id, COUNT(*) FROM events WHERE time >= ? GROUP BY rule_id`, "idx_events_rule_id_time"},
		{"proto", `SELECT proto, COUNT(*) FROM events WHERE time >= ? AND proto != '' GROUP BY proto`, "idx_events_proto_time"},
		{"src_ip", `SELECT src_ip, COUNT(*) FROM events WHERE time >= ? AND src_ip != '' GROUP BY src_ip`, "idx_events_src_ip_time"},
	}
	for _, c := range cases {
		rows, err := s.db.Query("EXPLAIN QUERY PLAN "+c.query, sinceNS)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var plan string
		for rows.Next() {
			var id, parent, notused int
			var detail string
			if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			plan += detail + "\n"
		}
		rows.Close()
		if !strings.Contains(plan, c.wantIndex) {
			t.Errorf("%s GROUP BY does not use %s; plan=\n%s", c.name, c.wantIndex, plan)
		}
		if strings.Contains(plan, "SCAN events\n") || strings.HasSuffix(strings.TrimSpace(plan), "SCAN events") {
			t.Errorf("%s GROUP BY falls back to a full table SCAN; plan=\n%s", c.name, plan)
		}
	}
}
