package store

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// UpsertIOCs: batched upsert reports first-seen per row (including correct
// in-batch de-duplication) and MAX-folds severity on conflict.
func TestUpsertIOCsBatch(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()

	batch := []IOCUpsert{
		{Type: "ip", Value: "1.2.3.4", RuleID: "r", Sensor: "s", Source: "1.2.3.4", Severity: event.SeverityHigh, Time: now},
		{Type: "ip", Value: "5.6.7.8", RuleID: "r", Sensor: "s", Source: "5.6.7.8", Severity: event.SeverityMedium, Time: now},
		{Type: "ip", Value: "1.2.3.4", RuleID: "r", Sensor: "s", Source: "1.2.3.4", Severity: event.SeverityCritical, Time: now.Add(time.Second)},
	}
	isNew, err := s.UpsertIOCs(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(isNew) != 3 || !isNew[0] || !isNew[1] || isNew[2] {
		t.Fatalf("isNew = %v; want [true true false]", isNew)
	}

	rows, err := s.QueryIOCs(ctx, IOCFilter{Type: "ip"})
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	sev := map[string]event.Severity{}
	for _, r := range rows {
		count[r.Value] = r.Count
		sev[r.Value] = r.Severity
	}
	if count["1.2.3.4"] != 2 || count["5.6.7.8"] != 1 {
		t.Errorf("counts = %v; want 1.2.3.4:2 5.6.7.8:1", count)
	}
	if sev["1.2.3.4"] != event.SeverityCritical {
		t.Errorf("severity for 1.2.3.4 = %v; want critical (MAX-folded)", sev["1.2.3.4"])
	}

	if out, err := s.UpsertIOCs(ctx, nil); err != nil || out != nil {
		t.Errorf("empty batch: out=%v err=%v; want nil,nil", out, err)
	}
}

// QueryIOCs filter branches (since / text / limit) and IOCSummary per-type
// counts, including the since-filtered path.
func TestQueryIOCsFiltersAndSummary(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	base := time.Unix(1_700_000_000, 0).UTC()
	_, err = s.UpsertIOCs(ctx, []IOCUpsert{
		{Type: "ip", Value: "1.2.3.4", RuleID: "r", Sensor: "s", Source: "1.2.3.4", Severity: event.SeverityHigh, Time: base},
		{Type: "ip", Value: "5.6.7.8", RuleID: "r", Sensor: "s", Source: "5.6.7.8", Severity: event.SeverityLow, Time: base.Add(time.Hour)},
		{Type: "domain", Value: "evil.example", RuleID: "r", Sensor: "s", Source: "1.2.3.4", Severity: event.SeverityMedium, Time: base.Add(2 * time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Text filter: substring match on value (case-insensitive).
	if rows, err := s.QueryIOCs(ctx, IOCFilter{Text: "EVIL"}); err != nil || len(rows) != 1 || rows[0].Value != "evil.example" {
		t.Errorf("text filter rows = %v (err %v); want just evil.example", rows, err)
	}
	// Since filter + limit: only the two later IOCs, capped at 1.
	rows, err := s.QueryIOCs(ctx, IOCFilter{Since: base.Add(30 * time.Minute), Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Errorf("since+limit rows = %d; want 1", len(rows))
	}

	// Summary across all time: ip=2, domain=1.
	sum, err := s.IOCSummary(ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if sum["ip"] != 2 || sum["domain"] != 1 {
		t.Errorf("IOCSummary = %v; want ip:2 domain:1", sum)
	}
	// Summary with a since cutoff (base+30m) drops the earliest ip sighting
	// (at base) but keeps the later ip (base+1h) and the domain (base+2h).
	if sum2, err := s.IOCSummary(ctx, base.Add(30*time.Minute)); err != nil || sum2["ip"] != 1 || sum2["domain"] != 1 {
		t.Errorf("since-filtered IOCSummary = %v (err %v); want ip:1 domain:1", sum2, err)
	}
}

// Path accessor + the batched insert path (including the empty-batch no-op and
// banner interning on the shared tx).
func TestStorePathAndInsertBatch(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	if s.Path() == "" {
		t.Error("Path() returned empty")
	}
	if err := s.InsertBatch(ctx, nil); err != nil {
		t.Fatalf("empty InsertBatch should be a no-op, got %v", err)
	}

	base := time.Unix(1_700_000_000, 0).UTC()
	batch := []*event.Event{
		{ID: "b1", Time: base, Sensor: "s", RuleID: "listener:x", Severity: event.SeverityLow, Source: event.Endpoint{IP: "1.1.1.1"}, BannerSent: "SSH-2.0-OpenSSH"},
		{ID: "b2", Time: base.Add(time.Second), Sensor: "s", RuleID: "listener:y", Severity: event.SeverityHigh, Source: event.Endpoint{IP: "2.2.2.2"}},
	}
	if err := s.InsertBatch(ctx, batch); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}
	if c, _, _ := s.Heartbeat(ctx); c != 2 {
		t.Errorf("post-batch event count = %d; want 2", c)
	}
}

// Empty-store branches: Heartbeat and OldestEventTime must report zero values
// (not an error) when the events table is empty — the NULL MIN/MAX path.
func TestStoreEmptyHeartbeatAndOldest(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if oldest, err := s.OldestEventTime(ctx); err != nil || !oldest.IsZero() {
		t.Errorf("empty OldestEventTime = (%v, %v); want zero time, nil", oldest, err)
	}
	if count, latest, err := s.Heartbeat(ctx); err != nil || count != 0 || !latest.IsZero() {
		t.Errorf("empty Heartbeat = (%d, %v, %v); want 0, zero, nil", count, latest, err)
	}
}

// AggregateIPs / DistinctIPs (check-iocs support) + the Heartbeat / oldest /
// PruneBefore retention primitives.
func TestStoreAggregatesAndRetention(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	base := time.Unix(1_700_000_000, 0).UTC()
	ins := func(id, src, dst string, port int, sev event.Severity, tm time.Time) {
		t.Helper()
		if err := s.Insert(ctx, &event.Event{
			ID: id, Time: tm, Sensor: "s", RuleID: "listener:x", Severity: sev,
			Source: event.Endpoint{IP: src}, Dest: event.Endpoint{IP: dst, Port: port},
		}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	ins("a", "1.1.1.1", "10.0.0.1", 80, event.SeverityHigh, base)
	ins("b", "1.1.1.1", "10.0.0.1", 443, event.SeverityCritical, base.Add(time.Minute))
	ins("c", "2.2.2.2", "10.0.0.2", 22, event.SeverityMedium, base.Add(2*time.Minute))
	ins("old", "9.9.9.9", "10.0.0.1", 21, event.SeverityLow, base.Add(-48*time.Hour))

	count, latest, err := s.Heartbeat(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 4 || !latest.Equal(base.Add(2*time.Minute)) {
		t.Errorf("heartbeat = (%d, %v); want (4, %v)", count, latest, base.Add(2*time.Minute))
	}
	if oldest, err := s.OldestEventTime(ctx); err != nil || !oldest.Equal(base.Add(-48*time.Hour)) {
		t.Errorf("oldest = (%v, %v); want %v", oldest, err, base.Add(-48*time.Hour))
	}

	agg, err := s.AggregateIPs(ctx, []string{"1.1.1.1", "2.2.2.2", "nope"}, "src_ip", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if a := agg["1.1.1.1"]; a.Count != 2 || a.MaxSeverity != event.SeverityCritical {
		t.Errorf("agg src 1.1.1.1 = %+v; want count 2, maxsev critical", a)
	}
	if _, ok := agg["nope"]; ok {
		t.Error("AggregateIPs returned a row for an IP with no events")
	}
	aggd, err := s.AggregateIPs(ctx, []string{"10.0.0.1"}, "dst_ip", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if aggd["10.0.0.1"].Count != 3 {
		t.Errorf("agg dst 10.0.0.1 count = %d; want 3", aggd["10.0.0.1"].Count)
	}
	if _, err := s.AggregateIPs(ctx, []string{"x"}, "evil", time.Time{}); err == nil {
		t.Error("AggregateIPs with a non-allowlisted column must error")
	}

	srcs, err := s.DistinctIPs(ctx, "src_ip", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 3 {
		t.Errorf("distinct src_ips = %d (%v); want 3", len(srcs), srcs)
	}
	if _, err := s.DistinctIPs(ctx, "evil", time.Time{}); err == nil {
		t.Error("DistinctIPs with a non-allowlisted column must error")
	}

	evDel, _, err := s.PruneBefore(ctx, base.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if evDel != 1 {
		t.Errorf("PruneBefore removed %d events; want 1 (the 48h-old one)", evDel)
	}
	if count2, _, _ := s.Heartbeat(ctx); count2 != 3 {
		t.Errorf("post-prune count = %d; want 3", count2)
	}
}
