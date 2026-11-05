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
