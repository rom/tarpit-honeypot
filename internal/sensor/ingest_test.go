package sensor

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/trust"
)

func testAggregator(t *testing.T) *Sensor {
	t.Helper()
	return &Sensor{
		identity:      identity.New("agg-node"),
		ingestSeen:    newTTLSet(time.Minute),
		ingestMaxHops: 8,
		bus:           make(chan *event.Event, 64),
	}
}

func TestIngestBatchAdmits(t *testing.T) {
	s := testAggregator(t)
	acc, dup, drop := s.IngestBatch([]*event.Event{
		{ID: "e1", SensorID: "depA", Hops: []string{"depA"}},
		{ID: "e2", SensorID: "depA", Hops: []string{"depA"}},
	})
	if acc != 2 || dup != 0 || drop != 0 {
		t.Fatalf("first batch: acc=%d dup=%d drop=%d; want 2/0/0", acc, dup, drop)
	}
	if len(s.bus) != 2 {
		t.Errorf("bus has %d events; want 2", len(s.bus))
	}
}

func TestIngestBatchDedups(t *testing.T) {
	s := testAggregator(t)
	ev := &event.Event{ID: "e1", SensorID: "depA"}
	s.IngestBatch([]*event.Event{ev})
	acc, dup, _ := s.IngestBatch([]*event.Event{{ID: "e1", SensorID: "depA"}}) // same key
	if acc != 0 || dup != 1 {
		t.Errorf("re-ingest of same sensor_id:id: acc=%d dup=%d; want 0/1", acc, dup)
	}
}

func TestIngestBatchLoopGuard(t *testing.T) {
	s := testAggregator(t)
	me := s.identity.Seed()
	long := make([]string, 9) // exceeds ingestMaxHops=8
	for i := range long {
		long[i] = "n"
	}
	acc, _, drop := s.IngestBatch([]*event.Event{
		{ID: "loop", SensorID: "depA", Hops: []string{"x", me, "y"}}, // already passed through us
		{ID: "deep", SensorID: "depB", Hops: long},                   // too many hops
		{ID: "ok", SensorID: "depC", Hops: []string{"depC"}},
	})
	if acc != 1 || drop != 2 {
		t.Errorf("loop guard: acc=%d drop=%d; want 1/2", acc, drop)
	}
}

func TestIngestMalformedDroppedAndScored(t *testing.T) {
	s := testAggregator(t)
	s.trust = trust.New(trust.Config{Enabled: true, MinEvents: 2, AlertBelow: 0.5})
	acc, _, drop := s.IngestBatch([]*event.Event{
		{SensorID: "depX", Severity: event.SeverityHigh},                                                // no ID -> malformed
		{ID: "m2", SensorID: "depX", Severity: event.SeverityHigh, Time: timeNow().Add(48 * time.Hour)}, // future -> malformed
	})
	if acc != 0 || drop != 2 {
		t.Fatalf("malformed batch: acc=%d drop=%d; want 0/2", acc, drop)
	}
	var found bool
	for len(s.bus) > 0 {
		if ev := <-s.bus; ev.RuleID == "fleet:sensor-untrusted" {
			found = true
		}
	}
	if !found {
		t.Error("no fleet:sensor-untrusted emitted for a malformed stream")
	}
}

func TestIngestQuarantineRefusesSensor(t *testing.T) {
	s := testAggregator(t)
	s.trust = trust.New(trust.Config{Enabled: true, MinEvents: 2, QuarantineBelow: 0.9})
	// Two malformed events tank depQ's score to 0 -> quarantined.
	s.IngestBatch([]*event.Event{{SensorID: "depQ"}, {SensorID: "depQ"}})
	// A subsequent well-formed event from depQ is refused.
	acc, _, drop := s.IngestBatch([]*event.Event{
		{ID: "ok", SensorID: "depQ", Severity: event.SeverityHigh, Hops: []string{"depQ"}},
	})
	if acc != 0 || drop != 1 {
		t.Errorf("quarantined sensor: acc=%d drop=%d; want 0/1", acc, drop)
	}
}

func TestIngestBatchShedsWhenBusFull(t *testing.T) {
	s := testAggregator(t)
	s.bus = make(chan *event.Event, 1)
	evs := []*event.Event{
		{ID: "a", SensorID: "d"},
		{ID: "b", SensorID: "d"},
		{ID: "c", SensorID: "d"},
	}
	acc, _, drop := s.IngestBatch(evs)
	if acc != 1 || drop != 2 {
		t.Errorf("bus-full shed: acc=%d drop=%d; want 1/2", acc, drop)
	}
}
