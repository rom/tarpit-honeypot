package sensor

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/identity"
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
