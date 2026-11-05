package sensor

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// The IOC writer drains the off-bus-loop queue, batches the upserts into the
// store, and collapses repeat sightings of the same indicator into one row with
// an advancing count — all without the bus loop ever touching the DB.
func TestIOCWriterBatchesAndPersists(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	// iocEmit is empty: every indicator is still tracked in the store, but none
	// emits an ioc:<type> event, so the writer needs no router/dispatch wiring.
	s := &Sensor{
		name:     "t",
		store:    st,
		iocEmit:  map[string]bool{},
		iocQueue: make(chan iocJob, iocQueueSize),
	}

	// Two distinct sources, with 198.51.100.7 seen three times.
	ips := []string{"198.51.100.7", "203.0.113.9", "198.51.100.7", "198.51.100.7"}
	base := time.Unix(1_700_000_000, 0).UTC()
	for i, ip := range ips {
		s.enqueueIOCs(&event.Event{
			RuleID: "listener:raw", Proto: "tcp",
			Source: event.Endpoint{IP: ip}, Time: base.Add(time.Duration(i) * time.Second),
		})
	}

	// Run the writer and let it drain on iocDone, exactly as Run() wires it.
	iocDone := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.runIOCWriter(iocDone) }()
	close(iocDone)
	wg.Wait()

	rows, err := st.QueryIOCs(context.Background(), store.IOCFilter{Type: "ip"})
	if err != nil {
		t.Fatalf("query iocs: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("distinct ip indicators = %d; want 2 (%+v)", len(rows), rows)
	}
	got := map[string]int{}
	for _, r := range rows {
		got[r.Value] = r.Count
	}
	if got["198.51.100.7"] != 3 {
		t.Errorf("count for repeated source = %d; want 3", got["198.51.100.7"])
	}
	if got["203.0.113.9"] != 1 {
		t.Errorf("count for single source = %d; want 1", got["203.0.113.9"])
	}
	if s.iocDropped.Load() != 0 {
		t.Errorf("dropped = %d; want 0 (queue was not full)", s.iocDropped.Load())
	}
}

// enqueueIOCs never blocks the bus loop: when the queue is full the job is
// dropped and counted instead of stalling event processing on a slow store.
func TestEnqueueIOCsDropsWhenQueueFull(t *testing.T) {
	// Tiny buffer, no writer draining it, so it fills after two jobs.
	s := &Sensor{iocQueue: make(chan iocJob, 2)}
	for i := 0; i < 5; i++ {
		s.enqueueIOCs(&event.Event{RuleID: "listener:raw", Source: event.Endpoint{IP: "192.0.2.5"}})
	}
	if got := s.iocDropped.Load(); got != 3 {
		t.Errorf("dropped = %d; want 3 (2 buffered, 3 dropped)", got)
	}
}

// A nil queue (IOC tracking disabled) makes enqueueIOCs a no-op, never a panic.
func TestEnqueueIOCsNoQueueIsNoop(t *testing.T) {
	s := &Sensor{}
	s.enqueueIOCs(&event.Event{Source: event.Endpoint{IP: "192.0.2.5"}})
	if s.iocDropped.Load() != 0 {
		t.Errorf("dropped = %d; want 0", s.iocDropped.Load())
	}
}
