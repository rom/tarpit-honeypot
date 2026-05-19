package router

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/sink"
)

// flakySink fails the first N Send calls then succeeds. Used to test the
// retry path: the early failures should land in the backlog and the later
// success should drain it.
type flakySink struct {
	id        string
	mu        sync.Mutex
	got       []*event.Event
	failsLeft atomic.Int32
}

func (f *flakySink) ID() string { return f.id }
func (f *flakySink) Send(_ context.Context, ev *event.Event) error {
	if f.failsLeft.Add(-1) >= 0 {
		return errors.New("transient")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, ev)
	return nil
}
func (f *flakySink) Close() error { return nil }
func (f *flakySink) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func TestRetryQueueDrainsOnRecovery(t *testing.T) {
	flaky := &flakySink{id: "flaky"}
	flaky.failsLeft.Store(2) // first 2 sends fail; 3rd succeeds
	cfg := &config.Config{
		Channels: []config.Channel{{ID: "flaky", Type: "webhook", MinSeverity: "low"}},
		Routes:   []config.Route{{Match: config.Match{Severity: ">=low"}, Channels: []string{"flaky"}}},
		Dedup:    config.Dedup{DefaultWindow: time.Second},
	}
	r, err := New(cfg, []sink.Sink{flaky})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)

	r.Dispatch(&event.Event{ID: "e1", Severity: event.SeverityHigh,
		Source: event.Endpoint{IP: "9.9.9.9"}, RuleID: "r"})
	// wait long enough for first send + first retry attempt
	time.Sleep(1500 * time.Millisecond)

	r.Stop()
	if flaky.count() < 1 {
		t.Fatalf("retry queue should have delivered the event eventually; got %d", flaky.count())
	}
	stats := r.Stats()["flaky"]
	if stats.Retried < 1 {
		t.Errorf("expected retried >= 1; got %d", stats.Retried)
	}
}

func TestRetryQueueRespectsBacklogCap(t *testing.T) {
	// Sink that never succeeds. Dispatch many events; the backlog should be
	// capped at maxRetryBacklog and "failed" counter should reflect overflow.
	always := &flakySink{id: "always"}
	always.failsLeft.Store(1 << 30) // effectively infinite failures

	cfg := &config.Config{
		Channels: []config.Channel{{ID: "always", Type: "webhook", MinSeverity: "low"}},
		Routes:   []config.Route{{Match: config.Match{Severity: ">=low"}, Channels: []string{"always"}}},
		Dedup:    config.Dedup{DefaultWindow: time.Second},
	}
	r, err := New(cfg, []sink.Sink{always})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)

	// Send maxRetryBacklog + 10 distinct events.
	for i := 0; i < maxRetryBacklog+10; i++ {
		r.Dispatch(&event.Event{
			ID:       string(rune('a'+i)) + "-event",
			Severity: event.SeverityHigh,
			Source:   event.Endpoint{IP: "9.9.9.9"},
			RuleID:   "r-" + string(rune('a'+i)),
		})
	}
	time.Sleep(200 * time.Millisecond)
	r.Stop()

	stats := r.Stats()["always"]
	if stats.Failed < 1 {
		t.Errorf("expected at least some events dropped from backlog cap; failed=%d", stats.Failed)
	}
}
