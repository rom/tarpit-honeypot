package ui

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// countingStore wraps a real store and counts Query calls so the test can prove
// the window cache collapses repeated/concurrent scans into one.
type countingStore struct {
	*store.Store
	queries atomic.Int64
	gate    chan struct{} // when non-nil, Query blocks on it (to force overlap)
}

func (c *countingStore) Query(ctx context.Context, f store.Filter) ([]*event.Event, error) {
	c.queries.Add(1)
	if c.gate != nil {
		<-c.gate
	}
	return c.Store.Query(ctx, f)
}

func newCacheTestServer(t *testing.T) (*Server, *countingStore) {
	t.Helper()
	base, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Close() })
	for i := 0; i < 20; i++ {
		if err := base.Insert(context.Background(), &event.Event{
			ID: string(rune('a' + i)), Time: time.Now(), Sensor: "s",
			RuleID: "listener:ssh", Severity: event.SeverityHigh,
			Source: event.Endpoint{IP: "1.2.3.4"}, Handler: "ssh",
		}); err != nil {
			t.Fatal(err)
		}
	}
	cs := &countingStore{Store: base}
	srv, err := New(config.UI{Enabled: true, Bind: "127.0.0.1:0"}, cs)
	if err != nil {
		t.Fatal(err)
	}
	return srv, cs
}

// TestWindowEventsCachesWithinTTL: a second call within the TTL reuses the
// snapshot and does not hit the store again.
func TestWindowEventsCachesWithinTTL(t *testing.T) {
	srv, cs := newCacheTestServer(t)
	ctx := context.Background()

	a, err := srv.windowEvents(ctx, time.Hour, 20000)
	if err != nil {
		t.Fatal(err)
	}
	b, err := srv.windowEvents(ctx, time.Hour, 20000)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 20 || len(b) != 20 {
		t.Fatalf("want 20 events, got %d / %d", len(a), len(b))
	}
	if n := cs.queries.Load(); n != 1 {
		t.Errorf("want exactly 1 store Query within TTL, got %d", n)
	}
	// A different window is a different key → a fresh scan.
	if _, err := srv.windowEvents(ctx, 2*time.Hour, 20000); err != nil {
		t.Fatal(err)
	}
	if n := cs.queries.Load(); n != 2 {
		t.Errorf("want 2 Query calls after distinct window, got %d", n)
	}
}

// TestWindowEventsSingleFlight: many concurrent callers for the same key while a
// scan is in flight share that one scan rather than each launching their own.
func TestWindowEventsSingleFlight(t *testing.T) {
	srv, cs := newCacheTestServer(t)
	cs.gate = make(chan struct{})

	const n = 25
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := srv.windowEvents(context.Background(), time.Hour, 20000)
			errs <- err
		}()
	}
	// Give the goroutines time to all arrive and coalesce on the in-flight scan,
	// then release the single blocked Query.
	time.Sleep(100 * time.Millisecond)
	close(cs.gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := cs.queries.Load(); got != 1 {
		t.Errorf("single-flight: want 1 store Query for %d concurrent callers, got %d", n, got)
	}
}

// TestWindowEventsHidesIPs: the snapshot is filtered by the presentation
// hide-list (it goes through s.query), so hidden sources never reach a page.
func TestWindowEventsHidesIPs(t *testing.T) {
	base, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	for _, ip := range []string{"1.1.1.1", "9.9.9.9"} {
		if err := base.Insert(context.Background(), &event.Event{
			ID: ip, Time: time.Now(), Sensor: "s", RuleID: "r", Severity: event.SeverityLow,
			Source: event.Endpoint{IP: ip}, Handler: "ssh",
		}); err != nil {
			t.Fatal(err)
		}
	}
	srv, err := New(config.UI{Enabled: true, Bind: "127.0.0.1:0", HiddenIPs: []string{"9.9.9.9"}}, base)
	if err != nil {
		t.Fatal(err)
	}
	evs, err := srv.windowEvents(context.Background(), time.Hour, 20000)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range evs {
		if ev.Source.IP == "9.9.9.9" {
			t.Fatalf("hidden IP leaked into windowEvents snapshot: %v", ev.Source.IP)
		}
	}
	if len(evs) != 1 {
		t.Errorf("want 1 visible event, got %d", len(evs))
	}
}
