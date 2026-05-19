package router

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/sink"
)

type fakeSink struct {
	id  string
	mu  sync.Mutex
	got []*event.Event
}

func (f *fakeSink) ID() string { return f.id }
func (f *fakeSink) Send(_ context.Context, ev *event.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, ev)
	return nil
}
func (f *fakeSink) Close() error { return nil }

func (f *fakeSink) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func makeRouter(t *testing.T, cfg *config.Config, fakes map[string]sink.Sink) *Router {
	t.Helper()
	var sinks []sink.Sink
	for _, s := range fakes {
		sinks = append(sinks, s)
	}
	r, err := New(cfg, sinks)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func TestDispatchToLocalAndOutbound(t *testing.T) {
	local := &fakeSink{id: "local"}
	web := &fakeSink{id: "web"}
	cfg := &config.Config{
		Channels: []config.Channel{
			{ID: "local", Type: "jsonlog", MinSeverity: "low"},
			{ID: "web", Type: "webhook", MinSeverity: "low"},
		},
		Routes: []config.Route{
			{Match: config.Match{Severity: ">=low"}, Channels: []string{"local", "web"}},
		},
		Dedup: config.Dedup{DefaultWindow: time.Second},
	}
	r := makeRouter(t, cfg, map[string]sink.Sink{"local": local, "web": web})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)

	r.Dispatch(&event.Event{ID: "1", Severity: event.SeverityMedium, Source: event.Endpoint{IP: "9.9.9.9"}, RuleID: "x"})
	time.Sleep(100 * time.Millisecond)
	r.Stop()

	if local.count() != 1 || web.count() != 1 {
		t.Fatalf("expected both sinks to receive 1 event; got local=%d web=%d", local.count(), web.count())
	}
}

func TestAllowlistOnlyAffectsOutbound(t *testing.T) {
	local := &fakeSink{id: "local"}
	web := &fakeSink{id: "web"}
	cfg := &config.Config{
		Channels: []config.Channel{
			{ID: "local", Type: "jsonlog", MinSeverity: "low"},
			{ID: "web", Type: "webhook", MinSeverity: "low"},
		},
		Routes: []config.Route{
			{Match: config.Match{Severity: ">=low"}, Channels: []string{"local", "web"}},
		},
		Allowlist: []string{"10.0.0.0/8"},
		Dedup:     config.Dedup{DefaultWindow: time.Second},
	}
	r := makeRouter(t, cfg, map[string]sink.Sink{"local": local, "web": web})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)

	r.Dispatch(&event.Event{ID: "1", Severity: event.SeverityMedium, Source: event.Endpoint{IP: "10.1.2.3"}, RuleID: "x"})
	time.Sleep(100 * time.Millisecond)
	r.Stop()

	if local.count() != 1 {
		t.Fatalf("local should bypass allowlist; got %d", local.count())
	}
	if web.count() != 0 {
		t.Fatalf("webhook should be suppressed by allowlist; got %d", web.count())
	}
}

func TestDedupOnlyAffectsOutbound(t *testing.T) {
	local := &fakeSink{id: "local"}
	web := &fakeSink{id: "web"}
	cfg := &config.Config{
		Channels: []config.Channel{
			{ID: "local", Type: "jsonlog", MinSeverity: "low"},
			{ID: "web", Type: "webhook", MinSeverity: "low"},
		},
		Routes: []config.Route{
			{Match: config.Match{Severity: ">=low"}, Channels: []string{"local", "web"}},
		},
		Dedup: config.Dedup{DefaultWindow: time.Second},
	}
	r := makeRouter(t, cfg, map[string]sink.Sink{"local": local, "web": web})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)

	for i := 0; i < 3; i++ {
		r.Dispatch(&event.Event{ID: "x", Severity: event.SeverityMedium, Source: event.Endpoint{IP: "9.9.9.9"}, RuleID: "r"})
	}
	time.Sleep(100 * time.Millisecond)
	r.Stop()

	if local.count() != 3 {
		t.Fatalf("local should get all 3 events (dedup is outbound-only); got %d", local.count())
	}
	if web.count() != 1 {
		t.Fatalf("webhook should dedup to 1; got %d", web.count())
	}
}

func TestMinSeverityGate(t *testing.T) {
	web := &fakeSink{id: "web"}
	cfg := &config.Config{
		Channels: []config.Channel{
			{ID: "web", Type: "webhook", MinSeverity: "high"},
		},
		Routes: []config.Route{
			{Match: config.Match{Severity: ">=low"}, Channels: []string{"web"}},
		},
		Dedup: config.Dedup{DefaultWindow: time.Second},
	}
	r := makeRouter(t, cfg, map[string]sink.Sink{"web": web})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	r.Dispatch(&event.Event{ID: "low", Severity: event.SeverityLow, Source: event.Endpoint{IP: "9.9.9.9"}, RuleID: "r"})
	r.Dispatch(&event.Event{ID: "high", Severity: event.SeverityHigh, Source: event.Endpoint{IP: "9.9.9.9"}, RuleID: "r2"})
	time.Sleep(100 * time.Millisecond)
	r.Stop()
	if web.count() != 1 {
		t.Fatalf("expected only the high event to pass min_severity; got %d", web.count())
	}
}

func TestRouteSeverityMatch(t *testing.T) {
	a := &fakeSink{id: "a"}
	b := &fakeSink{id: "b"}
	cfg := &config.Config{
		Channels: []config.Channel{
			{ID: "a", Type: "webhook", MinSeverity: "low"},
			{ID: "b", Type: "webhook", MinSeverity: "low"},
		},
		Routes: []config.Route{
			{Match: config.Match{Severity: ">=high"}, Channels: []string{"a"}},
			{Match: config.Match{Severity: "<high"}, Channels: []string{"b"}},
		},
		Dedup: config.Dedup{DefaultWindow: time.Second},
	}
	r := makeRouter(t, cfg, map[string]sink.Sink{"a": a, "b": b})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	r.Dispatch(&event.Event{ID: "low", Severity: event.SeverityLow, Source: event.Endpoint{IP: "9.9.9.9"}, RuleID: "r1"})
	r.Dispatch(&event.Event{ID: "high", Severity: event.SeverityHigh, Source: event.Endpoint{IP: "9.9.9.9"}, RuleID: "r2"})
	time.Sleep(100 * time.Millisecond)
	r.Stop()
	if a.count() != 1 {
		t.Errorf("sink a (>=high) should receive 1; got %d", a.count())
	}
	if b.count() != 1 {
		t.Errorf("sink b (<high) should receive 1; got %d", b.count())
	}
}
