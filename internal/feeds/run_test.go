package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestRunImmediateRefreshAndTick drives the full Run loop: the immediate fetch
// on start, at least one ticker-driven refresh, and a clean exit on ctx cancel.
// It also exercises fetchOne's auth-header and json_ips branches.
func TestRunImmediateRefreshAndTick(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Key") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`["203.0.113.9","198.51.100.22"]`))
	}))
	defer srv.Close()

	applied := make(chan map[string]string, 8)
	p := NewPuller(
		[]Feed{{Label: "t", URL: srv.URL, Format: "json_ips", Header: "X-Key: secret"}},
		20*time.Millisecond,
		srv.Client(),
		func(m map[string]string) { applied <- m },
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	// Expect the immediate refresh plus at least one ticker tick.
	for i := 0; i < 2; i++ {
		select {
		case m := <-applied:
			if m["203.0.113.9"] != "t" {
				t.Errorf("apply #%d missing labelled IP: %v", i, m)
			}
		case <-time.After(3 * time.Second):
			cancel()
			<-done
			t.Fatalf("did not receive apply #%d", i)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if atomic.LoadInt32(&hits) < 2 {
		t.Errorf("want >= 2 fetches (immediate + tick), got %d", hits)
	}
}

// TestNewPullerDefaultsInterval covers the interval<=0 default branch.
func TestNewPullerDefaultsInterval(t *testing.T) {
	p := NewPuller([]Feed{{URL: "x"}}, 0, http.DefaultClient, func(map[string]string) {})
	if p.interval != time.Hour {
		t.Errorf("default interval = %v; want 1h", p.interval)
	}
}

// TestRunNoopWithoutFeeds covers the guard that makes Run return at once when
// there's nothing to poll (no feeds / nil client / nil apply).
func TestRunNoopWithoutFeeds(t *testing.T) {
	p := NewPuller(nil, time.Millisecond, http.DefaultClient, func(map[string]string) {})
	done := make(chan struct{})
	go func() { p.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run with no feeds should return immediately")
	}
}
