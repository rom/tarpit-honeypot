package misp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/intel"
)

// TestNewPusherDefaults covers the default-filling branches.
func TestNewPusherDefaults(t *testing.T) {
	p := NewPusher(Config{}, func() []intel.IOC { return nil })
	if p.cfg.Interval != 5*time.Minute {
		t.Errorf("Interval default = %v; want 5m", p.cfg.Interval)
	}
	if p.cfg.EventInfo == "" || p.cfg.Distribution != "0" || p.cfg.ThreatLevel != "2" {
		t.Errorf("defaults not applied: %+v", p.cfg)
	}
}

// TestAttributeUnmappedAndOtherKinds covers the attribute() branches the
// existing test doesn't: an unknown IOC kind, a fingerprint with no "kind:value"
// separator, and a fingerprint of an unrecognised kind (the "other" fallback).
func TestAttributeUnmappedAndOtherKinds(t *testing.T) {
	if _, ok := attribute(intel.IOC{Kind: "mystery", Value: "x"}); ok {
		t.Error("unknown kind should not map")
	}
	if _, ok := attribute(intel.IOC{Kind: "fingerprint", Value: "nocolon"}); ok {
		t.Error("fingerprint without a ':' separator should not map")
	}
	a, ok := attribute(intel.IOC{Kind: "fingerprint", Value: "ja4:abc"})
	if !ok || a["type"] != "other" || a["value"] != "ja4:abc" {
		t.Errorf("unrecognised fingerprint kind -> %v (ok=%v); want type=other value=ja4:abc", a, ok)
	}
}

// TestOncePostFailureRollsBack covers the post() error path (status >= 300) and
// the rollback in once() that un-marks the indicators so the next tick retries.
func TestOncePostFailureRollsBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := NewPusher(Config{URL: srv.URL, Key: "k", Client: srv.Client()},
		func() []intel.IOC { return []intel.IOC{{Kind: "ip", Value: "1.1.1.1", Reason: "r"}} })
	p.once(context.Background())
	if len(p.pushed) != 0 {
		t.Errorf("pushed set = %d after a failed post; want 0 (rolled back for retry)", len(p.pushed))
	}
}

// TestOncePrunesVanishedIndicators covers the prune branch: an IOC that was
// pushed but no longer appears in the source is dropped from the pushed set so
// it doesn't leak memory as indicators age out.
func TestOncePrunesVanishedIndicators(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	iocs := []intel.IOC{{Kind: "ip", Value: "2.2.2.2", Reason: "r"}}
	p := NewPusher(Config{URL: srv.URL, Key: "k", Client: srv.Client()}, func() []intel.IOC { return iocs })
	p.once(context.Background())
	if len(p.pushed) != 1 {
		t.Fatalf("pushed = %d after first push; want 1", len(p.pushed))
	}
	iocs = nil // the indicator aged out of the intel store
	p.once(context.Background())
	if len(p.pushed) != 0 {
		t.Errorf("pushed = %d after the indicator vanished; want 0 (pruned)", len(p.pushed))
	}
}

// TestRunTicksUntilCancel covers the Run loop: a ticker-driven push and a clean
// exit on context cancel.
func TestRunTicksUntilCancel(t *testing.T) {
	posted := make(chan struct{}, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		select {
		case posted <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	p := NewPusher(
		Config{URL: srv.URL, Key: "k", Interval: 15 * time.Millisecond, Client: srv.Client()},
		func() []intel.IOC { return []intel.IOC{{Kind: "ip", Value: "3.3.3.3", Reason: "r"}} },
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	select {
	case <-posted:
	case <-time.After(3 * time.Second):
		cancel()
		<-done
		t.Fatal("Run never pushed within 3s")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
