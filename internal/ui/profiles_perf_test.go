package ui

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// TestCachedSourceAggregatesServesStale verifies the profiles-list cache
// collapses repeated scans: a second call within the TTL returns the cached
// rollup (it does not reflect an event inserted in between).
func TestCachedSourceAggregatesServesStale(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.Insert(ctx, &event.Event{ID: "1", Time: now, Sensor: "s", RuleID: "r",
		Severity: event.SeverityHigh, Source: event.Endpoint{IP: "1.1.1.1"}})
	srv, err := New(config.UI{Enabled: true, Bind: "127.0.0.1:0"}, st)
	if err != nil {
		t.Fatal(err)
	}

	first, err := srv.cachedSourceAggregates(ctx, 24*time.Hour, 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].Count != 1 {
		t.Fatalf("first rollup = %+v; want 1 source with 1 event", first)
	}
	// Insert another event for the same source, then call again within the TTL:
	// the cached result must be served (still Count==1), proving no re-scan.
	_ = st.Insert(ctx, &event.Event{ID: "2", Time: now, Sensor: "s", RuleID: "r2",
		Severity: event.SeverityHigh, Source: event.Endpoint{IP: "1.1.1.1"}})
	second, err := srv.cachedSourceAggregates(ctx, 24*time.Hour, 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].Count != 1 {
		t.Errorf("cached rollup = %+v; want the stale Count==1 within TTL", second)
	}
}

// TestVisibleAggregatesDoesNotMutateInput guards the aliasing hazard: the hide
// filter must not compact the (shared, cached) input slice in place.
func TestVisibleAggregatesDoesNotMutateInput(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv, err := New(config.UI{Enabled: true, Bind: "127.0.0.1:0", HiddenIPs: []string{"2.2.2.2"}}, st)
	if err != nil {
		t.Fatal(err)
	}
	in := []store.SourceAggregate{{IP: "1.1.1.1"}, {IP: "2.2.2.2"}, {IP: "3.3.3.3"}}
	out := srv.visibleAggregates(in)
	if len(out) != 2 {
		t.Errorf("visible = %d; want 2 (2.2.2.2 hidden)", len(out))
	}
	// The input (a stand-in for the cached snapshot) must be untouched.
	if len(in) != 3 || in[0].IP != "1.1.1.1" || in[1].IP != "2.2.2.2" || in[2].IP != "3.3.3.3" {
		t.Errorf("input slice was mutated by visibleAggregates: %+v", in)
	}
}

// TestProfilesListUsesShortDefaultWindow documents that the list defaults to the
// 24h window (the perf fix) while ?since= still widens it.
func TestProfilesListDefaultWindow(t *testing.T) {
	if profileListWindow != 24*time.Hour {
		t.Errorf("profileListWindow = %v; want 24h (perf-bounded list rollup)", profileListWindow)
	}
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv, err := New(config.UI{Enabled: true, Bind: "127.0.0.1:0"}, st)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	srv.handleProfiles(w, httptest.NewRequest("GET", "/profiles?since=720h", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "attacker profiles") {
		t.Errorf("profiles list with ?since= override: code=%d", w.Code)
	}
}
