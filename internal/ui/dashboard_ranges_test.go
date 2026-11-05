package ui

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// TestDashboardWindowsNeverEmpty guards the summary page against the regression
// where every window other than one happened-to-be-cached range (e.g. 7d)
// rendered as the near-empty "only headers" shell. Each window must surface the
// indexed SQL summary (counters / severity / trend) immediately on a cold load,
// and the cold load must cache a data-bearing entry rather than falling through
// to minimalDashboard whenever the store actually has events.
func TestDashboardWindowsNeverEmpty(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	// Events spread across ages so every window (24h … 6mo) has data, and each
	// larger window is a strict superset of the smaller ones.
	ages := []time.Duration{time.Hour, 3 * 24 * time.Hour, 10 * 24 * time.Hour, 20 * 24 * time.Hour, 60 * 24 * time.Hour}
	for i, age := range ages {
		_ = st.Insert(ctx, &event.Event{
			ID: fmt.Sprintf("e%d", i), Time: now.Add(-age), Sensor: "s",
			RuleID: "listener:ssh", Severity: event.SeverityHigh, Handler: "ssh",
			Source: event.Endpoint{IP: "9.9.9.9"}, Dest: event.Endpoint{IP: "10.0.0.1", Port: 22}, Proto: "tcp",
		})
	}
	srv, err := New(config.UI{Enabled: true, Bind: "127.0.0.1:0"}, st)
	if err != nil {
		t.Fatal(err)
	}

	// expectedTotal is how many of the seeded events fall inside each window.
	expected := map[string]int64{"24h": 1, "7d": 2, "14d": 3, "31d": 4, "3mo": 5, "6mo": 5}

	for _, key := range summaryRanges {
		win := summaryRange(key)
		// Cold path: must return real data, never the empty shell.
		d := srv.cachedIndexDashboard(win)
		if d.Sum.Total == 0 {
			t.Errorf("window %s: cold dashboard has Sum.Total=0 (minimal/empty shell)", key)
		}
		if got := d.Sum.Total; int64(got) != expected[key] {
			t.Errorf("window %s: Sum.Total=%d; want %d", key, got, expected[key])
		}
		if len(d.Counters) == 0 {
			t.Errorf("window %s: cold dashboard has no counters", key)
		}
		// The cold miss must have cached a data-bearing quick entry so reloads
		// are instant and still carry the summary.
		srv.dashMu.Lock()
		ent, ok := srv.dashCache[win.key]
		srv.dashMu.Unlock()
		if !ok {
			t.Errorf("window %s: cold load did not cache an entry", key)
		} else if ent.d.Sum.Total == 0 {
			t.Errorf("window %s: cached entry is empty", key)
		}
	}

	// Full HTTP render per window must carry the severity data, not the shell.
	for _, key := range summaryRanges {
		path := "/"
		if key != "24h" {
			path = "/?range=" + key
		}
		w := httptest.NewRecorder()
		srv.handleIndex(w, httptest.NewRequest("GET", path, nil))
		body := w.Body.String()
		if w.Code != 200 {
			t.Errorf("window %s: status %d", key, w.Code)
		}
		if !strings.Contains(body, "sev-high") {
			t.Errorf("window %s: rendered body missing severity data (empty shell)", key)
		}
	}
}
