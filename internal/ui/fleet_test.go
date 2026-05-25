package ui

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func fleetTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir(), 50)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	tmpl, err := template.New("").Funcs(tmplFuncs(func() int { return 0 })).Parse(tmpls)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{store: st, tmpl: tmpl}
}

func TestHandleFleet(t *testing.T) {
	s := fleetTestServer(t)
	ctx := context.Background()
	must := func(ev *event.Event) {
		if err := s.store.Insert(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	must(&event.Event{ID: "f1", Time: now, RuleID: "fleet:source-multi-sensor", Severity: event.SeverityHigh,
		Meta: map[string]any{"source": "203.0.113.7", "sensor_count": 4, "scope": "targeted"}})
	must(&event.Event{ID: "f2", Time: now, RuleID: "fleet:c2-shared", Severity: event.SeverityCritical,
		Meta: map[string]any{"url": "http://evil.test/x", "sensor_count": 3}})
	// A non-fleet event must not appear.
	must(&event.Event{ID: "n1", Time: now, RuleID: "listener:http", Severity: event.SeverityLow,
		Source: event.Endpoint{IP: "8.8.8.8"}})

	w := httptest.NewRecorder()
	s.handleFleet(w, httptest.NewRequest(http.MethodGet, "/fleet", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"fleet correlation", "fleet:source-multi-sensor", "fleet:c2-shared",
		"source=203.0.113.7", "sensor_count=4", "targeted",
		// each detector bar links to its filtered event log
		`href="/events?rule=fleet%3Asource-multi-sensor"`,
		"findings over time", // the timeline chart heading
	} {
		if !strings.Contains(body, want) {
			t.Errorf("fleet page missing %q", want)
		}
	}
	if strings.Contains(body, "listener:http") || strings.Contains(body, "8.8.8.8") {
		t.Error("non-fleet event leaked into the fleet panel")
	}
}

func TestFleetSummaryAndNumFmt(t *testing.T) {
	// numFmt strips the .0 the store's JSON round-trip adds to integers.
	if got := numFmt(float64(5)); got != "5" {
		t.Errorf("numFmt(5.0) = %q; want 5", got)
	}
	if got := numFmt(float64(0.83)); got != "0.83" {
		t.Errorf("numFmt(0.83) = %q; want 0.83", got)
	}
	ev := &event.Event{Meta: map[string]any{"fingerprint": "ja3:abc", "sensor_count": float64(3), "source_count": float64(7)}}
	got := fleetSummary(ev)
	if !strings.Contains(got, "fingerprint=ja3:abc") || !strings.Contains(got, "sensor_count=3") || !strings.Contains(got, "source_count=7") {
		t.Errorf("fleetSummary = %q", got)
	}
}
