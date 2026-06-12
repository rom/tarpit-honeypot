package ui

import (
	"context"
	"html/template"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// newFilterRenderServer builds a store-backed Server (with the real templates)
// holding three events on distinct rules / source IPs, for end-to-end render
// tests of the charts include/exclude UI and the events negation filter.
func newFilterRenderServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	mk := func(id, ip, rule string, off int) *event.Event {
		return &event.Event{
			ID: id, Time: now.Add(-time.Duration(off) * time.Minute), Sensor: "t",
			RuleID: rule, Severity: event.SeverityHigh,
			Source: event.Endpoint{IP: ip, Port: 1234}, Dest: event.Endpoint{IP: "10.0.0.1", Port: 22},
			Proto: "tcp", Handler: "ssh",
			Meta: map[string]any{"asn": uint32(64500), "geo_country": "US"},
		}
	}
	for _, e := range []*event.Event{
		mk("a", "1.1.1.1", "sniffer:arp_scan", 1),
		mk("b", "2.2.2.2", "ssh:bruteforce", 2),
		mk("c", "3.3.3.3", "webapp:sqli", 3),
	} {
		if err := st.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	tmpl, err := template.New("").Funcs(tmplFuncs(func() int { return 0 }, "nvd", "", true,
		navFuncs{has: func(string) bool { return true }, enabled: func(string) bool { return true }})).Parse(tmpls)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{store: st, tmpl: tmpl}
}

func TestRenderChartsWithFilter(t *testing.T) {
	s := newFilterRenderServer(t)
	w := httptest.NewRecorder()
	s.handleCharts(w, httptest.NewRequest("GET", "/charts?exclude=ip:1.1.1.1&exclude=rule:webapp:sqli", nil))
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	// The add-filter form, the carried-state hidden inputs, the two active chips,
	// and the clear link must all render.
	for _, want := range []string{
		"filter graphs:", `name="dim"`, `name="val"`,
		`name="exclude"`, "exclude ip=1.1.1.1", "exclude rule=webapp:sqli", "clear all",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("charts body missing %q", want)
		}
	}
}

func TestRenderChartsAddRedirect(t *testing.T) {
	s := newFilterRenderServer(t)
	w := httptest.NewRecorder()
	s.handleCharts(w, httptest.NewRequest("GET", "/charts?range=7d&mode=exclude&dim=ip&val=9.9.9.9", nil))
	if w.Code != 303 {
		t.Fatalf("add submit status = %d, want 303", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "exclude=ip%3A9.9.9.9") || !strings.Contains(loc, "range=7d") {
		t.Errorf("redirect Location = %q", loc)
	}
}

func TestRenderEventsNegated(t *testing.T) {
	s := newFilterRenderServer(t)
	w := httptest.NewRecorder()
	s.handleEvents(w, httptest.NewRequest("GET", "/events?rule="+url.QueryEscape("!sniffer:arp_scan"), nil))
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	// The arp_scan event (a) is excluded; the other two remain (check the per-row
	// details links so the form's echoed filter value doesn't fool the assertion).
	if strings.Contains(body, "/events/a\"") {
		t.Errorf("excluded arp_scan event still listed")
	}
	if !strings.Contains(body, "/events/b\"") || !strings.Contains(body, "/events/c\"") {
		t.Errorf("non-excluded events missing from listing")
	}
	// The negated value round-trips into the rule input.
	if !strings.Contains(body, `value="!sniffer:arp_scan"`) {
		t.Errorf("rule input did not round-trip the negation")
	}
}
