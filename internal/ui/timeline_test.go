package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestBuildTimelineView(t *testing.T) {
	now := time.Now()
	mk := func(ip, rule, handler string, sev event.Severity, dt time.Duration) *event.Event {
		return &event.Event{RuleID: rule, Handler: handler, Severity: sev,
			Source: event.Endpoint{IP: ip}, Dest: event.Endpoint{Port: 22}, Time: now.Add(dt)}
	}
	evs := []*event.Event{
		mk("1.1.1.1", "listener:ssh", "ssh", event.SeverityHigh, -3*time.Minute),
		mk("1.1.1.1", "listener:smb", "smb", event.SeverityCritical, -1*time.Minute),
		mk("2.2.2.2", "listener:http", "http", event.SeverityMedium, -2*time.Minute),
	}
	v := buildTimelineView(now.Add(-time.Hour), evs)

	if len(v.Sources) != 2 {
		t.Fatalf("want 2 source timelines, got %d", len(v.Sources))
	}
	// 1.1.1.1 has 2 events, ranked first; max severity critical.
	top := v.Sources[0]
	if top.Source != "1.1.1.1" || top.Count != 2 || top.MaxSev != "critical" {
		t.Errorf("top source wrong: %+v", top)
	}
	// Events are newest-first within the source (UI default; a button flips it).
	if !top.Events[0].Time.After(top.Events[1].Time) {
		t.Errorf("events not newest-first: %+v", top.Events)
	}
	// Tactics aggregated (ssh→credential-access, smb→lateral-movement).
	joined := strings.Join(top.Tactics, ",")
	if !strings.Contains(joined, "credential-access") || !strings.Contains(joined, "lateral-movement") {
		t.Errorf("tactics not aggregated: %v", top.Tactics)
	}

	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "timeline", v); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"attack timeline", "1.1.1.1", "listener:smb", "credential-access"} {
		if !strings.Contains(html, want) {
			t.Errorf("timeline page missing %q", want)
		}
	}
}

func TestEnrichDashboard(t *testing.T) {
	evs := []*event.Event{
		{RuleID: "listener:ssh", Handler: "ssh", Meta: map[string]any{"geo_country": "RU", "tools": []any{"hydra"}}},
		{RuleID: "listener:http", Handler: "http", Meta: map[string]any{"geo_country": "RU", "asn": 64500, "asn_org": "EvilNet"}},
	}
	var d dashboard
	enrichDashboard(&d, evs)
	if d.Scanned != 2 {
		t.Errorf("scanned = %d; want 2", d.Scanned)
	}
	has := func(rows []barRow, label string) bool {
		for _, r := range rows {
			if r.Label == label || strings.HasSuffix(r.Label, " "+label) || strings.HasPrefix(r.Label, label+" ") {
				return true
			}
		}
		return false
	}
	if !has(d.Countries, "RU") { // label is now "RU 🇷🇺" (code first, flag after)
		t.Errorf("country RU missing: %+v", d.Countries)
	}
	if !has(d.Tools, "hydra") {
		t.Errorf("tool hydra missing: %+v", d.Tools)
	}
	if !has(d.Handlers, "ssh") || !has(d.Handlers, "http") {
		t.Errorf("handlers missing: %+v", d.Handlers)
	}
	if len(d.Tactics) == 0 {
		t.Errorf("tactics not computed")
	}
}
