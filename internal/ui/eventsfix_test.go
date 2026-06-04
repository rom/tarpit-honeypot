package ui

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// "limit=all" / "limit=0" must lift the row cap to the safety maximum, and a
// huge numeric value is clamped — fixing the "Rows: All still shows 100" bug.
func TestParseFilterLimitAll(t *testing.T) {
	for _, v := range []string{"all", "0"} {
		f := parseFilter(httptest.NewRequest("GET", "/events?limit="+v, nil))
		if f.Limit != maxEventsLimit {
			t.Errorf("limit=%s -> %d; want %d", v, f.Limit, maxEventsLimit)
		}
	}
	if f := parseFilter(httptest.NewRequest("GET", "/events?limit=999999999", nil)); f.Limit != maxEventsLimit {
		t.Errorf("oversized limit -> %d; want clamp to %d", f.Limit, maxEventsLimit)
	}
	if f := parseFilter(httptest.NewRequest("GET", "/events?limit=250", nil)); f.Limit != 250 {
		t.Errorf("limit=250 -> %d; want 250", f.Limit)
	}
	if f := parseFilter(httptest.NewRequest("GET", "/events", nil)); f.Limit != 100 {
		t.Errorf("default limit -> %d; want 100", f.Limit)
	}
}

func TestSvcLinkAndDefenseURL(t *testing.T) {
	s := string(svcLink(110)) // pop3
	if !strings.Contains(s, `href="/events?port=110"`) || !strings.Contains(s, ">pop3<") {
		t.Errorf("svcLink(110) wrong: %q", s)
	}
	if string(svcLink(0)) != "" {
		t.Error("svcLink for an unnamed port should be empty")
	}
	u := defenseURL("D3-MFA")
	if u != "https://d3fend.mitre.org/technique/d3f:Multi-factorAuthentication/" {
		t.Errorf("defenseURL(D3-MFA) = %q", u)
	}
	if defenseURL("D3-NOPE") != "" {
		t.Error("defenseURL for an unknown id should be empty")
	}
}

// The event detail must link D3FEND ids and append a flag to geo_country.
func TestEventDetailDefenseAndCountry(t *testing.T) {
	tmpl := uiTmpl(t)
	ev := &event.Event{
		ID: "x", RuleID: "r", Severity: event.SeverityHigh,
		MitreTechniques: []string{"T1110"}, MitreDefenses: []string{"D3-MFA"},
		Meta: map[string]any{"geo_country": "US"},
	}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "event", ev); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	// uiTmpl enables attack links, so D3FEND should be an external d3fend link.
	if !strings.Contains(out, "d3fend.mitre.org/technique/d3f:Multi-factorAuthentication") {
		t.Errorf("event detail missing D3FEND link: %q", out)
	}
	if !strings.Contains(out, "US 🇺🇸") {
		t.Errorf("event detail missing country flag for geo_country")
	}
}
