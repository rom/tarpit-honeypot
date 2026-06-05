package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestBuildThreatMapView(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{RuleID: "listener:ssh", Handler: "ssh", Time: now.Add(-2 * time.Minute),
			Source: event.Endpoint{IP: "9.9.9.9"}, Severity: event.SeverityCritical,
			Meta: map[string]any{
				"geo_lat": 51.5, "geo_lon": -0.12, "geo_country": "GB", "geo_city": "London",
				"asn": "AS123", "asn_org": "EvilNet", "net_class": "hosting",
				"threat_intel_hit": true, "tor_exit": true,
			}},
		{RuleID: "listener:web", Handler: "http", Time: now.Add(-1 * time.Minute),
			Source: event.Endpoint{IP: "8.8.8.8"}, Severity: event.SeverityLow,
			Meta: map[string]any{
				"geo_lat": 37.4, "geo_lon": -122.0, "geo_country": "US", "asn": "AS456", "asn_org": "Cloudy",
			}},
	}
	v := buildThreatMapView(now.Add(-time.Hour), evs)

	if v.GeoLocated != 2 {
		t.Errorf("geo-located = %d; want 2", v.GeoLocated)
	}
	if !v.HasMap || v.MapB64 == "" {
		t.Errorf("expected a rendered source map")
	}
	// Two countries, both ASNs present.
	if len(v.Countries) != 2 {
		t.Errorf("countries = %+v; want 2", v.Countries)
	}
	// Tor + threat-intel hit should land in the intel sources + counters.
	var hasTor bool
	for _, b := range v.IntelSources {
		if b.Label == "tor-exit" {
			hasTor = true
		}
	}
	if !hasTor {
		t.Errorf("tor-exit not surfaced in intel sources: %+v", v.IntelSources)
	}
	// Only the critical event qualifies as recent high-severity.
	if len(v.Recent) != 1 || v.Recent[0].Source != "9.9.9.9" || !v.Recent[0].Intel {
		t.Errorf("recent high-sev hits wrong: %+v", v.Recent)
	}

	// Template renders.
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "threatmap", v); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"threat map", "top countries", "recent high-severity"} {
		if !strings.Contains(html, want) {
			t.Errorf("threat map page missing %q", want)
		}
	}

	// The events / countries / ASNs counters are clickable.
	href := map[string]string{"events": "/events", "countries": "#map-countries", "ASNs": "#map-asns"}
	for _, c := range v.Counters {
		if want, ok := href[c.Label]; ok && c.Href != want {
			t.Errorf("counter %q Href = %q, want %q", c.Label, c.Href, want)
		}
	}
	for _, want := range []string{
		`href="/events"`, `href="#map-countries"`, `href="#map-asns"`,
		`id="map-countries"`, `id="map-asns"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("threat map missing clickable counter markup %q", want)
		}
	}
}

func TestThreatMapNoGeo(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{RuleID: "listener:ssh", Handler: "ssh", Time: now, Source: event.Endpoint{IP: "1.2.3.4"}, Severity: event.SeverityMedium},
	}
	v := buildThreatMapView(now.Add(-time.Hour), evs)
	if v.HasMap {
		t.Errorf("expected no map without geo data")
	}
	if v.GeoLocated != 0 {
		t.Errorf("geo-located = %d; want 0", v.GeoLocated)
	}
	// Renders the "no geo" path without error.
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "threatmap", v); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "no geo-located events") {
		t.Errorf("expected no-geo note")
	}
}
