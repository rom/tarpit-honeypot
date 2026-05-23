package correlate

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestThreatIntelBurstFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		ThreatIntelBurst: config.CorrThreatIntelBurst{Enabled: true, Events: 3, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 3; i++ {
		ev := mkEvent("203.0.113.9", 22, now.Add(time.Duration(i)*time.Second))
		ev.Meta = map[string]any{"threat_intel_hit": true, "threat_intel": []string{"firehol"}}
		last = cor.Observe(ev)
	}
	agg := aggregate(last, "correlate:threat_intel_burst")
	if agg == nil {
		t.Fatalf("threat_intel_burst did not fire: %v", last)
	}
	if agg.Meta["events"].(int) != 3 {
		t.Errorf("events = %v; want 3", agg.Meta["events"])
	}
	// A clean source must never trip it.
	clean := mkEvent("8.8.8.8", 22, now)
	for i := 0; i < 5; i++ {
		if aggregate(cor.Observe(clean), "correlate:threat_intel_burst") != nil {
			t.Fatal("clean source must not trip threat_intel_burst")
		}
	}
}

func TestThreatIntelBurstWorksForPortlessEvents(t *testing.T) {
	// ICMP (port 0) events from a Tor exit should still count.
	cor, _ := New(config.Correlate{
		ThreatIntelBurst: config.CorrThreatIntelBurst{Enabled: true, Events: 2, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 2; i++ {
		ev := &event.Event{
			ID: event.NewID(), Time: now.Add(time.Duration(i) * time.Second), Sensor: "t",
			RuleID: "icmp:echo", Proto: "icmp",
			Source: event.Endpoint{IP: "185.220.101.1"},
			Meta:   map[string]any{"tor_exit": true},
		}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:threat_intel_burst") == nil {
		t.Fatalf("threat_intel_burst should fire on port-0 Tor events: %v", last)
	}
}

func TestGeoVelocityFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		GeoVelocity: config.CorrGeoVelocity{Enabled: true, DistinctCountries: 2, Window: time.Hour, Severity: "high"},
	})
	now := time.Now().UTC()
	mk := func(srcIP, country string) *event.Event {
		ev := mkEvent(srcIP, 22, now)
		ev.Meta = map[string]any{"auth_user": "root", "auth_pass": "toor", "geo_country": country}
		return ev
	}
	cor.Observe(mk("1.1.1.1", "US"))
	last := cor.Observe(mk("2.2.2.2", "RU"))
	agg := aggregate(last, "correlate:geo_velocity")
	if agg == nil {
		t.Fatalf("geo_velocity did not fire: %v", last)
	}
	if agg.Meta["distinct_countries"].(int) != 2 {
		t.Errorf("distinct_countries = %v; want 2", agg.Meta["distinct_countries"])
	}
	// The credential must NOT leak into the aggregate event meta.
	for k, v := range agg.Meta {
		if s, ok := v.(string); ok && (s == "toor" || s == "root:toor") {
			t.Errorf("credential leaked into meta[%s]=%q", k, s)
		}
	}
}

func TestGeoVelocitySameCountryDoesNotFire(t *testing.T) {
	cor, _ := New(config.Correlate{
		GeoVelocity: config.CorrGeoVelocity{Enabled: true, DistinctCountries: 2, Window: time.Hour, Severity: "high"},
	})
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		ev := mkEvent("1.1.1.1", 22, now)
		ev.Meta = map[string]any{"auth_user": "admin", "auth_pass": "x", "geo_country": "US"}
		if aggregate(cor.Observe(ev), "correlate:geo_velocity") != nil {
			t.Fatal("single-country credential reuse must not trip geo_velocity")
		}
	}
}
