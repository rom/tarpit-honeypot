package enrich

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func hasLabel(ev *event.Event, want string) bool {
	ls, _ := ev.Meta["labels"].([]string)
	for _, l := range ls {
		if l == want {
			return true
		}
	}
	return false
}

// OT classification must fire for RFC1918 sources — OT segments are private, and
// the GeoIP/reputation path early-returns on them, so this is the regression
// that "not all OT recon is marked" was really about.
func TestDecorateOTClassPrivateSource(t *testing.T) {
	e := &Enricher{}
	ev := &event.Event{Handler: "modbus", Source: event.Endpoint{IP: "10.2.3.4"}, Meta: map[string]any{}}
	e.Decorate(ev)
	if ev.Meta["ot"] != true {
		t.Errorf("private-source OT event should set ot=true, got %v", ev.Meta["ot"])
	}
	if ev.Meta["ot_class"] != "ics" {
		t.Errorf("ot_class = %v want ics", ev.Meta["ot_class"])
	}
	if ev.Meta["targeting"] != "ics-ot" {
		t.Errorf("targeting = %v want ics-ot", ev.Meta["targeting"])
	}
	if !hasLabel(ev, "meta:ot") {
		t.Errorf("want meta:ot umbrella label, got %v", ev.Meta["labels"])
	}
}

func TestDecorateOTClassDomains(t *testing.T) {
	e := &Enricher{}
	for handler, wantClass := range map[string]string{"knx": "bas", "dicom": "medtech", "fhir": "medtech"} {
		ev := &event.Event{Handler: handler, Source: event.Endpoint{IP: "192.168.1.5"}, Meta: map[string]any{}}
		e.Decorate(ev)
		if ev.Meta["ot_class"] != wantClass {
			t.Errorf("%s: ot_class = %v want %v", handler, ev.Meta["ot_class"], wantClass)
		}
		if ev.Meta["ot"] != true || !hasLabel(ev, "meta:ot") {
			t.Errorf("%s: should carry the OT umbrella", handler)
		}
	}
	// A non-OT handler carries no OT signal.
	ev := &event.Event{Handler: "http", Source: event.Endpoint{IP: "192.168.1.5"}, Meta: map[string]any{}}
	e.Decorate(ev)
	if _, ok := ev.Meta["ot"]; ok {
		t.Error("non-OT handler must not set ot")
	}
}

// ot-recon now fires on any recon/hostile-origin signal (not only hidden/rented)
// — scanner, automation, reputation, or a novel ASN — but never on a plain
// residential/direct touch.
func TestOTReconBroadened(t *testing.T) {
	fire := []map[string]any{
		{"ot": true, "targeting": "ics-ot", "known_scanner": "shodan"},
		{"ot": true, "targeting": "ics-ot", "tls_automation": "non-browser TLS (no ALPN)"},
		{"ot": true, "targeting": "ics-ot", "fp_tool": true},
		{"ot": true, "targeting": "ics-ot", "novel_asn": true},
		{"ot": true, "targeting": "ics-ot", "threat_intel_hit": true},
		{"ot": true, "targeting": "ics-ot", "anonymized": true}, // original path still works
	}
	for i, m := range fire {
		got := metaSignals(&event.Event{RuleID: "listener:x", Meta: m})
		if !labelsHave(got, "meta:ot-recon") {
			t.Errorf("case %d: expected meta:ot-recon for %v, got %v", i, m, got)
		}
		if !labelsHave(got, "meta:ot") {
			t.Errorf("case %d: expected meta:ot umbrella, got %v", i, got)
		}
	}
	// No recon context → meta:ot umbrella but NOT ot-recon.
	got := metaSignals(&event.Event{Meta: map[string]any{"ot": true, "targeting": "ics-ot", "conn_type": "residential"}})
	if labelsHave(got, "meta:ot-recon") {
		t.Errorf("residential/direct OT touch must not fire ot-recon: %v", got)
	}
	if !labelsHave(got, "meta:ot") {
		t.Errorf("should still carry meta:ot: %v", got)
	}
	// Medtech target with a recon signal → meta:medtech-recon.
	med := metaSignals(&event.Event{Meta: map[string]any{"ot": true, "targeting": "healthcare", "threat_intel_hit": true}})
	if !labelsHave(med, "meta:medtech-recon") {
		t.Errorf("expected meta:medtech-recon, got %v", med)
	}
}

func labelsHave(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
