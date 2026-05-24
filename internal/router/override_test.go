package router

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/sink"
)

func TestSeverityOverrideMarksEvent(t *testing.T) {
	cfg := &config.Config{
		SeverityOverrides: []config.SeverityOverride{
			{Rule: "correlate:port_scan", Severity: "high"},
			{Rule: "cve:*", Severity: "critical"},
		},
		Dedup: config.Dedup{DefaultWindow: time.Second},
	}
	r := makeRouter(t, cfg, map[string]sink.Sink{})

	ev := &event.Event{RuleID: "correlate:port_scan", Severity: event.SeverityLow}
	r.applySeverityOverride(ev)
	if ev.Severity != event.SeverityHigh || !ev.SeverityOverridden {
		t.Fatalf("override not applied: sev=%v overridden=%v", ev.Severity, ev.SeverityOverridden)
	}
	if ev.Meta["default_severity"] != "low" || ev.Meta["severity_override_rule"] != "correlate:port_scan" {
		t.Errorf("override meta wrong: %v", ev.Meta)
	}
	// Idempotent: second call doesn't re-mark or change the (already-changed) default.
	r.applySeverityOverride(ev)
	if ev.Meta["default_severity"] != "low" {
		t.Errorf("override not idempotent: %v", ev.Meta)
	}

	// Prefix override.
	cve := &event.Event{RuleID: "cve:CVE-2024-1709", Severity: event.SeverityHigh}
	r.applySeverityOverride(cve)
	if cve.Severity != event.SeverityCritical || cve.Meta["severity_override_rule"] != "cve:*" {
		t.Errorf("prefix override wrong: %v / %v", cve.Severity, cve.Meta)
	}

	// No override, no marking.
	other := &event.Event{RuleID: "listener:ssh-bait", Severity: event.SeverityMedium}
	r.applySeverityOverride(other)
	if other.SeverityOverridden {
		t.Errorf("unrelated event should not be marked")
	}
}

// An override that raises severity must let the event through a channel whose
// min-severity it now meets (routing reflects the override).
func TestSeverityOverrideAffectsRouting(t *testing.T) {
	highOnly := &fakeSink{id: "soc"}
	cfg := &config.Config{
		Channels: []config.Channel{{ID: "soc", Type: "webhook", MinSeverity: "high"}},
		Routes:   []config.Route{{Match: config.Match{Severity: ">=low"}, Channels: []string{"soc"}}},
		SeverityOverrides: []config.SeverityOverride{
			{Rule: "correlate:port_scan", Severity: "high"},
		},
		Dedup: config.Dedup{DefaultWindow: time.Millisecond},
	}
	r := makeRouter(t, cfg, map[string]sink.Sink{"soc": highOnly})
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	r.Dispatch(&event.Event{RuleID: "correlate:port_scan", Severity: event.SeverityLow, Source: event.Endpoint{IP: "1.2.3.4"}})
	time.Sleep(50 * time.Millisecond)
	cancel()
	r.Stop()
	if highOnly.count() != 1 {
		t.Errorf("overridden-to-high event should reach the high-min channel; got %d", highOnly.count())
	}
}
