package sensor

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func newFirstSeenSensor(enabled bool) *Sensor {
	c := &config.Config{}
	c.Sensor.Alerts.FirstSeen = enabled
	return &Sensor{name: "t", cfg: c, seenSources: map[string]struct{}{}}
}

func TestFirstSeenFiresOncePerSource(t *testing.T) {
	s := newFirstSeenSensor(true)
	ev := &event.Event{RuleID: "listener:ssh", Severity: event.SeverityHigh, Source: event.Endpoint{IP: "1.2.3.4"}}
	if got := s.observeFirstSeen(ev); got == nil || got.RuleID != "source:first_seen" {
		t.Fatalf("first occurrence should fire source:first_seen, got %v", got)
	}
	if got := s.observeFirstSeen(ev); got != nil {
		t.Errorf("second occurrence should not fire, got %v", got.RuleID)
	}
}

func TestFirstSeenGatedBelowMedium(t *testing.T) {
	s := newFirstSeenSensor(true)
	ev := &event.Event{RuleID: "listener:ssh", Severity: event.SeverityLow, Source: event.Endpoint{IP: "9.9.9.9"}}
	if got := s.observeFirstSeen(ev); got != nil {
		t.Errorf("low-severity event should not fire first_seen")
	}
}

func TestFirstSeenDisabled(t *testing.T) {
	s := newFirstSeenSensor(false)
	ev := &event.Event{RuleID: "listener:ssh", Severity: event.SeverityCritical, Source: event.Endpoint{IP: "1.1.1.1"}}
	if got := s.observeFirstSeen(ev); got != nil {
		t.Errorf("first_seen should be off when disabled")
	}
}

func TestFirstSeenSkipsSyntheticEvents(t *testing.T) {
	s := newFirstSeenSensor(true)
	for _, rid := range []string{"risk:high", "source:first_seen", "sensor:health"} {
		ev := &event.Event{RuleID: rid, Severity: event.SeverityHigh, Source: event.Endpoint{IP: "2.2.2.2"}}
		if got := s.observeFirstSeen(ev); got != nil {
			t.Errorf("%s should not trigger first_seen", rid)
		}
	}
}
