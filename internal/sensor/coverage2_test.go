package sensor

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/router"
)

func TestNewBlockerAndRiskScorer(t *testing.T) {
	if newRiskScorer(config.RiskScoring{Enabled: false}) != nil {
		t.Error("disabled risk scorer should be nil")
	}
	if newRiskScorer(config.RiskScoring{Enabled: true, HalfLife: time.Hour, Elevated: 10, High: 20, Critical: 30}) == nil {
		t.Error("enabled risk scorer should be non-nil")
	}
	// newBlocker is always non-nil (a disabled blocker is a no-op, not nil).
	b := newBlocker(config.Blocklist{})
	if b == nil {
		t.Error("newBlocker should never return nil")
	}
	if b.ShouldBlock("1.2.3.4", "critical") {
		t.Error("a disabled blocker must never say ShouldBlock")
	}
}

func TestScoreRiskCrossesThreshold(t *testing.T) {
	rt, err := router.New(&config.Config{}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	rt.Start(context.Background())
	s := &Sensor{
		name:     "t",
		identity: identity.New("seed"),
		risk:     newRiskScorer(config.RiskScoring{Enabled: true, HalfLife: time.Hour, Elevated: 1, High: 1000, Critical: 2000}),
		blocker:  newBlocker(config.Blocklist{}),
	}
	ev := &event.Event{Source: event.Endpoint{IP: "203.0.113.9"}, Proto: "tcp", RuleID: "listener:ssh", Severity: event.SeverityCritical}
	// Several high-severity events from one source cross the low "elevated"
	// threshold, exercising scoreRisk's dispatch + blocker path.
	for i := 0; i < 5; i++ {
		s.scoreRisk(rt, ev)
	}
	// risk:-prefixed events and sourceless events are ignored (guard branch).
	s.scoreRisk(rt, &event.Event{RuleID: "risk:high", Source: event.Endpoint{IP: "203.0.113.9"}})
	s.scoreRisk(rt, &event.Event{RuleID: "listener:x"}) // no source IP
	// nil scorer → no-op.
	(&Sensor{}).scoreRisk(rt, ev)
}
