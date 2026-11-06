package correlate

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestAgenticEscalationFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		AgenticEscalation: config.CorrAgenticEscalation{Enabled: true, DistinctSignals: 3, Window: time.Minute, Severity: "critical"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, m := range []string{"agent:bait-identity", "agent:provoke-plan", "agent:counter-exfil"} {
		ev := mkEvent("8.8.8.8", 8080, now.Add(time.Duration(i)*time.Second))
		ev.Handler = "agent"
		ev.Anomalies = []string{m}
		last = cor.Observe(ev)
	}
	a := aggregate(last, "correlate:agentic_escalation")
	if a == nil {
		t.Fatalf("agentic_escalation did not fire: %v", last)
	}
	if n, _ := a.Meta["distinct_signals"].(int); n < 3 {
		t.Errorf("distinct_signals=%v want >=3", a.Meta["distinct_signals"])
	}
}

func TestAgenticEscalationNeedsDistinct(t *testing.T) {
	cor, _ := New(config.Correlate{
		AgenticEscalation: config.CorrAgenticEscalation{Enabled: true, DistinctSignals: 3, Window: time.Minute, Severity: "critical"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	// Same marker repeated is only one distinct signal — must NOT fire.
	for i := 0; i < 5; i++ {
		ev := mkEvent("8.8.8.9", 8080, now.Add(time.Duration(i)*time.Second))
		ev.Handler = "agent"
		ev.Anomalies = []string{"agent:bait-identity"}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:agentic_escalation") != nil {
		t.Error("agentic_escalation fired on a single distinct marker repeated")
	}
}
