package correlate

import (
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Round-13 agentic correlator: an autonomous LLM agent being strung up the
// agent-provocateur's bait ladder. See docs/AGENTIC.md.

// checkAgenticEscalation counts the DISTINCT agent:* provocation markers one
// source trips across a window — the agent handler escalates its bait each turn
// (identity → config → credentials → plan → tools → operator → environment →
// enrolment → attack-decoy, plus counter-exfil / provoked / injection-confirmed).
// Several distinct markers from one source means a persistent autonomous agent
// is being driven up that ladder, not a one-off probe.
func checkAgenticEscalationMarker(a string) bool {
	// Count the escalation-bearing agent markers, not every agent:* tag (so a
	// bare protocol probe like agent:a2a alone does not inflate the count).
	return strings.HasPrefix(a, "agent:bait-") ||
		strings.HasPrefix(a, "agent:provoke-") ||
		strings.HasPrefix(a, "agent:provoked") ||
		a == "agent:counter-exfil" ||
		a == "agent:injection-confirmed" ||
		a == "agent:provocateur"
}

func (c *Correlator) checkAgenticEscalation(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.AgenticEscalation
	st := windowedSet(c.agenticEsc, ev.Source.IP, now, cfg.Window)
	hit := false
	for _, a := range ev.Anomalies {
		if checkAgenticEscalationMarker(a) {
			if len(st.set) < corrSetCap {
				st.set[a] = struct{}{}
			}
			hit = true
		}
	}
	if !hit || len(st.set) < cfg.DistinctSignals {
		return nil
	}
	if !c.shouldEmit("agenticesc|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:agentic_escalation", Severity: c.agenticEscSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"distinct_signals": len(st.set),
			"signals":          setKeys(st.set),
			"window_s":         int(cfg.Window.Seconds()),
		},
	}
}
