package router

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestMatchSeverityOnly(t *testing.T) {
	m := config.Match{Severity: ">=high"}
	if !matchEvent(m, &event.Event{Severity: event.SeverityHigh}) {
		t.Error("expected severity match")
	}
	if matchEvent(m, &event.Event{Severity: event.SeverityLow}) {
		t.Error("low should not pass >=high")
	}
}

func TestMatchHoneynet(t *testing.T) {
	m := config.Match{Honeynet: "corp-lan"}
	if !matchEvent(m, &event.Event{Meta: map[string]any{"honeynet": "corp-lan"}}) {
		t.Error("expected honeynet match")
	}
	if matchEvent(m, &event.Event{Meta: map[string]any{"honeynet": "other"}}) {
		t.Error("wrong honeynet should not match")
	}
	if matchEvent(m, &event.Event{}) {
		t.Error("missing meta should not match")
	}
}

func TestMatchHoneynetOS(t *testing.T) {
	m := config.Match{HoneynetOS: "windows"}
	if !matchEvent(m, &event.Event{Meta: map[string]any{"honeynet_os": "windows"}}) {
		t.Error("windows match")
	}
	if matchEvent(m, &event.Event{Meta: map[string]any{"honeynet_os": "linux"}}) {
		t.Error("linux should not match windows")
	}
}

func TestMatchRuleID(t *testing.T) {
	m := config.Match{RuleID: "listener:ssh-bait"}
	if !matchEvent(m, &event.Event{RuleID: "listener:ssh-bait"}) {
		t.Error("rule id match")
	}
	if matchEvent(m, &event.Event{RuleID: "listener:http-bait"}) {
		t.Error("wrong rule id should not match")
	}
}

func TestMatchANDSemantics(t *testing.T) {
	m := config.Match{Severity: ">=high", Honeynet: "corp", HoneynetOS: "windows"}
	ev := &event.Event{
		Severity: event.SeverityHigh,
		Meta:     map[string]any{"honeynet": "corp", "honeynet_os": "windows"},
	}
	if !matchEvent(m, ev) {
		t.Error("all-true conjunction should match")
	}
	// Flip OS to linux — the conjunction should fail.
	ev.Meta["honeynet_os"] = "linux"
	if matchEvent(m, ev) {
		t.Error("AND semantics: one false predicate should fail the whole match")
	}
}

func TestMatchEmptyMatchesEverything(t *testing.T) {
	m := config.Match{}
	if !matchEvent(m, &event.Event{}) {
		t.Error("empty match should match every event")
	}
}
