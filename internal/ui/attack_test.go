package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestBuildAttackView(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		// ssh handler → T1110.001 (credential-access) + T1078 (initial-access)
		{RuleID: "listener:ssh", Handler: "ssh", Time: now, Source: event.Endpoint{IP: "1.1.1.1"}},
		// http handler → T1190/T1083, augmented by a webapp:sqli anomaly (T1190).
		{RuleID: "listener:web", Handler: "http", Time: now, Source: event.Endpoint{IP: "2.2.2.2"},
			Meta: map[string]any{"anomalies": []any{"webapp:sqli"}}},
		// a storyline chain
		{RuleID: "storyline:multi_stage", Handler: "", Time: now, Source: event.Endpoint{IP: "3.3.3.3"},
			Meta: map[string]any{"chain": "discovery -> credential-access -> lateral-movement"}},
	}
	v := buildAttackView(now.Add(-time.Hour), evs)

	if v.Events < 2 {
		t.Fatalf("expected >=2 attributed events, got %d", v.Events)
	}
	// credential-access tactic should be present (from ssh).
	var hasCred bool
	for _, tac := range v.Tactics {
		if tac.Tactic == "credential-access" {
			hasCred = true
		}
	}
	if !hasCred {
		t.Errorf("credential-access tactic missing: %+v", v.Tactics)
	}
	// T1190 technique should rank in the heatmap (http + sqli).
	var hasT1190 bool
	for _, b := range v.TopTech {
		if b.Label == "T1190" {
			hasT1190 = true
		}
	}
	if !hasT1190 {
		t.Errorf("T1190 missing from technique heatmap: %+v", v.TopTech)
	}
	if len(v.Chains) != 1 || !strings.Contains(v.Chains[0].Chain, "lateral-movement") {
		t.Errorf("storyline chain not captured: %+v", v.Chains)
	}

	// Template renders.
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "attack", v); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"ATT&amp;CK mapping", "tactic timeline", "credential-access", "technique heatmap"} {
		if !strings.Contains(html, want) {
			t.Errorf("attack page missing %q", want)
		}
	}
}

func TestAttackViewTacticsKillChainOrder(t *testing.T) {
	now := time.Now()
	// Mix: impact (modbus T0814) + initial-access (http) + credential-access (ssh).
	evs := []*event.Event{
		{RuleID: "listener:a", Handler: "ssh", Time: now},
		{RuleID: "listener:b", Handler: "http", Time: now},
		{RuleID: "listener:c", Handler: "modbus", Time: now},
	}
	v := buildAttackView(now.Add(-time.Hour), evs)
	// Tactics must come back in reconnaissance→impact rank order.
	for i := 1; i < len(v.Tactics); i++ {
		if v.Tactics[i-1].Rank > v.Tactics[i].Rank {
			t.Fatalf("tactics not in kill-chain order: %+v", v.Tactics)
		}
	}
}
