package correlate

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// A chain that lands a CVE exploit is escalated to Critical and records
// the exploited CVE id in the storyline meta.
func TestStorylineEscalatesOnCVE(t *testing.T) {
	c, err := New(config.Correlate{})
	if err != nil {
		t.Fatal(err)
	}
	src := event.Endpoint{IP: "203.0.113.55"}
	now := time.Now().UTC()

	c.Observe(&event.Event{Source: src, Dest: event.Endpoint{Port: 161}, Handler: "snmp",
		RuleID: "listener:snmp", Time: now,
		MitreTactics: []string{"discovery"}, MitreTechniques: []string{"T1018"}})
	c.Observe(&event.Event{Source: src, Dest: event.Endpoint{Port: 22}, Handler: "ssh",
		RuleID: "listener:ssh", Time: now.Add(time.Second),
		MitreTactics: []string{"credential-access"}, MitreTechniques: []string{"T1110.001"}})
	// CVE exploit attempt = initial-access stage 3 -> fires + escalates.
	out := c.Observe(&event.Event{Source: src, Dest: event.Endpoint{Port: 80}, Handler: "http",
		RuleID: "cve:CVE-2021-44228", Time: now.Add(2 * time.Second),
		MitreTactics: []string{"initial-access"}, MitreTechniques: []string{"T1190"}})

	var story *event.Event
	for _, e := range out {
		if e.RuleID == "storyline:multi_stage" {
			story = e
		}
	}
	if story == nil {
		t.Fatal("expected storyline event")
	}
	if story.Severity != event.SeverityCritical {
		t.Errorf("severity = %v; want critical (CVE exploit in chain)", story.Severity)
	}
	cves, _ := story.Meta["cve_exploits"].([]string)
	if len(cves) != 1 || cves[0] != "CVE-2021-44228" {
		t.Errorf("cve_exploits = %v; want [CVE-2021-44228]", story.Meta["cve_exploits"])
	}
	if len(story.MitreDefenses) == 0 {
		t.Error("storyline should carry D3FEND defenses")
	}
}

// Reaching the impact tactic flips objective_reached + Critical.
func TestStorylineObjectiveReached(t *testing.T) {
	c, _ := New(config.Correlate{})
	src := event.Endpoint{IP: "203.0.113.56"}
	now := time.Now().UTC()
	c.Observe(&event.Event{Source: src, RuleID: "listener:http", Handler: "http", Time: now,
		MitreTactics: []string{"discovery"}, MitreTechniques: []string{"T1046"}})
	c.Observe(&event.Event{Source: src, RuleID: "listener:ssh", Handler: "ssh", Time: now.Add(time.Second),
		MitreTactics: []string{"credential-access"}, MitreTechniques: []string{"T1110"}})
	out := c.Observe(&event.Event{Source: src, RuleID: "listener:modbus", Handler: "modbus", Time: now.Add(2 * time.Second),
		MitreTactics: []string{"impact"}, MitreTechniques: []string{"T0814"}})
	var story *event.Event
	for _, e := range out {
		if e.RuleID == "storyline:multi_stage" {
			story = e
		}
	}
	if story == nil {
		t.Fatal("expected storyline event")
	}
	if story.Meta["objective_reached"] != true {
		t.Errorf("objective_reached = %v; want true", story.Meta["objective_reached"])
	}
	if story.Severity != event.SeverityCritical {
		t.Errorf("severity = %v; want critical (objective reached)", story.Severity)
	}
}
