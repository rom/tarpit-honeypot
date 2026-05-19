package correlate

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// A storyline only fires once the source has touched StoryMinStages
// distinct ATT&CK tactics inside StoryWindow. Two tactics alone don't
// fire it; the third tactic flips the threshold.
func TestStorylineFiresAtThirdTactic(t *testing.T) {
	c, err := New(config.Correlate{})
	if err != nil {
		t.Fatal(err)
	}
	src := event.Endpoint{IP: "203.0.113.10"}
	now := time.Now().UTC()

	// Stage 1: discovery.
	e1 := &event.Event{
		Source: src, Dest: event.Endpoint{Port: 22}, Handler: "snmp",
		RuleID: "listener:snmp", Time: now,
		MitreTactics: []string{"discovery"}, MitreTechniques: []string{"T1018"},
	}
	if got := c.Observe(e1); len(got) > 1 {
		t.Errorf("stage 1 should not fire storyline, got %d events", len(got))
	}

	// Stage 2: credential-access.
	e2 := &event.Event{
		Source: src, Dest: event.Endpoint{Port: 22}, Handler: "ssh",
		RuleID: "listener:ssh", Time: now.Add(time.Second),
		MitreTactics: []string{"credential-access"}, MitreTechniques: []string{"T1110.001"},
	}
	if got := c.Observe(e2); len(got) > 1 {
		t.Errorf("stage 2 should not fire, got %d events", len(got))
	}

	// Stage 3: lateral-movement — this should fire the storyline.
	e3 := &event.Event{
		Source: src, Dest: event.Endpoint{Port: 445}, Handler: "smb",
		RuleID: "listener:smb", Time: now.Add(2 * time.Second),
		MitreTactics: []string{"lateral-movement"}, MitreTechniques: []string{"T1021.002"},
	}
	out := c.Observe(e3)
	if len(out) < 2 {
		t.Fatalf("stage 3 should fire storyline, got %d events", len(out))
	}
	story := out[len(out)-1]
	if story.RuleID != "storyline:multi_stage" {
		t.Errorf("storyline rule_id = %q", story.RuleID)
	}
	chain, _ := story.Meta["chain"].(string)
	if !strings.Contains(chain, "discovery") ||
		!strings.Contains(chain, "credential-access") ||
		!strings.Contains(chain, "lateral-movement") {
		t.Errorf("chain missing one of the stages: %q", chain)
	}
	// Tactics should be ordered by ATT&CK kill-chain rank.
	stages, _ := story.Meta["stages"].([]string)
	if len(stages) >= 3 {
		// credential-access < discovery < lateral-movement.
		if stages[0] != "credential-access" {
			t.Errorf("first stage should be credential-access, got %v", stages)
		}
		if stages[len(stages)-1] != "lateral-movement" {
			t.Errorf("last stage should be lateral-movement, got %v", stages)
		}
	}
}

// Once a storyline has emitted, it shouldn't re-emit on every
// follow-up event — only when the source picks up another set of
// new stages worth of activity.
func TestStorylineRateLimitsReemissions(t *testing.T) {
	c, err := New(config.Correlate{})
	if err != nil {
		t.Fatal(err)
	}
	src := event.Endpoint{IP: "203.0.113.10"}
	now := time.Now().UTC()
	stages := []string{"discovery", "credential-access", "lateral-movement", "impact"}
	techs := []string{"T1018", "T1110", "T1021", "T0814"}
	emissions := 0
	for i, s := range stages {
		out := c.Observe(&event.Event{
			Source: src, Dest: event.Endpoint{Port: 80}, Handler: "http",
			RuleID: "listener:bait", Time: now.Add(time.Duration(i) * time.Second),
			MitreTactics: []string{s}, MitreTechniques: []string{techs[i]},
		})
		for _, o := range out {
			if o.RuleID == "storyline:multi_stage" {
				emissions++
			}
		}
	}
	if emissions == 0 {
		t.Errorf("expected at least one storyline emission across 4 stages")
	}
	if emissions > 2 {
		t.Errorf("expected ≤2 emissions across 4 stages (re-emit policy), got %d", emissions)
	}
}

// A storyline window closing (>StoryWindow gap) should reset the
// source's stage tracker — the source then needs to climb the chain
// again before a fresh storyline fires.
func TestStorylineExpiresAfterWindow(t *testing.T) {
	c, err := New(config.Correlate{})
	if err != nil {
		t.Fatal(err)
	}
	src := event.Endpoint{IP: "203.0.113.10"}
	now := time.Now().UTC()
	// Lay down three stages so storyline fires.
	for i, s := range []string{"discovery", "credential-access", "lateral-movement"} {
		c.Observe(&event.Event{
			Source: src, Dest: event.Endpoint{Port: 22}, Handler: "ssh",
			RuleID: "listener:ssh", Time: now.Add(time.Duration(i) * time.Second),
			MitreTactics: []string{s},
		})
	}
	// Jump past StoryWindow.
	later := now.Add(StoryWindow + time.Minute)
	out := c.Observe(&event.Event{
		Source: src, Dest: event.Endpoint{Port: 22}, Handler: "ssh",
		RuleID: "listener:ssh", Time: later,
		MitreTactics: []string{"discovery"},
	})
	for _, o := range out {
		if o.RuleID == "storyline:multi_stage" {
			t.Errorf("storyline should NOT re-fire on a fresh source-window with only 1 stage")
		}
	}
}

// Events with no ATT&CK tactics shouldn't contribute to the storyline.
// Otherwise sensor:reload / sensor:panic would inflate the stage count.
func TestStorylineIgnoresUntaggedEvents(t *testing.T) {
	c, err := New(config.Correlate{})
	if err != nil {
		t.Fatal(err)
	}
	src := event.Endpoint{IP: "10.0.0.1"}
	for i := 0; i < 5; i++ {
		out := c.Observe(&event.Event{
			Source: src, RuleID: "sensor:reload",
			Time: time.Now().Add(time.Duration(i) * time.Second),
		})
		for _, o := range out {
			if o.RuleID == "storyline:multi_stage" {
				t.Errorf("untagged events should not produce a storyline")
			}
		}
	}
}
