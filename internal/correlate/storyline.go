package correlate

import (
	"sort"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/mitre"
)

// storylineState tracks every distinct (rule_id, ATT&CK tactic, dest
// port, handler) tuple a single source IP has produced inside the
// storyline window. Once the source has touched StoryMinStages
// distinct ATT&CK tactics, the correlator emits a storyline:* event
// summarizing the path it walked (e.g.
// "discovery → credential-access → lateral-movement"). The summary
// is what makes a SOC triage tractable: instead of 47 individual
// "source touched port 22" lines, the analyst sees one
// "203.0.113.10 ran an attack from discovery to impact in 4 minutes"
// timeline.
type storylineState struct {
	firstSeen time.Time
	lastSeen  time.Time
	// stages preserves the order tactics first appeared. We re-render
	// it as a "->" arrow chain in the storyline event meta.
	stages       []string
	stageSeen    map[string]bool
	ruleHits     map[string]int
	techniques   map[string]bool
	destPorts    map[int]bool
	handlers     map[string]bool
	hitCount     int
	lastEmittedSize int
}

// StoryMinStages is the minimum number of distinct ATT&CK tactics a
// source must touch within StoryWindow before a storyline:* event
// fires. Two stages alone (e.g. just "discovery") is too low signal;
// at three the activity is clearly multi-step.
const StoryMinStages = 3

// StoryWindow is how long a source-IP storyline stays "open". Activity
// older than this is pruned and the source starts a fresh storyline
// on its next event.
const StoryWindow = 30 * time.Minute

// StoryReEmitEvery controls how many new stages can accumulate after
// an initial emission before we emit a refreshed storyline. Stops the
// router from re-emitting on every single follow-up event.
const StoryReEmitEvery = 2

// observeStoryline ingests an event and returns a storyline:* event
// if the source has crossed a new threshold. Must be called with
// c.mu held.
func (c *Correlator) observeStoryline(ev *event.Event, now time.Time) *event.Event {
	if ev.Source.IP == "" || len(ev.MitreTactics) == 0 {
		return nil
	}
	// Skip storyline-on-storyline recursion.
	if len(ev.RuleID) >= 10 && ev.RuleID[:10] == "storyline:" {
		return nil
	}
	st, ok := c.story[ev.Source.IP]
	if !ok || now.Sub(st.lastSeen) > StoryWindow {
		st = &storylineState{
			firstSeen: now,
			stageSeen: map[string]bool{},
			ruleHits:  map[string]int{},
			techniques: map[string]bool{},
			destPorts: map[int]bool{},
			handlers:  map[string]bool{},
		}
		c.story[ev.Source.IP] = st
	}
	st.lastSeen = now
	st.hitCount++
	for _, t := range ev.MitreTactics {
		if !st.stageSeen[t] {
			st.stageSeen[t] = true
			st.stages = append(st.stages, t)
		}
	}
	for _, tech := range ev.MitreTechniques {
		st.techniques[tech] = true
	}
	st.ruleHits[ev.RuleID]++
	if ev.Dest.Port > 0 {
		st.destPorts[ev.Dest.Port] = true
	}
	if ev.Handler != "" {
		st.handlers[ev.Handler] = true
	}

	if len(st.stages) < StoryMinStages {
		return nil
	}
	// Only re-emit when we've gained StoryReEmitEvery new stages
	// since the last emission. First emission fires at == StoryMinStages.
	if st.lastEmittedSize > 0 && len(st.stages)-st.lastEmittedSize < StoryReEmitEvery {
		return nil
	}
	st.lastEmittedSize = len(st.stages)

	techniques := setToSortedSlice(st.techniques)
	ports := setToSortedIntSlice(st.destPorts)
	handlers := setToSortedSlice(st.handlers)
	ordered := orderTacticsByRank(st.stages)

	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "storyline:multi_stage",
		Severity: event.SeverityHigh,
		Source:   ev.Source,
		Proto:    "tcp",
		MitreTechniques: techniques,
		MitreTactics:    ordered,
		Meta: map[string]any{
			"stages":        ordered,
			"chain":         joinStages(ordered),
			"hit_count":     st.hitCount,
			"dest_ports":    ports,
			"handlers":      handlers,
			"first_seen_s":  int(now.Sub(st.firstSeen).Seconds()),
			"distinct_rules": len(st.ruleHits),
		},
	}
}

// orderTacticsByRank sorts tactic names by their position in the
// reconnaissance-to-impact ordering from mitre.Tactics().
func orderTacticsByRank(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		ri := mitre.TacticRank(out[i])
		rj := mitre.TacticRank(out[j])
		if ri < 0 {
			return false
		}
		if rj < 0 {
			return true
		}
		return ri < rj
	})
	return out
}

func joinStages(stages []string) string {
	if len(stages) == 0 {
		return ""
	}
	out := stages[0]
	for i := 1; i < len(stages); i++ {
		out += " -> " + stages[i]
	}
	return out
}

func setToSortedSlice(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func setToSortedIntSlice(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
