package ui

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/mitre"
)

// ATT&CK mapping view. The store doesn't persist the per-event technique
// list as columns, so we recompute it exactly as the live router does —
// mitre.Lookup(rule_id, handler) refined by mitre.Augment over the event's
// anomaly markers — and aggregate technique / tactic counts across a window.
// The result is a tactic timeline (kill-chain-ordered) + a technique heatmap
// + the recent multi-stage storyline chains.

const attackWindow = 24 * time.Hour // default window for the technique drilldown
const attackScanMax = 20000         // events scanned per render

type attackView struct {
	Since       time.Time
	RangeKey    string
	RangeLabel  string
	RangeLinks  []rangeLink
	Events      int         // events that carried at least one technique
	Tactics     []tacticRow // kill-chain order, with their techniques nested
	TopTech     []barRow    // top techniques overall (the heatmap rows)
	Chains      []chainRow  // recent storyline:multi_stage progressions
	DistinctTID int         // distinct techniques seen
	Matrix      []matrixCol // native ATT&CK matrix (tactic columns × technique cells)
	Punchcard   chartFig    // activity heatmap (day-of-week × hour-of-day)
}

// matrixCol is one tactic column of the native ATT&CK matrix.
type matrixCol struct {
	Tactic string
	Count  int
	Rank   int
	Cells  []matrixCell
}

// matrixCell is one technique within a tactic column, shaded by observed volume.
type matrixCell struct {
	ID    string
	Count int
	Level int // 0-4 shading bucket (CSS class m-lN)
}

type tacticRow struct {
	Tactic     string
	Count      int
	Pct        int
	Rank       int
	Techniques []barRow
}

type chainRow struct {
	Time     time.Time
	Source   string
	Chain    string
	Playbook string // named attack pattern (storyline meta.playbook), if recognized
}

// eventTag recomputes the ATT&CK Tag for a stored event exactly as the live
// router does: handler/rule base lookup refined by the event's anomaly
// markers. The store doesn't persist the technique list, so views that need
// it recompute from rule_id + handler + meta.anomalies.
func eventTag(ev *event.Event) mitre.Tag {
	return mitre.Augment(mitre.Lookup(ev.RuleID, ev.Handler), metaStrings(ev.Meta, "anomalies"))
}

// buildAttackView aggregates ATT&CK techniques + tactics across the events.
func buildAttackView(since time.Time, evs []*event.Event) attackView {
	v := attackView{Since: since}
	techCount := map[string]int{}
	tacCount := map[string]int{}
	tacTech := map[string]map[string]int{} // tactic -> technique -> count

	for _, ev := range evs {
		// Storyline aggregates carry their chain in meta (no technique tag of
		// their own), so capture them before the technique guard.
		if ev.RuleID == "storyline:multi_stage" {
			if chain, ok := ev.Meta["chain"].(string); ok && chain != "" {
				pb, _ := ev.Meta["playbook"].(string)
				v.Chains = append(v.Chains, chainRow{Time: ev.Time, Source: ev.Source.IP, Chain: chain, Playbook: pb})
			}
		}
		tag := eventTag(ev)
		if len(tag.Techniques) == 0 && len(tag.Tactics) == 0 {
			continue
		}
		v.Events++
		for _, tac := range tag.Tactics {
			tacCount[tac]++
			if tacTech[tac] == nil {
				tacTech[tac] = map[string]int{}
			}
		}
		for _, t := range tag.Techniques {
			techCount[t]++
			// Attribute the technique to each of the event's tactics.
			for _, tac := range tag.Tactics {
				tacTech[tac][t]++
			}
		}
	}

	v.DistinctTID = len(techCount)
	v.TopTech = topBars(techCount, 25, "/attack/technique?id=")

	// Tactic timeline, ordered along the reconnaissance→impact kill chain.
	maxTac := 0
	for _, c := range tacCount {
		if c > maxTac {
			maxTac = c
		}
	}
	for rank, tac := range mitre.Tactics() {
		c := tacCount[tac]
		if c == 0 {
			continue
		}
		row := tacticRow{Tactic: tac, Count: c, Pct: pct(c, maxTac), Rank: rank + 1}
		row.Techniques = topBars(tacTech[tac], 12, "/attack/technique?id=")
		v.Tactics = append(v.Tactics, row)
	}

	// Native ATT&CK matrix: a column per observed tactic (kill-chain order),
	// each holding its techniques shaded by observed volume relative to the
	// busiest technique anywhere in the window.
	maxTech := 0
	for _, c := range techCount {
		if c > maxTech {
			maxTech = c
		}
	}
	for rank, tac := range mitre.Tactics() {
		tt := tacTech[tac]
		if len(tt) == 0 {
			continue
		}
		col := matrixCol{Tactic: tac, Count: tacCount[tac], Rank: rank + 1}
		type kv struct {
			id string
			n  int
		}
		items := make([]kv, 0, len(tt))
		for id, n := range tt {
			items = append(items, kv{id, n})
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].n != items[j].n {
				return items[i].n > items[j].n
			}
			return items[i].id < items[j].id
		})
		for _, it := range items {
			col.Cells = append(col.Cells, matrixCell{ID: it.id, Count: it.n, Level: shadeLevel(it.n, maxTech)})
		}
		v.Matrix = append(v.Matrix, col)
	}

	// Most recent storyline chains first, capped.
	sort.Slice(v.Chains, func(i, j int) bool { return v.Chains[i].Time.After(v.Chains[j].Time) })
	if len(v.Chains) > 20 {
		v.Chains = v.Chains[:20]
	}
	return v
}

// shadeLevel buckets a count into a 0-4 intensity band for matrix cell shading.
func shadeLevel(n, max int) int {
	if max <= 0 || n <= 0 {
		return 0
	}
	l := (n*5 - 1) / max // 1..5 -> map to 0..4
	if l > 4 {
		l = 4
	}
	return l
}

// punchDays labels the rows of the activity punchcard (UTC weekdays).
var punchDays = []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

// buildPunchcard tallies events into a 7×24 day-of-week × hour-of-day grid and
// returns a heatmap figure ("when do they attack" — reveals working hours and
// timezone of the operators).
func buildPunchcard(evs []*event.Event) chartFig {
	cells := make([][]int, 7)
	for i := range cells {
		cells[i] = make([]int, 24)
	}
	max := 0
	for _, ev := range evs {
		t := ev.Time.UTC()
		// Go: Sunday=0..Saturday=6; remap to Monday-first rows.
		row := (int(t.Weekday()) + 6) % 7
		col := t.Hour()
		cells[row][col]++
		if cells[row][col] > max {
			max = cells[row][col]
		}
	}
	hours := make([]string, 24)
	for h := 0; h < 24; h++ {
		hours[h] = itoa2(h)
	}
	return chartFigure("heatmap", "Activity punchcard (UTC weekday × hour)", map[string]any{
		"rows": punchDays, "cols": hours, "cells": cells, "max": max, "unit": "events",
	})
}

// itoa2 formats 0-23 as a 2-char hour label.
func itoa2(h int) string {
	if h < 10 {
		return "0" + string(rune('0'+h))
	}
	return string(rune('0'+h/10)) + string(rune('0'+h%10))
}

func (s *Server) handleAttack(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	dur, rkey, rlabel, rlinks := pageRange(r, "/attack")
	since := time.Now().Add(-dur)
	evs, err := s.windowEvents(ctx, dur, s.scanCap(attackScanMax))
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	v := buildAttackView(since, evs)
	v.RangeKey, v.RangeLabel, v.RangeLinks = rkey, rlabel, rlinks
	// Punchcard over the same selected window (pick 7d+ for a meaningful grid).
	v.Punchcard = buildPunchcard(evs)
	// The ATT&CK page keeps its technique labels pointing at the in-honeypot
	// drill-down (/attack/technique?id=…) — which shows the sources, rules and
	// events behind each technique — rather than out-linking to attack.mitre.org.
	// (External MITRE links remain on the event-detail / profile chips, gated by
	// ui.attack_links.)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "attack", v); err != nil {
		slog.Warn("ui: render attack", "err", err)
	}
}

// techniqueView is the drill-down for one ATT&CK technique: what it means,
// which tactics it falls under here, the rules/handlers that triggered it,
// and the source IPs responsible (with event counts).
type techniqueView struct {
	ID          string
	Description string
	Since       time.Time
	Events      int
	Tactics     []string
	Sources     []barRow // source IP -> events carrying this technique
	Rules       []barRow // rule_id -> count
}

// buildTechniqueView scans events for those whose recomputed ATT&CK tag
// includes tid and aggregates the sources / rules / tactics behind it.
func buildTechniqueView(tid string, since time.Time, evs []*event.Event) techniqueView {
	v := techniqueView{ID: tid, Description: mitre.Describe(tid), Since: since}
	srcCount := map[string]int{}
	ruleCount := map[string]int{}
	tacSet := map[string]struct{}{}
	for _, ev := range evs {
		tag := eventTag(ev)
		if !containsStr(tag.Techniques, tid) {
			continue
		}
		v.Events++
		if ev.Source.IP != "" {
			srcCount[ev.Source.IP]++
		}
		if ev.RuleID != "" {
			ruleCount[ev.RuleID]++
		}
		for _, t := range tag.Tactics {
			tacSet[t] = struct{}{}
		}
	}
	for t := range tacSet {
		v.Tactics = append(v.Tactics, t)
	}
	sort.Strings(v.Tactics)
	v.Sources = topBars(srcCount, 50, "/profiles/")
	v.Rules = topBars(ruleCount, 25, "")
	return v
}

// containsStr reports whether xs contains s.
func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// validTechniqueID guards the id query param: T followed by digits, with an
// optional .NNN sub-technique. Keeps the drill-down to well-formed IDs.
func validTechniqueID(s string) bool {
	if len(s) < 4 || len(s) > 12 || s[0] != 'T' {
		return false
	}
	dot := false
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '.' && !dot && i > 1 {
			dot = true
			continue
		}
		return false
	}
	return true
}

func (s *Server) handleAttackTechnique(w http.ResponseWriter, r *http.Request) {
	tid := strings.TrimSpace(r.URL.Query().Get("id"))
	if !validTechniqueID(tid) {
		http.Error(w, "invalid technique id", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	since := time.Now().Add(-attackWindow)
	evs, err := s.windowEvents(ctx, attackWindow, s.scanCap(attackScanMax))
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "technique", buildTechniqueView(tid, since, evs)); err != nil {
		slog.Warn("ui: render technique", "err", err)
	}
}

func (s *Server) handleAPIAttack(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	since := time.Now().Add(-attackWindow)
	evs, err := s.windowEvents(ctx, attackWindow, s.scanCap(attackScanMax))
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	writeJSON(w, buildAttackView(since, evs))
}

// handleNavigator serves a MITRE ATT&CK Navigator layer scored by the
// techniques observed in the configured window — drop the JSON into
// https://mitre-attack.github.io/attack-navigator/ for an observed-technique
// heatmap. ?static=1 returns the static-coverage layer instead.
func (s *Server) handleNavigator(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("static") == "1" {
		writeJSON(w, mitre.Navigator(nil))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	evs, err := s.windowEvents(ctx, attackWindow, s.scanCap(attackScanMax))
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	counts := map[string]int{}
	for _, ev := range evs {
		for _, t := range ev.MitreTechniques {
			counts[t]++
		}
	}
	w.Header().Set("Content-Disposition", `attachment; filename="navigator-observed.json"`)
	writeJSON(w, mitre.Navigator(counts))
}
