package ui

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/mitre"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// Attack timeline: per-source chronological event sequences, so an analyst
// sees how each attacker progressed (recon → creds → lateral → impact)
// instead of a flat firehose. Sources are ranked by event volume; each
// source's events are time-ordered with their severity + ATT&CK tactics.

const timelineWindow = 24 * time.Hour
const timelineScanMax = 20000
const timelineMaxSources = 25
const timelineMaxPerSource = 40

type timelineView struct {
	Since   time.Time
	Total   int
	Sources []sourceTimeline
}

type sourceTimeline struct {
	Source    string
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
	MaxSev    string
	Tactics   []string // distinct tactics this source touched, kill-chain order
	Events    []timelineEvent
	Truncated int             // events not shown (Count - len(Events))
	tacticSet map[string]bool // working set, resolved into Tactics
}

type timelineEvent struct {
	Time     time.Time
	RuleID   string
	Handler  string
	Severity string
	Port     int
	Tactics  []string
}

func buildTimelineView(since time.Time, evs []*event.Event) timelineView {
	v := timelineView{Since: since, Total: len(evs)}
	bySrc := map[string]*sourceTimeline{}
	order := []string{} // first-seen order of source keys

	for _, ev := range evs {
		ip := ev.Source.IP
		if ip == "" {
			continue
		}
		st := bySrc[ip]
		if st == nil {
			st = &sourceTimeline{Source: ip, FirstSeen: ev.Time, LastSeen: ev.Time}
			bySrc[ip] = st
			order = append(order, ip)
		}
		st.Count++
		if ev.Time.Before(st.FirstSeen) {
			st.FirstSeen = ev.Time
		}
		if ev.Time.After(st.LastSeen) {
			st.LastSeen = ev.Time
		}
		sev := ev.Severity.String()
		if sevRank(sev) > sevRank(st.MaxSev) {
			st.MaxSev = sev
		}
		tac := eventTag(ev).Tactics
		if len(st.Events) < timelineMaxPerSource {
			st.Events = append(st.Events, timelineEvent{
				Time: ev.Time, RuleID: ev.RuleID, Handler: ev.Handler,
				Severity: sev, Port: ev.Dest.Port, Tactics: tac,
			})
		}
		for _, t := range tac {
			st.addTactic(t)
		}
	}

	for _, ip := range order {
		st := bySrc[ip]
		sort.Slice(st.Events, func(i, j int) bool { return st.Events[i].Time.Before(st.Events[j].Time) })
		st.Tactics = orderTactics(st.tacticSet)
		st.Truncated = st.Count - len(st.Events)
		v.Sources = append(v.Sources, *st)
	}
	// Rank sources by volume, then most-recent.
	sort.Slice(v.Sources, func(i, j int) bool {
		if v.Sources[i].Count != v.Sources[j].Count {
			return v.Sources[i].Count > v.Sources[j].Count
		}
		return v.Sources[i].LastSeen.After(v.Sources[j].LastSeen)
	})
	if len(v.Sources) > timelineMaxSources {
		v.Sources = v.Sources[:timelineMaxSources]
	}
	return v
}

func (s *sourceTimeline) addTactic(t string) {
	if s.tacticSet == nil {
		s.tacticSet = map[string]bool{}
	}
	s.tacticSet[t] = true
}

// sevRank orders severity strings for "max severity" comparisons.
func sevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// orderTactics returns the present tactics in reconnaissance→impact order.
func orderTactics(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	var out []string
	for _, t := range mitre.Tactics() {
		if set[t] {
			out = append(out, t)
		}
	}
	return out
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	since := time.Now().Add(-timelineWindow)
	evs, err := s.store.Query(ctx, store.Filter{Since: since, Limit: timelineScanMax})
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "timeline", buildTimelineView(since, evs)); err != nil {
		slog.Warn("ui: render timeline", "err", err)
	}
}
