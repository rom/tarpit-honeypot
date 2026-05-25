package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// fleetFinding is one fleet:* alert rendered for the panel.
type fleetFinding struct {
	Time     time.Time
	Severity event.Severity
	Rule     string // the detector (rule_id minus the "fleet:" prefix)
	Summary  string // compact, per-detector meta summary
	ID       string
}

type fleetPage struct {
	Counts   []barRow // per-detector breakdown (bars; each links to filtered events)
	Timeline []barRow // findings-over-time (bucketed bars)
	Findings []fleetFinding
	Total    int
	SinceStr string
}

// handleFleet renders the cross-sensor (fleet:*) findings panel: a per-detector
// breakdown bar chart (each bar links to the filtered event log), a
// findings-over-time chart, and the recent findings with a compact summary.
func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) {
	since := fleetSince(r)
	evs, err := s.fleetEvents(r)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	counts := map[string]int{}
	findings := make([]fleetFinding, 0, len(evs))
	for _, ev := range evs {
		rule := strings.TrimPrefix(ev.RuleID, "fleet:")
		counts[rule]++
		findings = append(findings, fleetFinding{
			Time: ev.Time, Severity: ev.Severity, Rule: rule,
			Summary: fleetSummary(ev), ID: ev.ID,
		})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "fleet", fleetPage{
		Counts:   detectorBars(counts),
		Timeline: fleetTimeline(findings, since, time.Now().UTC()),
		Findings: findings, Total: len(findings),
		SinceStr: r.URL.Query().Get("since"),
	}); err != nil {
		slog.Warn("ui: render fleet", "err", err)
	}
}

// detectorBars turns the per-detector counts into bar rows (sorted desc), each
// linking to the filtered event log for that exact rule.
func detectorBars(counts map[string]int) []barRow {
	max := 0
	for _, v := range counts {
		if v > max {
			max = v
		}
	}
	rows := make([]barRow, 0, len(counts))
	for rule, c := range counts {
		ruleID := "fleet:" + rule
		pct := 0
		if max > 0 {
			pct = c * 100 / max
		}
		rows = append(rows, barRow{
			Label: ruleID, Count: c, Pct: pct,
			Href: "/events?rule=" + url.QueryEscape(ruleID),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Label < rows[j].Label
	})
	return rows
}

// fleetTimeline buckets findings across the window into ~24 bars.
func fleetTimeline(findings []fleetFinding, since time.Duration, now time.Time) []barRow {
	if len(findings) == 0 || since <= 0 {
		return nil
	}
	const buckets = 24
	bucketDur := since / buckets
	if bucketDur < time.Minute {
		bucketDur = time.Minute
	}
	n := int(since/bucketDur) + 1
	start := now.Add(-since)
	counts := make([]int, n)
	max := 0
	for _, f := range findings {
		idx := int(f.Time.Sub(start) / bucketDur)
		if idx < 0 {
			idx = 0
		}
		if idx >= n {
			idx = n - 1
		}
		counts[idx]++
		if counts[idx] > max {
			max = counts[idx]
		}
	}
	layout := "15:04"
	if since > 48*time.Hour {
		layout = "01-02 15h"
	}
	rows := make([]barRow, 0, n)
	for i, c := range counts {
		pct := 0
		if max > 0 {
			pct = c * 100 / max
		}
		rows = append(rows, barRow{
			Label: start.Add(time.Duration(i) * bucketDur).UTC().Format(layout),
			Count: c, Pct: pct,
		})
	}
	return rows
}

// handleAPIFleet returns the window's fleet:* events as JSON.
func (s *Server) handleAPIFleet(w http.ResponseWriter, r *http.Request) {
	evs, err := s.fleetEvents(r)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(evs)
}

// fleetSince parses the ?since= window (default 24h).
func fleetSince(r *http.Request) time.Duration {
	since := 24 * time.Hour
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = d
		}
	}
	return since
}

// fleetEvents queries the window and keeps only fleet:* findings (newest first).
func (s *Server) fleetEvents(r *http.Request) ([]*event.Event, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	evs, err := s.store.Query(ctx, store.Filter{Since: time.Now().Add(-fleetSince(r)), Limit: 2000})
	if err != nil {
		return nil, err
	}
	out := make([]*event.Event, 0, 64)
	for _, ev := range evs {
		if strings.HasPrefix(ev.RuleID, "fleet:") {
			out = append(out, ev)
		}
	}
	return out, nil
}

// fleetSummary builds a one-line, per-detector summary from an event's meta: the
// primary identity (the first present of a priority list), the port, the breadth
// counts, and the broad/targeted scope.
func fleetSummary(ev *event.Event) string {
	if ev.Meta == nil {
		return ""
	}
	var parts []string
	for _, k := range []string{
		"source", "asn", "asn_org", "fingerprint", "cve", "technique", "tool",
		"url", "user_agent", "subnet", "token", "identity", "username", "sensor",
	} {
		if v, ok := ev.Meta[k].(string); ok && v != "" {
			parts = append(parts, k+"="+truncStr(v, 64))
			break
		}
	}
	if v, ok := ev.Meta["port"]; ok {
		parts = append(parts, "port="+numFmt(v))
	}
	for _, k := range []string{
		"sensor_count", "source_count", "asn_count", "country_count",
		"password_count", "handler_count", "active_buckets",
	} {
		if v, ok := ev.Meta[k]; ok {
			parts = append(parts, k+"="+numFmt(v))
		}
	}
	if v, ok := ev.Meta["scope"].(string); ok && v != "" {
		parts = append(parts, v)
	}
	return strings.Join(parts, " · ")
}

// numFmt renders a meta number (float64 after the store's JSON round-trip, or a
// native int) without a trailing ".0".
func numFmt(v any) string {
	switch n := v.(type) {
	case float64:
		if n == float64(int64(n)) {
			return fmt.Sprintf("%d", int64(n))
		}
		return fmt.Sprintf("%g", n)
	case int:
		return fmt.Sprintf("%d", n)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
