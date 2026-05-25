package forward

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// rollupTopN caps each dimension's top list in a rollup summary; rollupMapCap
// bounds accumulator memory under a flood.
const (
	rollupTopN   = 25
	rollupMapCap = 50000
)

// rollup accumulates the per-window counters a "rollup" forwarder ships upward
// instead of every raw event: enough to keep the correlation keys (which
// sources / ASNs / fingerprints / rules were active, and how much) at a small
// fraction of the volume.
type rollup struct {
	total       int
	sources     map[string]int
	asns        map[string]int
	fps         map[string]int
	rules       map[string]int
	sev         [5]int // indexed by event.Severity (1..4)
	first, last time.Time
}

func newRollup() *rollup {
	return &rollup{
		sources: map[string]int{}, asns: map[string]int{},
		fps: map[string]int{}, rules: map[string]int{},
	}
}

func (r *rollup) fold(ev *event.Event) {
	r.total++
	addCapped(r.sources, ev.Source.IP)
	addCapped(r.rules, ev.RuleID)
	if asn := metaString(ev, "asn"); asn != "" {
		addCapped(r.asns, asn)
	}
	for _, k := range []string{"ja3", "ja4", "hassh"} {
		if v := metaString(ev, k); v != "" {
			addCapped(r.fps, k+":"+v)
		}
	}
	if ev.Severity >= 1 && ev.Severity <= 4 {
		r.sev[ev.Severity]++
	}
	if !ev.Time.IsZero() {
		if r.first.IsZero() || ev.Time.Before(r.first) {
			r.first = ev.Time
		}
		if ev.Time.After(r.last) {
			r.last = ev.Time
		}
	}
}

func (r *rollup) maxSev() event.Severity {
	for s := 4; s >= 1; s-- {
		if r.sev[s] > 0 {
			return event.Severity(s)
		}
	}
	return event.SeverityMedium
}

func (r *rollup) sevHistogram() map[string]int {
	out := map[string]int{}
	for s := 1; s <= 4; s++ {
		if r.sev[s] > 0 {
			out[event.Severity(s).String()] = r.sev[s]
		}
	}
	return out
}

// runRollup folds incoming events into a window summary and ships one
// fleet:rollup event per RollupInterval (and a final one on shutdown).
func (f *Forwarder) runRollup(ctx context.Context) {
	ticker := time.NewTicker(f.t.RollupInterval)
	defer ticker.Stop()
	r := newRollup()
	flush := func() {
		if r.total == 0 {
			return
		}
		ev := f.buildRollupEvent(r)
		r = newRollup()
		if err := f.send(ctx, []*event.Event{ev}); err != nil {
			f.failed.Add(1)
			f.dropped.Add(1)
			slog.Warn("forward: rollup dropped after retries", "target", f.t.ID, "err", err)
			return
		}
		f.sent.Add(1)
	}
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case ev := <-f.in:
					r.fold(ev)
				default:
					flush()
					return
				}
			}
		case ev := <-f.in:
			r.fold(ev)
		case <-ticker.C:
			flush()
		}
	}
}

func (f *Forwarder) buildRollupEvent(r *rollup) *event.Event {
	meta := map[string]any{
		"node":             f.t.NodeID,
		"rollup_interval":  f.t.RollupInterval.String(),
		"total":            r.total,
		"distinct_sources": len(r.sources),
		"top_sources":      topN(r.sources, rollupTopN),
		"top_asns":         topN(r.asns, rollupTopN),
		"top_fingerprints": topN(r.fps, rollupTopN),
		"top_rules":        topN(r.rules, rollupTopN),
		"severity":         r.sevHistogram(),
	}
	if !r.first.IsZero() {
		meta["first"] = r.first.UTC().Format(time.RFC3339)
		meta["last"] = r.last.UTC().Format(time.RFC3339)
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     time.Now().UTC(),
		Sensor:   f.t.NodeID,
		SensorID: f.t.NodeID,
		RuleID:   "fleet:rollup",
		Severity: r.maxSev(),
		Meta:     meta,
	}
}

// kv is one ranked counter in a rollup top list.
type kv struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// topN returns the n highest-count entries of m, ties broken by value for a
// stable ordering.
func topN(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{Value: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// addCapped increments m[k], adding new keys only until the cap is reached so a
// flood can't grow the accumulator without bound.
func addCapped(m map[string]int, k string) {
	if k == "" {
		return
	}
	if _, ok := m[k]; ok {
		m[k]++
		return
	}
	if len(m) < rollupMapCap {
		m[k] = 1
	}
}

func metaString(ev *event.Event, key string) string {
	if ev.Meta == nil {
		return ""
	}
	s, _ := ev.Meta[key].(string)
	return s
}
