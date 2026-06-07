package correlate

import (
	"sort"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Cross-target correlation: on a host serving several decoy IPs (multiple
// addresses on an interface, or several per-IP honeypot instances feeding one
// store), the interesting signal is one SOURCE reaching across MULTIPLE target
// IPs. host_sweep already counts distinct targets; cross_target adds the
// dimensions an analyst actually asks about:
//
//   - which targets a source touched, in the ORDER it reached them;
//   - the TIMING (first-touch offset of each target from the first);
//   - the PORTS hit per target, and which ports were hit on MORE THAN ONE
//     target (port-correlation across machines — the same service swept across
//     the fleet, a strong "scripted multi-host campaign" tell).

// targetHit accumulates what a source did to one target IP within the window.
type targetHit struct {
	first time.Time
	hits  int
	ports map[int]struct{}
}

// targetSeqState is the per-source cross-target accumulator.
type targetSeqState struct {
	since time.Time
	order []string // target IPs in first-seen order
	info  map[string]*targetHit
}

func windowedTargets(m map[string]*targetSeqState, key string, now time.Time, window time.Duration) *targetSeqState {
	st, ok := m[key]
	if !ok || now.Sub(st.since) > window {
		st = &targetSeqState{since: now, info: map[string]*targetHit{}}
		m[key] = st
	}
	return st
}

// checkCrossTarget records the (source -> target, port, time) tuple and fires
// once a source has reached DistinctTargets distinct target IPs in the window.
func (c *Correlator) checkCrossTarget(ev *event.Event, now time.Time) *event.Event {
	dst := ev.Dest.IP
	if dst == "" {
		if m, ok := ev.Meta["target_ip"].(string); ok {
			dst = m
		}
	}
	if dst == "" || ev.Source.IP == "" {
		return nil
	}
	cfg := c.cfg.CrossTarget
	st := windowedTargets(c.crossTarget, ev.Source.IP, now, cfg.Window)

	hit := st.info[dst]
	if hit == nil {
		if len(st.order) >= corrSetCap {
			return nil // bound memory on a pathological fan-out
		}
		hit = &targetHit{first: now, ports: map[int]struct{}{}}
		st.info[dst] = hit
		st.order = append(st.order, dst)
	}
	hit.hits++
	if ev.Dest.Port > 0 && len(hit.ports) < corrSetCap {
		hit.ports[ev.Dest.Port] = struct{}{}
	}

	if len(st.order) < cfg.DistinctTargets {
		return nil
	}
	if !c.shouldEmit("crosstarget|"+ev.Source.IP, cfg.Window) {
		return nil
	}

	// Timeline (ordered) + per-target ports + cross-target shared ports.
	base := st.info[st.order[0]].first
	timeline := make([]map[string]any, 0, len(st.order))
	portTargets := map[int]int{} // port -> distinct targets that saw it
	for _, ip := range st.order {
		h := st.info[ip]
		ports := sortedPorts(h.ports)
		for _, p := range ports {
			portTargets[p]++
		}
		timeline = append(timeline, map[string]any{
			"target":         ip,
			"first_offset_s": int(h.first.Sub(base).Seconds()),
			"hits":           h.hits,
			"ports":          ports,
		})
	}
	shared := make([]int, 0)
	for p, n := range portTargets {
		if n >= 2 {
			shared = append(shared, p)
		}
	}
	sort.Ints(shared)

	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:cross_target",
		Severity: c.crossTargetSev,
		Source:   ev.Source,
		Proto:    ev.Proto,
		Meta: map[string]any{
			"distinct_targets": len(st.order),
			"targets":          append([]string(nil), st.order...), // first-seen order
			"target_timeline":  timeline,                           // order + timing + per-target ports
			"shared_ports":     shared,                             // ports hit on >=2 targets
			"window_s":         int(cfg.Window.Seconds()),
		},
	}
}

func sortedPorts(m map[int]struct{}) []int {
	out := make([]int, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
