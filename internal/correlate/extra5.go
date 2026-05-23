package correlate

import (
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Round-three correlators: data-destruction escalation, leaked-honeytoken
// spread, and attack-tool rotation.

// destructiveMarkers are the handler anomaly markers that represent an actual
// data-destruction / wipe operation (as opposed to recon or a write). One
// source performing several is a hands-on-keyboard impact action.
var destructiveMarkers = map[string]bool{
	"redis-flush":               true,
	"memcached-flush":           true,
	"printer-filesystem-format": true,
	"ftp-delete-attempt":        true,
}

// toolMarkers are the client-classifier anomaly markers that name a recognized
// scanning / attack tool. Counting DISTINCT ones per source (plus any "tool:"
// fingerprint) measures how much tooling an adversary is cycling through —
// the tool analogue of ua_rotation.
var toolMarkers = map[string]bool{
	"vulnerability-scanner": true,
	"c2-framework":          true,
	"headless-browser":      true,
	"automation-client":     true,
}

// checkDestructiveAction counts data-destruction operations from one source;
// crossing the threshold within the window is an active impact action that
// should escalate immediately.
func (c *Correlator) checkDestructiveAction(ev *event.Event, now time.Time) *event.Event {
	hit := false
	for _, a := range ev.Anomalies {
		if destructiveMarkers[a] {
			hit = true
			break
		}
	}
	if !hit {
		return nil
	}
	cfg := c.cfg.DestructiveAction
	st := windowedCount(c.destruct, ev.Source.IP, now, cfg.Window)
	st.count++
	if st.count < cfg.Events {
		return nil
	}
	if !c.shouldEmit("destruct|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:destructive_action", Severity: c.destructSev,
		Source: ev.Source, Proto: ev.Proto,
		Meta: map[string]any{
			"events":   st.count,
			"window_s": int(cfg.Window.Seconds()),
		},
	}
}

// checkHoneytokenSpread tracks the distinct source IPs that trip the SAME
// canary token; many sources on one token within the window means the planted
// credential / URL / file has leaked and is being used broadly.
func (c *Correlator) checkHoneytokenSpread(ev *event.Event, now time.Time) *event.Event {
	if !strings.HasPrefix(ev.RuleID, "canary:") {
		return nil
	}
	token := strings.TrimPrefix(ev.RuleID, "canary:")
	cfg := c.cfg.HoneytokenSpread
	st, ok := c.honeytoken[token]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &reuseState{since: now, sources: map[string]struct{}{}}
		c.honeytoken[token] = st
	}
	if len(st.sources) < corrSetCap {
		st.sources[ev.Source.IP] = struct{}{}
	}
	if len(st.sources) < cfg.DistinctSources {
		return nil
	}
	if !c.shouldEmit("honeytoken|"+token, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:honeytoken_spread", Severity: c.honeytokenSev,
		Source: ev.Source, Proto: ev.Proto,
		Meta: map[string]any{
			"token":            token,
			"distinct_sources": len(st.sources),
			"sources":          setKeys(st.sources),
			"window_s":         int(cfg.Window.Seconds()),
		},
	}
}

// checkToolRotation tracks the distinct attack tools one source has been
// identified running; reaching the threshold within the window is a
// determined adversary cycling tooling against the sensor.
func (c *Correlator) checkToolRotation(ev *event.Event, now time.Time) *event.Event {
	var found []string
	for _, a := range ev.Anomalies {
		if toolMarkers[a] || strings.HasPrefix(a, "tool:") {
			found = append(found, a)
		}
	}
	if len(found) == 0 {
		return nil
	}
	cfg := c.cfg.ToolRotation
	st := windowedSet(c.toolRot, ev.Source.IP, now, cfg.Window)
	for _, a := range found {
		if len(st.set) < corrSetCap {
			st.set[a] = struct{}{}
		}
	}
	if len(st.set) < cfg.DistinctTools {
		return nil
	}
	if !c.shouldEmit("toolrot|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:tool_rotation", Severity: c.toolRotSev,
		Source: ev.Source, Proto: ev.Proto,
		Meta: map[string]any{
			"distinct_tools": len(st.set),
			"tools":          setKeys(st.set),
			"window_s":       int(cfg.Window.Seconds()),
		},
	}
}
