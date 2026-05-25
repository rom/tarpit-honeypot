package fleet

import (
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// --- fleet:threat-intel-surge ----------------------------------------------
//
// A surge of known-bad infrastructure converging on the fleet right now: many
// distinct sources that enrichment flagged (threat-intel list member or Tor
// exit) across many sensors within the window. The in-sensor threat_intel_burst
// keys on one source's volume; this is the fleet-wide convergence of flagged
// infra — "we're under coordinated attack from known-bad space."
func (c *Correlator) observeThreatSurgeLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	if !metaBool(ev, "threat_intel_hit") && !metaBool(ev, "tor_exit") {
		return nil
	}
	a := touch(c.surge, "", sid, ev.Source.IP, now)
	if a.fired || len(a.sources) < c.cfg.ThreatSurgeSources || len(a.sensors) < c.cfg.ThreatSurgeSensors {
		return nil
	}
	a.fired = true
	return c.event("fleet:threat-intel-surge", event.SeverityHigh, ev.Source, map[string]any{
		"source_count": len(a.sources), "sensor_count": len(a.sensors),
		"sources": c.list(a.sources), "sensors": c.list(a.sensors),
	})
}

// --- fleet:tool-campaign ---------------------------------------------------
//
// The same identified attack tool (scananalysis / fuzz tooling, recorded in
// meta "tools") wielded across many sensors from many sources — one tool /
// exploit-kit sweeping the fleet. Identity is the tool name, so it links a
// campaign even when the IPs and TLS stacks differ.
func (c *Correlator) observeToolCampaignLocked(ev *event.Event, sid string, now time.Time) []*event.Event {
	var out []*event.Event
	for _, tool := range metaStrings(ev, "tools") {
		if tool == "" {
			continue
		}
		a := touch(c.toolc, tool, sid, ev.Source.IP, now)
		if a.fired || len(a.sensors) < c.cfg.ToolSensors || len(a.sources) < c.cfg.ToolSources {
			continue
		}
		a.fired = true
		out = append(out, c.event("fleet:tool-campaign", event.SeverityHigh, ev.Source, map[string]any{
			"tool": tool, "sensor_count": len(a.sensors), "source_count": len(a.sources),
			"sensors": c.list(a.sensors), "sources": c.list(a.sources),
		}))
	}
	return out
}

// --- fleet:c2-shared -------------------------------------------------------
//
// The same harvested URL (a C2 / dropper URL pulled from payloads or shell
// command lines, recorded in meta "harvested_urls") seen at several sensors —
// shared command-and-control infrastructure behind otherwise-distinct attacks.
// A shared C2 URL is never background noise, so a low sensor threshold suffices.
func (c *Correlator) observeC2SharedLocked(ev *event.Event, sid string, now time.Time) []*event.Event {
	var out []*event.Event
	for _, url := range metaStrings(ev, "harvested_urls") {
		if url == "" {
			continue
		}
		a := touch(c.c2, url, sid, ev.Source.IP, now)
		if a.fired || len(a.sensors) < c.cfg.C2Sensors {
			continue
		}
		a.fired = true
		out = append(out, c.event("fleet:c2-shared", event.SeverityCritical, ev.Source, map[string]any{
			"url": url, "sensor_count": len(a.sensors), "source_count": len(a.sources),
			"sensors": c.list(a.sensors), "sources": c.list(a.sources),
		}))
	}
	return out
}

// --- fleet:user-agent-shared -----------------------------------------------
//
// The same HTTP User-Agent across many sensors AND many sources — a shared HTTP
// scanner / tool family. The HTTP-layer analogue of fingerprint-shared, catching
// tools that expose no (or a varying) TLS fingerprint but a fixed UA.
func (c *Correlator) observeUASharedLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	ua := metaStr(ev, "user_agent")
	if ua == "" {
		return nil
	}
	a := touch(c.uas, ua, sid, ev.Source.IP, now)
	if a.fired || len(a.sensors) < c.cfg.UASensors || len(a.sources) < c.cfg.UASources {
		return nil
	}
	a.fired = true
	return c.event("fleet:user-agent-shared", event.SeverityMedium, ev.Source, map[string]any{
		"user_agent": ua, "sensor_count": len(a.sensors), "source_count": len(a.sources),
		"sensors": c.list(a.sensors),
	})
}

// metaBool reads a boolean meta value (false when absent or non-bool).
func metaBool(ev *event.Event, key string) bool {
	if ev.Meta == nil {
		return false
	}
	b, _ := ev.Meta[key].(bool)
	return b
}
