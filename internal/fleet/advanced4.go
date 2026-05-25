package fleet

import (
	"strconv"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// --- fleet:tactic-convergence ----------------------------------------------
//
// The same MITRE ATT&CK technique surging across the fleet: many distinct
// sources exercising one technique across many sensors within the window. A
// technique-level abstraction above cve-wave / tool-campaign — it catches a
// coordinated push on a TTP (e.g. a sudden fleet-wide wave of T1190
// exploit-public-facing-application) even when the exact CVE or tool differs.
func (c *Correlator) observeTacticConvergenceLocked(ev *event.Event, sid string, now time.Time) []*event.Event {
	var out []*event.Event
	for _, tech := range ev.MitreTechniques {
		if tech == "" {
			continue
		}
		a := touch(c.tactics, tech, sid, ev.Source.IP, now)
		if a.fired || len(a.sources) < c.cfg.TacticSources || len(a.sensors) < c.cfg.TacticSensors {
			continue
		}
		a.fired = true
		out = append(out, c.event("fleet:tactic-convergence", event.SeverityHigh, ev.Source, map[string]any{
			"technique": tech, "source_count": len(a.sources), "sensor_count": len(a.sensors),
			"sources": c.list(a.sources), "sensors": c.list(a.sensors),
		}))
	}
	return out
}

// --- fleet:recidivist-network ----------------------------------------------
//
// An ASN that keeps coming back: active in many distinct time buckets ("days")
// over the long novelty horizon. Persistence, not breadth — a network that
// returns day after day is a determined adversary's infrastructure, distinct
// from a one-off scan. Keyed on ASN so the memory stays bounded.

type recidEntry struct {
	buckets map[int64]struct{}
	sensors map[string]struct{}
	last    time.Time
	fired   bool
}

func (c *Correlator) observeRecidivistLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	asn := metaStr(ev, "asn")
	if asn == "" {
		return nil
	}
	e := c.recid[asn]
	if e == nil {
		e = &recidEntry{buckets: map[int64]struct{}{}, sensors: map[string]struct{}{}}
		c.recid[asn] = e
	}
	e.last = now
	e.buckets[now.Unix()/int64(c.cfg.RecidivistBucket.Seconds())] = struct{}{}
	e.sensors[sid] = struct{}{}
	if e.fired || len(e.buckets) < c.cfg.RecidivistWindows {
		return nil
	}
	e.fired = true
	return c.event("fleet:recidivist-network", event.SeverityHigh, ev.Source, map[string]any{
		"asn": asn, "asn_org": metaStr(ev, "asn_org"),
		"active_buckets": len(e.buckets), "bucket": c.cfg.RecidivistBucket.String(),
		"sensor_count": len(e.sensors), "sensors": c.list(e.sensors),
	})
}

// --- fleet:port-campaign ---------------------------------------------------
//
// A sudden fleet-wide focus on one destination port: many distinct sources
// probing the same port across many sensors — a service-targeted campaign (e.g.
// a new IoT botnet hammering tcp/23, or a worm on a specific app port). The
// ubiquitous always-scanned ports (22/80/443 by default) are excluded so the
// signal isn't drowned by routine background scanning.
func (c *Correlator) observePortCampaignLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	port := ev.Dest.Port
	if port <= 0 || c.portExclude[port] {
		return nil
	}
	key := strconv.Itoa(port)
	a := touch(c.ports, key, sid, ev.Source.IP, now)
	if a.fired || len(a.sources) < c.cfg.PortCampaignSources || len(a.sensors) < c.cfg.PortCampaignSensors {
		return nil
	}
	a.fired = true
	return c.event("fleet:port-campaign", event.SeverityHigh, ev.Source, map[string]any{
		"port": port, "proto": ev.Proto,
		"source_count": len(a.sources), "sensor_count": len(a.sensors),
		"sources": c.list(a.sources), "sensors": c.list(a.sensors),
	})
}
