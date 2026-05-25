package fleet

import (
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// --- fleet:honeytoken-spread -----------------------------------------------
//
// The SAME canary token tripped on several distinct sensors. The in-sensor
// honeytoken_spread keys on sources hitting one sensor's token; this keys on the
// token reaching the FLEET — the planted token has leaked and is propagating, so
// the blast radius is now several honeypots. Never background noise.
func (c *Correlator) observeHoneytokenLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	if !strings.HasPrefix(ev.RuleID, "canary:") {
		return nil
	}
	a := touch(c.tokens, ev.RuleID, sid, ev.Source.IP, now)
	if a.fired || len(a.sensors) < c.cfg.HoneytokenSensors {
		return nil
	}
	a.fired = true
	return c.event("fleet:honeytoken-spread", event.SeverityCritical, ev.Source, map[string]any{
		"token": ev.RuleID, "sensor_count": len(a.sensors), "source_count": len(a.sources),
		"sensors": c.list(a.sensors), "sources": c.list(a.sources),
	})
}

// --- fleet:cve-emergence ---------------------------------------------------
//
// A CVE never seen anywhere in the fleet within the novelty horizon, suddenly
// exploited against several sensors — an n-day going live fleet-wide (the first
// wave of a freshly-weaponised vulnerability). Distinct from cve-wave, which
// fires for any CVE crossing the breadth threshold (new or long-known).
func (c *Correlator) observeCVEEmergenceLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	if !strings.HasPrefix(ev.RuleID, "cve:") {
		return nil
	}
	cve := strings.TrimPrefix(ev.RuleID, "cve:")
	if cve == "" {
		return nil
	}
	e := c.seenCVE[cve]
	if e == nil {
		e = &seenEntry{first: now, sensors: map[string]struct{}{}}
		c.seenCVE[cve] = e
	}
	e.last = now
	if now.Sub(e.first) > c.cfg.Window { // established, not novel
		return nil
	}
	e.sensors[sid] = struct{}{}
	if e.fired || len(e.sensors) < c.cfg.CVEEmergenceSensors {
		return nil
	}
	e.fired = true
	return c.event("fleet:cve-emergence", event.SeverityCritical, ev.Source, map[string]any{
		"cve": cve, "sensor_count": len(e.sensors), "sensors": c.list(e.sensors),
		"first_seen": e.first.UTC().Format(time.RFC3339),
	})
}

// --- fleet:cross-protocol-actor --------------------------------------------
//
// One source touching many DISTINCT services across the fleet — fleet-wide
// service enumeration by a single actor. The in-sensor service_sweep sees one
// node's services; the aggregator sees the breadth across nodes (the actor that
// probes ssh on A, redis on B, modbus on C is mapping the whole estate).
func (c *Correlator) observeCrossProtoLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	if ev.Handler == "" {
		return nil
	}
	a := touch(c.crossProto, ev.Source.IP, sid, "", now)
	if a.extra == nil {
		a.extra = map[string]struct{}{}
	}
	if len(a.extra) < corrSetCap {
		a.extra[ev.Handler] = struct{}{}
	}
	if a.fired || len(a.extra) < c.cfg.CrossProtoHandlers || len(a.sensors) < c.cfg.CrossProtoSensors {
		return nil
	}
	a.fired = true
	return c.event("fleet:cross-protocol-actor", event.SeverityHigh, ev.Source, map[string]any{
		"source": ev.Source.IP, "handler_count": len(a.extra), "handlers": c.list(a.extra),
		"sensor_count": len(a.sensors), "sensors": c.list(a.sensors),
	})
}

// --- fleet:fingerprint-asn-spread ------------------------------------------
//
// One TLS/SSH fingerprint operated from many DISTINCT ASNs across the fleet: a
// toolkit run from networks all over the internet. Complements fingerprint-
// shared (distinct source IPs) and geo-distributed-actor (distinct countries)
// on the network-of-origin axis — strong evidence of a botnet / managed tool.
func (c *Correlator) observeFPASNLocked(ev *event.Event, sid string, now time.Time) []*event.Event {
	asn := metaStr(ev, "asn")
	if asn == "" {
		return nil
	}
	var out []*event.Event
	for _, kind := range []string{"ja3", "ja4", "hassh"} {
		v := metaStr(ev, kind)
		if v == "" {
			continue
		}
		a := touch(c.fpASN, kind+":"+v, sid, ev.Source.IP, now)
		if a.extra == nil {
			a.extra = map[string]struct{}{}
		}
		if len(a.extra) < corrSetCap {
			a.extra[asn] = struct{}{}
		}
		if a.fired || len(a.extra) < c.cfg.FPASNs || len(a.sensors) < c.cfg.FPASNSensors {
			continue
		}
		a.fired = true
		out = append(out, c.event("fleet:fingerprint-asn-spread", event.SeverityHigh, ev.Source, map[string]any{
			"fingerprint": kind + ":" + v, "asn_count": len(a.extra), "asns": c.list(a.extra),
			"source_count": len(a.sources), "sensor_count": len(a.sensors),
		}))
	}
	return out
}

// corrSetCap bounds a per-actor dimension set under a flood.
const corrSetCap = 256
