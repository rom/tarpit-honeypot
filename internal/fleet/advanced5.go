package fleet

import (
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// --- fleet:credential-spray-fleet ------------------------------------------
//
// One username attacked with many distinct passwords across the fleet — a
// distributed brute-force of a single account (e.g. "admin"), spread over
// sensors to stay under any one node's brute-force threshold. The in-sensor
// brute-force detector sees one node's attempts; the aggregator sees the
// account hammered fleet-wide.
func (c *Correlator) observeCredSprayLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	user := metaStr(ev, "username")
	if user == "" {
		user = metaStr(ev, "user")
	}
	pass := metaStr(ev, "password")
	if pass == "" {
		pass = metaStr(ev, "pass")
	}
	if user == "" || pass == "" {
		return nil
	}
	a := touch(c.credSpray, user, sid, ev.Source.IP, now)
	if a.extra == nil {
		a.extra = map[string]struct{}{}
	}
	if len(a.extra) < corrSetCap {
		a.extra[pass] = struct{}{}
	}
	if a.fired || len(a.extra) < c.cfg.CredSprayPasswords || len(a.sensors) < c.cfg.CredSpraySensors {
		return nil
	}
	a.fired = true
	return c.event("fleet:credential-spray-fleet", event.SeverityHigh, ev.Source, map[string]any{
		"username": user, "password_count": len(a.extra),
		"source_count": len(a.sources), "sensor_count": len(a.sensors),
		"sources": c.list(a.sources), "sensors": c.list(a.sensors),
	})
}

// --- fleet:asn-org-campaign ------------------------------------------------
//
// One AS-organisation (a provider) operating from several DISTINCT ASNs across
// the fleet. Big providers (cloud / hosting / bulletproof) announce many ASNs;
// asn-multi-sensor keys on the ASN number and so misses a campaign spread across
// a provider's ASNs. Keying on the org name catches it — requires >= 2 distinct
// ASNs so it never just duplicates asn-multi-sensor.
func (c *Correlator) observeAsnOrgLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	org := metaStr(ev, "asn_org")
	asn := metaStr(ev, "asn")
	if org == "" || asn == "" {
		return nil
	}
	a := touch(c.asnOrgs, org, sid, ev.Source.IP, now)
	if a.extra == nil {
		a.extra = map[string]struct{}{}
	}
	if len(a.extra) < corrSetCap {
		a.extra[asn] = struct{}{}
	}
	if a.fired || len(a.extra) < c.cfg.AsnOrgASNs || len(a.sensors) < c.cfg.AsnOrgSensors {
		return nil
	}
	a.fired = true
	return c.event("fleet:asn-org-campaign", event.SeverityHigh, ev.Source, map[string]any{
		"asn_org": org, "asn_count": len(a.extra), "asns": c.list(a.extra),
		"source_count": len(a.sources), "sensor_count": len(a.sensors),
		"sensors": c.list(a.sensors),
	})
}
