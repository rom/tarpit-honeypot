package correlate

import (
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// This file holds the enrichment-driven correlators: they key on metadata
// the enrichment layer (internal/enrich) stamps onto events — threat-intel
// list / Tor membership and GeoIP country — rather than on raw packet shape.

// flaggedBadSource reports whether enrichment tagged the event's source as
// known-bad infrastructure (a threat-intel list member or a Tor exit node).
func flaggedBadSource(ev *event.Event) bool {
	if ev.Meta == nil {
		return false
	}
	return ev.Meta["threat_intel_hit"] == true || ev.Meta["tor_exit"] == true
}

// checkThreatIntelBurst counts events from a flagged source and fires once
// the count crosses the threshold within the window — sustained activity
// from known-bad infrastructure, regardless of which service it touches.
func (c *Correlator) checkThreatIntelBurst(ev *event.Event, now time.Time) *event.Event {
	if !flaggedBadSource(ev) {
		return nil
	}
	cfg := c.cfg.ThreatIntelBurst
	st := windowedCount(c.tiBurst, ev.Source.IP, now, cfg.Window)
	st.count++
	if st.count < cfg.Events {
		return nil
	}
	if !c.shouldEmit("tiburst|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	meta := map[string]any{
		"events":   st.count,
		"window_s": int(cfg.Window.Seconds()),
	}
	if labels, ok := ev.Meta["threat_intel"].([]string); ok && len(labels) > 0 {
		meta["threat_intel"] = labels
	}
	if ev.Meta["tor_exit"] == true {
		meta["tor_exit"] = true
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:threat_intel_burst",
		Severity: c.tiBurstSev,
		Source:   ev.Source,
		Proto:    ev.Proto,
		Meta:     meta,
	}
}

// checkGeoVelocity tracks the distinct GeoIP countries one credential pair
// has been tried from; reaching the threshold within the window is
// "impossible travel" / credential stuffing across geographies. The
// credential itself is never logged — only the country set.
func (c *Correlator) checkGeoVelocity(ev *event.Event, now time.Time) *event.Event {
	cred := extractCreds(ev)
	if cred == "" || cred == ":" {
		return nil
	}
	country, _ := ev.Meta["geo_country"].(string)
	if country == "" {
		return nil
	}
	cfg := c.cfg.GeoVelocity
	st := windowedSet(c.geoVel, cred, now, cfg.Window)
	if len(st.set) < corrSetCap {
		st.set[country] = struct{}{}
	}
	if len(st.set) < cfg.DistinctCountries {
		return nil
	}
	if !c.shouldEmit("geovel|"+cred, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:geo_velocity",
		Severity: c.geoVelSev,
		Source:   ev.Source,
		Proto:    ev.Proto,
		Meta: map[string]any{
			"distinct_countries": len(st.set),
			"countries":          setKeys(st.set),
			"window_s":           int(cfg.Window.Seconds()),
		},
	}
}
