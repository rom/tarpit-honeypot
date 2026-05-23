package correlate

import (
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Round-two correlators: reflection-amplifier scouting, default-credential
// botnet sweeps, and same-CVE mass-exploit campaigns.

// amplifierServices are the UDP services whose small request -> larger
// response makes them DDoS reflectors. A source enumerating several is
// scouting reflectors for a campaign.
var amplifierServices = map[string]bool{
	"chargen": true, "ntp": true, "dns": true, "ssdp": true,
	"memcached": true, "snmp": true, "qotd": true, "daytime": true,
	"cldap": true, "ipmi": true,
}

func evHasAnomaly(ev *event.Event, want string) bool {
	for _, a := range ev.Anomalies {
		if a == want {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// checkAmplificationProbe tracks the distinct amplifier services one source
// has touched; reaching the threshold within the window is reflection-DDoS
// reconnaissance.
func (c *Correlator) checkAmplificationProbe(ev *event.Event, now time.Time) *event.Event {
	if !amplifierServices[ev.Handler] {
		return nil
	}
	cfg := c.cfg.AmplificationProbe
	st := windowedSet(c.amp, ev.Source.IP, now, cfg.Window)
	if len(st.set) < corrSetCap {
		st.set[ev.Handler] = struct{}{}
	}
	if len(st.set) < cfg.DistinctServices {
		return nil
	}
	if !c.shouldEmit("amp|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:amplification_probe", Severity: c.ampSev,
		Source: ev.Source, Proto: ev.Proto,
		Meta: map[string]any{
			"distinct_services": len(st.set),
			"services":          sortedKeys(st.set),
			"window_s":          int(cfg.Window.Seconds()),
		},
	}
}

// checkDefaultCredSweep tracks the distinct services one source tried a
// default credential against; breadth across services is an automated
// default-credential botnet (Mirai-class).
func (c *Correlator) checkDefaultCredSweep(ev *event.Event, now time.Time) *event.Event {
	if ev.Handler == "" || !evHasAnomaly(ev, "default-credential-attempt") {
		return nil
	}
	cfg := c.cfg.DefaultCredSweep
	st := windowedSet(c.defCred, ev.Source.IP, now, cfg.Window)
	if len(st.set) < corrSetCap {
		st.set[ev.Handler] = struct{}{}
	}
	if len(st.set) < cfg.DistinctServices {
		return nil
	}
	if !c.shouldEmit("defcred|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:default_cred_sweep", Severity: c.defCredSev,
		Source: ev.Source, Proto: ev.Proto,
		Meta: map[string]any{
			"distinct_services": len(st.set),
			"services":          sortedKeys(st.set),
			"window_s":          int(cfg.Window.Seconds()),
		},
	}
}

// checkCVECampaign tracks the distinct source IPs that fired the SAME CVE
// signature; many sources on one CVE within the window is a mass-exploit /
// worm campaign (the inverse of exploit_chain).
func (c *Correlator) checkCVECampaign(ev *event.Event, now time.Time) *event.Event {
	if !strings.HasPrefix(ev.RuleID, "cve:") {
		return nil
	}
	cve := strings.TrimPrefix(ev.RuleID, "cve:")
	cfg := c.cfg.CVECampaign
	st, ok := c.cveCamp[cve]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &reuseState{since: now, sources: map[string]struct{}{}}
		c.cveCamp[cve] = st
	}
	if len(st.sources) < corrSetCap {
		st.sources[ev.Source.IP] = struct{}{}
	}
	if len(st.sources) < cfg.DistinctSources {
		return nil
	}
	if !c.shouldEmit("cvecamp|"+cve, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:cve_campaign", Severity: c.cveCampSev,
		Source: ev.Source, Proto: ev.Proto,
		Meta: map[string]any{
			"cve":              cve,
			"distinct_sources": len(st.sources),
			"sources":          sortedKeys(st.sources),
			"window_s":         int(cfg.Window.Seconds()),
		},
	}
}
