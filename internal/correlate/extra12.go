package correlate

import (
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Round-twelve correlators: DNS-tunnel / DGA bursts and the scan-then-exploit
// progression.

// dnsTunnelMarkers are the DNS-handler anomaly markers that indicate tunneling,
// domain-generation, or exfil-shaped query abuse.
var dnsTunnelMarkers = map[string]bool{
	"dns-tunnel-suspected": true,
	"dns-dga-suspected":    true,
	"dns-qname-overlong":   true,
	"dns-txt-exfil":        true,
}

// checkDNSTunnel counts DNS tunneling / DGA anomalies from one source; several
// within the window is DNS-based C2 or data exfiltration rather than a stray
// malformed query.
func (c *Correlator) checkDNSTunnel(ev *event.Event, now time.Time) *event.Event {
	if !evHasMarkerIn(ev, dnsTunnelMarkers) {
		return nil
	}
	cfg := c.cfg.DNSTunnel
	st := windowedCount(c.dnsTunnel, ev.Source.IP, now, cfg.Window)
	st.count++
	if st.count < cfg.Events {
		return nil
	}
	if !c.shouldEmit("dnstunnel|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:dns_tunnel", Severity: c.dnsTunnelSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"events":   st.count,
			"window_s": int(cfg.Window.Seconds()),
		},
	}
}

// checkReconToExploit fires when a source that earlier showed recon/discovery
// activity then lands a CVE exploit attempt within the window — the classic
// scan-then-exploit progression, caught at two stages (the storyline needs
// three distinct tactics). The recon marker is remembered per source; the
// emission happens on the exploit event.
func (c *Correlator) checkReconToExploit(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.ReconToExploit
	st := windowedSet(c.reconExp, ev.Source.IP, now, cfg.Window)
	recon := false
	for _, tac := range ev.MitreTactics {
		if tac == "reconnaissance" || tac == "discovery" {
			recon = true
		}
	}
	if recon {
		st.set["recon"] = struct{}{}
	}
	isExploit := strings.HasPrefix(ev.RuleID, "cve:")
	if !isExploit {
		for _, a := range ev.Anomalies {
			if strings.HasPrefix(a, "cve:") {
				isExploit = true
				break
			}
		}
	}
	if !isExploit {
		return nil
	}
	if _, sawRecon := st.set["recon"]; !sawRecon {
		return nil
	}
	if !c.shouldEmit("recon2exp|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:recon_to_exploit", Severity: c.reconExpSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"exploit_rule": ev.RuleID,
			"window_s":     int(cfg.Window.Seconds()),
		},
	}
}
