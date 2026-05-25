package fleet

import (
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// observeSourceLocked: one source IP across many sensors = a single attacker
// sweeping the fleet. Classified broad vs targeted by fleet coverage.
func (c *Correlator) observeSourceLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	a := touch(c.sources, ev.Source.IP, sid, "", now)
	if a.fired || len(a.sensors) < c.cfg.SourceSensors {
		return nil
	}
	a.fired = true
	scope, cov, sev := c.coverageLocked(len(a.sensors))
	return c.event("fleet:source-multi-sensor", sev, ev.Source, map[string]any{
		"source": ev.Source.IP, "asn": metaStr(ev, "asn"),
		"sensor_count": len(a.sensors), "sensors": c.list(a.sensors),
		"scope": scope, "coverage": cov,
	})
}

// observeASNLocked: one ASN across many sensors = coordinated / distributed from
// one network. Tracks distinct sources too, and is coverage-classified.
func (c *Correlator) observeASNLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	asn := metaStr(ev, "asn")
	if asn == "" {
		return nil
	}
	a := touch(c.asns, asn, sid, ev.Source.IP, now)
	if a.fired || len(a.sensors) < c.cfg.ASNSensors {
		return nil
	}
	a.fired = true
	scope, cov, sev := c.coverageLocked(len(a.sensors))
	return c.event("fleet:asn-multi-sensor", sev, ev.Source, map[string]any{
		"asn": asn, "asn_org": metaStr(ev, "asn_org"),
		"sensor_count": len(a.sensors), "source_count": len(a.sources),
		"sensors": c.list(a.sensors), "scope": scope, "coverage": cov,
	})
}

// observeFPLocked: one TLS/SSH fingerprint across many sensors AND many sources
// = a shared toolkit / botnet (the IPs differ but the client stack is
// identical). Already high-signal via the dual breadth requirement.
func (c *Correlator) observeFPLocked(ev *event.Event, sid string, now time.Time) []*event.Event {
	var out []*event.Event
	for _, kind := range []string{"ja3", "ja4", "hassh"} {
		v := metaStr(ev, kind)
		if v == "" {
			continue
		}
		a := touch(c.fps, kind+":"+v, sid, ev.Source.IP, now)
		if a.fired || len(a.sensors) < c.cfg.FPSensors || len(a.sources) < c.cfg.FPSources {
			continue
		}
		a.fired = true
		out = append(out, c.alert(ev, "fleet:fingerprint-shared", map[string]any{
			"fingerprint": kind + ":" + v, "sensor_count": len(a.sensors),
			"source_count": len(a.sources), "sensors": c.list(a.sensors),
		}))
	}
	return out
}

// observePayloadLocked: the SAME malware/shellcode artifact (by SHA-256) landing
// on several sensors = one distribution campaign / botnet. A shared hash is
// never background scanning, so this is high-signal regardless of coverage.
func (c *Correlator) observePayloadLocked(ev *event.Event, sid string, now time.Time) []*event.Event {
	arts := metaStrings(ev, "payload_artifacts")
	if len(arts) == 0 {
		return nil
	}
	var out []*event.Event
	for _, desc := range arts {
		hash := artifactHash(desc)
		if hash == "" {
			continue
		}
		a := touch(c.payloads, hash, sid, ev.Source.IP, now)
		if a.fired || len(a.sensors) < c.cfg.PayloadSensors {
			continue
		}
		a.fired = true
		out = append(out, c.alert(ev, "fleet:payload-campaign", map[string]any{
			"sha256": hash, "artifact": desc,
			"sensor_count": len(a.sensors), "source_count": len(a.sources),
			"sensors": c.list(a.sensors), "sources": c.list(a.sources),
		}))
	}
	return out
}

// artifactHash pulls the sha256 out of a "<kind>:<sha256>[ -> file]" descriptor
// (the form sensor.observePayload stamps into payload_artifacts).
func artifactHash(desc string) string {
	if i := strings.Index(desc, " -> "); i >= 0 {
		desc = desc[:i]
	}
	_, hash, ok := strings.Cut(desc, ":")
	if !ok {
		return ""
	}
	return strings.TrimSpace(hash)
}

// observeCredLocked: the SAME credential pair tried across several sensors =
// a shared stuffing list, or — the high-value case — a honeytoken credential
// planted on one node now being used against others. Never background noise.
func (c *Correlator) observeCredLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	user := metaStr(ev, "username")
	if user == "" {
		user = metaStr(ev, "user")
	}
	pass := metaStr(ev, "password")
	if pass == "" {
		pass = metaStr(ev, "pass")
	}
	if user == "" && pass == "" {
		return nil
	}
	a := touch(c.creds, user+"\x00"+pass, sid, ev.Source.IP, now)
	if a.fired || len(a.sensors) < c.cfg.CredSensors {
		return nil
	}
	a.fired = true
	return c.alert(ev, "fleet:credential-campaign", map[string]any{
		"username": user, "password": pass,
		"sensor_count": len(a.sensors), "source_count": len(a.sources),
		"sensors": c.list(a.sensors), "sources": c.list(a.sources),
	})
}

// observeCVELocked: the SAME CVE exploit signature hitting several sensors =
// a worm / mass-exploitation wave. Coverage-classified: a wave touching nearly
// the whole fleet is internet-wide scanning (broad), a specific subset is
// targeted.
func (c *Correlator) observeCVELocked(ev *event.Event, sid string, now time.Time) *event.Event {
	if !strings.HasPrefix(ev.RuleID, "cve:") {
		return nil
	}
	cve := strings.TrimPrefix(ev.RuleID, "cve:")
	if cve == "" {
		return nil
	}
	a := touch(c.cves, cve, sid, ev.Source.IP, now)
	if a.fired || len(a.sensors) < c.cfg.CVESensors {
		return nil
	}
	a.fired = true
	scope, cov, sev := c.coverageLocked(len(a.sensors))
	meta := map[string]any{
		"cve": cve, "sensor_count": len(a.sensors), "source_count": len(a.sources),
		"sensors": c.list(a.sensors), "scope": scope, "coverage": cov,
	}
	copyCVEMeta(ev, meta)
	return c.event("fleet:cve-wave", sev, ev.Source, meta)
}

// observeSubnetLocked: several distinct IPs from one source block (/24, /64)
// each hitting a different sensor — the one-IP-per-target evasion that slips
// under source-multi-sensor. Requires multiple distinct IPs so it never
// duplicates the single-IP detector.
func (c *Correlator) observeSubnetLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	key := subnetKey(ev.Source.IP)
	if key == "" {
		return nil
	}
	a := touch(c.subnets, key, sid, ev.Source.IP, now)
	if a.fired || len(a.sensors) < c.cfg.SubnetSensors || len(a.sources) < c.cfg.SubnetSources {
		return nil
	}
	a.fired = true
	return c.event("fleet:subnet-coordinated", event.SeverityHigh, ev.Source, map[string]any{
		"subnet": key, "sensor_count": len(a.sensors), "source_count": len(a.sources),
		"sensors": c.list(a.sensors), "sources": c.list(a.sources),
	})
}

// observeOutlierLocked: a sensor whose high-severity volume is far above its
// peers is being specifically targeted (or has been discovered as a honeypot).
// Purely aggregator-only: it needs peer baselines. Volume-relative, so it is
// robust to sensors running different handler mixes.
func (c *Correlator) observeOutlierLocked(sid string) *event.Event {
	st := c.sensorStats[sid] // trackSensorLocked guarantees presence
	if st == nil || st.fired || st.high < c.cfg.OutlierMinEvents {
		return nil
	}
	peers := make([]int, 0, len(c.sensorStats))
	for id, s := range c.sensorStats {
		if id != sid {
			peers = append(peers, s.high)
		}
	}
	if len(peers) < c.cfg.OutlierMinPeers {
		return nil
	}
	med := medianInt(peers)
	thresh := float64(med) * c.cfg.OutlierFactor
	if med == 0 {
		// Peers essentially idle: being alone over the floor is the signal.
		thresh = float64(c.cfg.OutlierMinEvents)
	}
	if float64(st.high) < thresh {
		return nil
	}
	st.fired = true
	return c.event("fleet:outlier-sensor", event.SeverityHigh, event.Endpoint{}, map[string]any{
		"sensor": sid, "high_sev_events": st.high, "total_events": st.total,
		"peer_median": med, "factor": c.cfg.OutlierFactor, "peers": len(peers),
	})
}

// medianInt returns the median of xs (it sorts xs in place).
func medianInt(xs []int) int {
	n := len(xs)
	if n == 0 {
		return 0
	}
	sort.Ints(xs)
	if n%2 == 1 {
		return xs[n/2]
	}
	return (xs[n/2-1] + xs[n/2]) / 2
}
