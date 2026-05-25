package fleet

import (
	"encoding/binary"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// --- fleet:scan-trajectory -------------------------------------------------
//
// One source walking the address space: it hits each sensor's destination IP
// in (roughly) numeric order over time. A single sensor sees one hit; the
// aggregator sees the trajectory — its direction, rate, and the next target it
// is about to reach.

type trajHit struct {
	pos uint64
	t   time.Time
}

type trajectory struct {
	hits    []trajHit
	dests   map[string]struct{}
	sensors map[string]struct{}
	isV4    bool
	family  int // 0 = unset, 4, or 6
	last    time.Time
	fired   bool
}

const trajMaxHits = 256

func (c *Correlator) observeTrajectoryLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	pos, isV4, ok := ipToPos(ev.Dest.IP)
	if !ok {
		return nil
	}
	fam := 6
	if isV4 {
		fam = 4
	}
	tr := c.trajectories[ev.Source.IP]
	if tr == nil {
		tr = &trajectory{dests: map[string]struct{}{}, sensors: map[string]struct{}{}, isV4: isV4, family: fam}
		c.trajectories[ev.Source.IP] = tr
	}
	tr.last = now
	if tr.family != fam {
		return nil // don't mix v4/v6 positions in one trajectory
	}
	tr.sensors[sid] = struct{}{}
	if _, seen := tr.dests[ev.Dest.IP]; seen {
		return nil // only distinct destinations advance the walk
	}
	tr.dests[ev.Dest.IP] = struct{}{}
	when := ev.Time
	if when.IsZero() {
		when = now
	}
	tr.hits = append(tr.hits, trajHit{pos: pos, t: when})
	if len(tr.hits) > trajMaxHits {
		tr.hits = tr.hits[len(tr.hits)-trajMaxHits:]
	}
	if tr.fired || len(tr.dests) < c.cfg.TrajectoryHits || len(tr.sensors) < c.cfg.TrajectorySensors {
		return nil
	}
	dir, ratio, stride := trajShape(tr.hits)
	if ratio < c.cfg.TrajectoryMonotonic || dir == 0 {
		return nil
	}
	tr.fired = true
	meta := map[string]any{
		"source": ev.Source.IP, "direction": map[int]string{1: "ascending", -1: "descending"}[dir],
		"distinct_dests": len(tr.dests), "sensor_count": len(tr.sensors),
		"sensors": c.list(tr.sensors), "monotonic": round2(ratio),
	}
	if tr.isV4 && stride > 0 {
		last := tr.hits[len(tr.hits)-1].pos
		var next uint64
		if dir == 1 {
			next = last + stride
		} else if last > stride {
			next = last - stride
		}
		if next > 0 && next <= 0xffffffff {
			meta["next_target"] = uint32ToIP(uint32(next))
			meta["stride"] = stride
		}
	}
	return c.event("fleet:scan-trajectory", event.SeverityMedium, ev.Source, meta)
}

// trajShape returns the dominant direction (+1 asc, -1 desc, 0 none), the
// fraction of time-ordered steps that move that way, and the median step size.
func trajShape(hits []trajHit) (dir int, ratio float64, stride uint64) {
	if len(hits) < 2 {
		return 0, 0, 0
	}
	ordered := make([]trajHit, len(hits))
	copy(ordered, hits)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].t.Before(ordered[j].t) })
	var asc, desc int
	var diffs []uint64
	for i := 1; i < len(ordered); i++ {
		switch {
		case ordered[i].pos > ordered[i-1].pos:
			asc++
			diffs = append(diffs, ordered[i].pos-ordered[i-1].pos)
		case ordered[i].pos < ordered[i-1].pos:
			desc++
			diffs = append(diffs, ordered[i-1].pos-ordered[i].pos)
		}
	}
	steps := len(ordered) - 1
	if asc >= desc {
		dir = 1
		ratio = float64(asc) / float64(steps)
	} else {
		dir = -1
		ratio = float64(desc) / float64(steps)
	}
	stride = medianUint(diffs)
	return dir, ratio, stride
}

// --- fleet:synchronized-burst ----------------------------------------------
//
// Many sensors spiking inside the same short window, regardless of whether the
// sources overlap: the moment a fleet-wide event (a new exploit, a mass-scan
// campaign) goes live. A fleet-level changepoint, not an identity pattern.

func (c *Correlator) observeBurstLocked(sid string, now time.Time) *event.Event {
	st := c.sensorStats[sid] // trackSensorLocked guarantees presence
	if now.Sub(st.recentStart) > c.cfg.BurstWindow {
		st.recentStart = now
		st.recentCount = 0
	}
	st.recentCount++
	if now.Sub(c.lastBurstFire) < c.cfg.BurstWindow {
		return nil // cooldown: at most one burst alert per window
	}
	hot := make(map[string]struct{})
	for id, s := range c.sensorStats {
		if now.Sub(s.recentStart) <= c.cfg.BurstWindow && s.recentCount >= c.cfg.BurstMinEvents {
			hot[id] = struct{}{}
		}
	}
	if len(hot) < c.cfg.BurstSensors {
		return nil
	}
	c.lastBurstFire = now
	return c.event("fleet:synchronized-burst", event.SeverityHigh, event.Endpoint{}, map[string]any{
		"sensor_count": len(hot), "sensors": c.list(hot),
		"burst_window": c.cfg.BurstWindow.String(), "min_events": c.cfg.BurstMinEvents,
	})
}

// --- fleet:first-fleet-contact ---------------------------------------------
//
// A brand-new ASN or fingerprint — never seen anywhere in the fleet within the
// (long) novelty horizon — that immediately reaches several sensors: new
// infrastructure spinning up against the deployment. Keyed on ASN / fingerprint
// (not raw source IP) so the novelty memory stays bounded and high-signal.

type seenEntry struct {
	first, last time.Time
	sensors     map[string]struct{}
	fired       bool
}

func (c *Correlator) observeFirstContactLocked(ev *event.Event, sid string, now time.Time) []*event.Event {
	var out []*event.Event
	if asn := metaStr(ev, "asn"); asn != "" {
		out = add(out, c.firstContact(c.seenASN, "asn", asn, sid, now))
	}
	for _, kind := range []string{"ja3", "ja4", "hassh"} {
		if v := metaStr(ev, kind); v != "" {
			out = add(out, c.firstContact(c.seenFP, "fingerprint", kind+":"+v, sid, now))
		}
	}
	return out
}

func (c *Correlator) firstContact(seen map[string]*seenEntry, kind, value, sid string, now time.Time) *event.Event {
	e := seen[value]
	if e == nil {
		e = &seenEntry{first: now, sensors: map[string]struct{}{}}
		seen[value] = e
	}
	e.last = now
	// Novel only while first contact is still within the correlation window;
	// after that the identity is established and never re-fires (until it has
	// been absent for the whole horizon and the entry is pruned).
	if now.Sub(e.first) > c.cfg.Window {
		return nil
	}
	e.sensors[sid] = struct{}{}
	if e.fired || len(e.sensors) < c.cfg.FirstContactSensors {
		return nil
	}
	e.fired = true
	return c.event("fleet:first-fleet-contact", event.SeverityHigh, event.Endpoint{}, map[string]any{
		"kind": kind, "identity": value,
		"sensor_count": len(e.sensors), "sensors": c.list(e.sensors),
		"first_seen": e.first.UTC().Format(time.RFC3339),
	})
}

// --- fleet:identity-pivot --------------------------------------------------
//
// One actor behind many rotating IPs, linked by a stable composite identity
// (>= 2 attributes, at least one a fingerprint or credential) that survives the
// IP change. Stronger than fingerprint-shared's single-attribute link, and the
// headline is the rotation breadth (distinct IPs) across sensors.

func (c *Correlator) observePivotLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	attrs := pivotAttrs(ev)
	if len(attrs) < 2 {
		return nil
	}
	key := strings.Join(attrs, "|")
	a := touch(c.pivots, key, sid, ev.Source.IP, now)
	if a.fired || len(a.sources) < c.cfg.PivotSources || len(a.sensors) < c.cfg.PivotSensors {
		return nil
	}
	a.fired = true
	return c.event("fleet:identity-pivot", event.SeverityHigh, ev.Source, map[string]any{
		"identity": attrs, "source_count": len(a.sources), "sensor_count": len(a.sensors),
		"sources": c.list(a.sources), "sensors": c.list(a.sensors),
	})
}

// pivotAttrs collects the linking attributes present on an event, sorted for a
// deterministic key. It returns them only when at least one is a strong
// identifier (fingerprint or credential username) — a weak pair (UA + tool)
// alone would over-link unrelated clients.
func pivotAttrs(ev *event.Event) []string {
	var attrs []string
	strong := false
	addAttr := func(label, val string, isStrong bool) {
		if val == "" {
			return
		}
		attrs = append(attrs, label+"="+val)
		if isStrong {
			strong = true
		}
	}
	addAttr("ja3", metaStr(ev, "ja3"), true)
	addAttr("ja4", metaStr(ev, "ja4"), true)
	addAttr("hassh", metaStr(ev, "hassh"), true)
	user := metaStr(ev, "username")
	if user == "" {
		user = metaStr(ev, "user")
	}
	addAttr("user", user, true)
	if tools := metaStrings(ev, "tools"); len(tools) > 0 {
		addAttr("tool", tools[0], false)
	}
	addAttr("ua", metaStr(ev, "user_agent"), false)
	if !strong {
		return nil
	}
	sort.Strings(attrs)
	return attrs
}

// --- fleet:geo-distributed-actor -------------------------------------------
//
// One fingerprint or credential appearing from many countries across sensors:
// fleet-scale impossible travel — a single actor behind a distributed proxy /
// botnet. Needs GeoIP country enrichment on the aggregator.

func (c *Correlator) observeGeoLocked(ev *event.Event, sid string, now time.Time) []*event.Event {
	country := metaStr(ev, "geo_country")
	if country == "" {
		return nil
	}
	var out []*event.Event
	for _, kind := range []string{"ja3", "ja4", "hassh"} {
		if v := metaStr(ev, kind); v != "" {
			out = add(out, c.geoCheck(c.geoFP, "fingerprint", kind+":"+v, ev, sid, country, now))
		}
	}
	user := metaStr(ev, "username")
	if user == "" {
		user = metaStr(ev, "user")
	}
	pass := metaStr(ev, "password")
	if pass == "" {
		pass = metaStr(ev, "pass")
	}
	if user != "" || pass != "" {
		out = add(out, c.geoCheck(c.geoCred, "credential", user+"\x00"+pass, ev, sid, country, now))
	}
	return out
}

func (c *Correlator) geoCheck(m map[string]*actor, kind, value string, ev *event.Event, sid, country string, now time.Time) *event.Event {
	a := touch(m, value, sid, ev.Source.IP, now)
	if a.geos == nil {
		a.geos = map[string]struct{}{}
	}
	a.geos[country] = struct{}{}
	if a.fired || len(a.geos) < c.cfg.GeoCountries || len(a.sensors) < c.cfg.GeoSensors {
		return nil
	}
	a.fired = true
	identity := value
	if kind == "credential" {
		identity = strings.ReplaceAll(value, "\x00", ":")
	}
	return c.event("fleet:geo-distributed-actor", event.SeverityHigh, ev.Source, map[string]any{
		"by": kind, "identity": identity, "country_count": len(a.geos), "countries": c.list(a.geos),
		"source_count": len(a.sources), "sensor_count": len(a.sensors),
	})
}

// --- fleet:target-profile-match --------------------------------------------
//
// Distinct sources independently running the same multi-CVE playbook across
// sensors: a shared toolkit / runbook even without a shared fingerprint. Keyed
// on the sorted set of CVEs a source attempts (>= ProfileCVEs of them, so it is
// a real combination, not a single probe).

type cveSet struct {
	set  map[string]struct{}
	last time.Time
}

const cveSetCap = 64

func (c *Correlator) observeProfileLocked(ev *event.Event, sid string, now time.Time) *event.Event {
	if !strings.HasPrefix(ev.RuleID, "cve:") {
		return nil
	}
	cve := strings.TrimPrefix(ev.RuleID, "cve:")
	if cve == "" {
		return nil
	}
	cs := c.srcCVEs[ev.Source.IP]
	if cs == nil {
		cs = &cveSet{set: map[string]struct{}{}}
		c.srcCVEs[ev.Source.IP] = cs
	}
	cs.last = now
	if len(cs.set) < cveSetCap {
		cs.set[cve] = struct{}{}
	}
	if len(cs.set) < c.cfg.ProfileCVEs {
		return nil
	}
	sig := setKeysSorted(cs.set)
	key := strings.Join(sig, "+")
	a := touch(c.profiles, key, sid, ev.Source.IP, now)
	if a.fired || len(a.sources) < c.cfg.ProfileSources || len(a.sensors) < c.cfg.ProfileSensors {
		return nil
	}
	a.fired = true
	return c.event("fleet:target-profile-match", event.SeverityHigh, ev.Source, map[string]any{
		"playbook": sig, "cve_count": len(sig),
		"source_count": len(a.sources), "sensor_count": len(a.sensors),
		"sources": c.list(a.sources), "sensors": c.list(a.sensors),
	})
}

// --- shared helpers --------------------------------------------------------

// ipToPos maps an IP to a comparable numeric position: the full 32 bits for
// IPv4, the high 64 bits for IPv6. Returns ok=false for an unparseable address.
func ipToPos(ipStr string) (pos uint64, isV4, ok bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, false, false
	}
	if v4 := ip.To4(); v4 != nil {
		return uint64(binary.BigEndian.Uint32(v4)), true, true
	}
	return binary.BigEndian.Uint64(ip.To16()[:8]), false, true
}

func uint32ToIP(v uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IP(b[:]).String()
}

func medianUint(xs []uint64) uint64 {
	n := len(xs)
	if n == 0 {
		return 0
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	if n%2 == 1 {
		return xs[n/2]
	}
	return (xs[n/2-1] + xs[n/2]) / 2
}

func setKeysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
