// Package fleet is the cross-sensor correlator that runs on an aggregator over
// the merged event stream (local + ingested). A single sensor only ever sees
// one vantage point; once events from many sensors converge, patterns invisible
// to any one node emerge. This correlator keys events by attacker identity and
// by shared artifact, tracking the distinct sensors (and, where useful, the
// distinct sources) each touches within a window, and emits a fleet:* event the
// first time a pattern crosses its threshold this window. It exploits five
// vantage axes:
//
//   - breadth: one source IP / ASN / fingerprint hammering many sensors
//     (fleet:source-multi-sensor, fleet:asn-multi-sensor, fleet:fingerprint-shared);
//   - shared-artifact campaigns: one malware hash / credential / CVE recurring
//     across sensors (fleet:payload-campaign, fleet:credential-campaign,
//     fleet:cve-wave);
//   - coordination: several IPs from one network each hitting a different sensor,
//     evading every per-sensor threshold (fleet:subnet-coordinated);
//   - peer-relative baselines: one sensor far louder than its peers, i.e.
//     specifically targeted/discovered (fleet:outlier-sensor).
//
// The breadth/wave detectors are additionally classified broad vs targeted by
// fleet coverage: an identity hitting nearly every sensor is internet background
// radiation (every public honeypot gets scanned), while one hitting a specific
// subset is targeted and reported at higher severity.
package fleet

import (
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Config tunes the thresholds and the observation window. Zero-valued fields
// fall back to withDefaults.
type Config struct {
	Enabled bool
	Window  time.Duration // how long an identity's activity is remembered

	// Breadth-of-sensors detectors.
	SourceSensors int // one source IP on >= N sensors -> alert
	ASNSensors    int // one ASN on >= N sensors -> alert
	FPSensors     int // one fingerprint on >= N sensors ...
	FPSources     int // ... and >= M distinct sources -> alert (botnet/tool family)

	// Shared-artifact campaigns.
	PayloadSensors int // same artifact hash on >= N sensors -> alert
	CredSensors    int // same credential pair on >= N sensors -> alert
	CVESensors     int // same CVE on >= N sensors -> alert

	// Coordinated distributed infrastructure: >= M distinct IPs from one source
	// block (/24, /64) covering >= N sensors. (One IP across sensors is already
	// source-multi-sensor; this is the one-IP-per-target evasion.)
	SubnetSensors int
	SubnetSources int

	// Peer-relative outlier: a sensor whose high-severity event count crosses
	// OutlierMinEvents AND exceeds OutlierFactor x the peer median (with at
	// least OutlierMinPeers other sensors to compare against).
	OutlierMinEvents int
	OutlierFactor    float64
	OutlierMinPeers  int

	// BroadCoverage is the fraction of the active fleet (sensors_hit /
	// total_sensors) at or above which a breadth/wave hit is labelled "broad"
	// (internet background) and downgraded to medium; below it is "targeted".
	BroadCoverage float64

	MaxList int // cap the sensor/source list in alert meta
}

func (c *Config) withDefaults() {
	if c.Window <= 0 {
		c.Window = time.Hour
	}
	if c.SourceSensors <= 0 {
		c.SourceSensors = 3
	}
	if c.ASNSensors <= 0 {
		c.ASNSensors = 5
	}
	if c.FPSensors <= 0 {
		c.FPSensors = 3
	}
	if c.FPSources <= 0 {
		c.FPSources = 5
	}
	if c.PayloadSensors <= 0 {
		c.PayloadSensors = 2
	}
	if c.CredSensors <= 0 {
		c.CredSensors = 2
	}
	if c.CVESensors <= 0 {
		c.CVESensors = 3
	}
	if c.SubnetSensors <= 0 {
		c.SubnetSensors = 3
	}
	if c.SubnetSources <= 0 {
		c.SubnetSources = 3
	}
	if c.OutlierMinEvents <= 0 {
		c.OutlierMinEvents = 100
	}
	if c.OutlierFactor <= 0 {
		c.OutlierFactor = 4
	}
	if c.OutlierMinPeers <= 0 {
		c.OutlierMinPeers = 3
	}
	if c.BroadCoverage <= 0 {
		c.BroadCoverage = 0.8
	}
	if c.MaxList <= 0 {
		c.MaxList = 50
	}
}

// actor is one tracked identity (a source IP, ASN, fingerprint, artifact hash,
// credential, CVE, or source block): the distinct sensors and sources it has
// touched within the window, and whether it has already fired this window.
type actor struct {
	sensors map[string]struct{}
	sources map[string]struct{}
	last    time.Time
	fired   bool
}

func newActor() *actor {
	return &actor{sensors: map[string]struct{}{}, sources: map[string]struct{}{}}
}

// sensorStat is a per-sensor windowed counter, used by the coverage classifier
// (total active sensors) and the peer-relative outlier detector.
type sensorStat struct {
	total int
	high  int
	last  time.Time
	fired bool
}

// Correlator holds the windowed per-identity state. Safe for concurrent use.
type Correlator struct {
	cfg Config
	mu  sync.Mutex

	sources  map[string]*actor // key: source IP
	asns     map[string]*actor // key: ASN
	fps      map[string]*actor // key: "<kind>:<value>" (ja3/ja4/hassh)
	payloads map[string]*actor // key: artifact sha256
	creds    map[string]*actor // key: "<user>\x00<pass>"
	cves     map[string]*actor // key: CVE id
	subnets  map[string]*actor // key: source block ("a.b.c.0/24" | ".../64")

	sensorStats map[string]*sensorStat // key: sensor id

	now func() time.Time // overridable in tests
}

// New builds a correlator. Returns nil when disabled so callers can no-op.
func New(cfg Config) *Correlator {
	if !cfg.Enabled {
		return nil
	}
	cfg.withDefaults()
	return &Correlator{
		cfg:         cfg,
		sources:     map[string]*actor{},
		asns:        map[string]*actor{},
		fps:         map[string]*actor{},
		payloads:    map[string]*actor{},
		creds:       map[string]*actor{},
		cves:        map[string]*actor{},
		subnets:     map[string]*actor{},
		sensorStats: map[string]*sensorStat{},
		now:         time.Now,
	}
}

// Observe folds one event into the fleet view and returns any fleet:* detection
// events that crossed a threshold for the first time this window.
func (c *Correlator) Observe(ev *event.Event) []*event.Event {
	if c == nil || ev == nil || ev.Source.IP == "" {
		return nil
	}
	if strings.HasPrefix(ev.RuleID, "fleet:") { // never correlate our own output (loop guard)
		return nil
	}
	sid := ev.SensorID
	if sid == "" {
		sid = ev.Sensor
	}
	if sid == "" {
		return nil
	}
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	c.trackSensorLocked(sid, ev, now) // before the detectors: feeds coverage + outlier

	var out []*event.Event
	out = add(out, c.observeSourceLocked(ev, sid, now))
	out = add(out, c.observeASNLocked(ev, sid, now))
	out = append(out, c.observeFPLocked(ev, sid, now)...)
	out = append(out, c.observePayloadLocked(ev, sid, now)...)
	out = add(out, c.observeCredLocked(ev, sid, now))
	out = add(out, c.observeCVELocked(ev, sid, now))
	out = add(out, c.observeSubnetLocked(ev, sid, now))
	out = add(out, c.observeOutlierLocked(sid))
	return out
}

// add appends e to out when non-nil.
func add(out []*event.Event, e *event.Event) []*event.Event {
	if e != nil {
		out = append(out, e)
	}
	return out
}

// trackSensorLocked records this event against its sensor's windowed counters.
func (c *Correlator) trackSensorLocked(sid string, ev *event.Event, now time.Time) {
	st := c.sensorStats[sid]
	if st == nil {
		st = &sensorStat{}
		c.sensorStats[sid] = st
	}
	st.total++
	if ev.Severity >= event.SeverityHigh {
		st.high++
	}
	st.last = now
}

// touch records (key seen from sensor sid, optional source src) and returns the
// actor.
func touch(m map[string]*actor, key, sid, src string, now time.Time) *actor {
	a := m[key]
	if a == nil {
		a = newActor()
		m[key] = a
	}
	a.sensors[sid] = struct{}{}
	if src != "" {
		a.sources[src] = struct{}{}
	}
	a.last = now
	return a
}

// pruneLocked drops identities + sensors idle longer than the window so
// thresholds are "within a window" and memory stays bounded.
func (c *Correlator) pruneLocked(now time.Time) {
	cutoff := now.Add(-c.cfg.Window)
	for _, m := range []map[string]*actor{c.sources, c.asns, c.fps, c.payloads, c.creds, c.cves, c.subnets} {
		for k, a := range m {
			if a.last.Before(cutoff) {
				delete(m, k)
			}
		}
	}
	for k, s := range c.sensorStats {
		if s.last.Before(cutoff) {
			delete(c.sensorStats, k)
		}
	}
}

// coverageLocked classifies how much of the active fleet an identity touched.
// A hit spanning nearly every sensor is "broad" (internet background radiation —
// every public honeypot gets scanned), reported at medium; a hit on a specific
// subset is "targeted", reported at high. Returns the label, the rounded ratio,
// and the severity to use.
func (c *Correlator) coverageLocked(nSensors int) (scope string, ratio float64, sev event.Severity) {
	total := len(c.sensorStats)
	if total < 1 {
		total = 1
	}
	ratio = math.Round(float64(nSensors)/float64(total)*100) / 100
	if ratio >= c.cfg.BroadCoverage {
		return "broad", ratio, event.SeverityMedium
	}
	return "targeted", ratio, event.SeverityHigh
}

// event builds a fleet:* detection event with the window stamped in meta.
func (c *Correlator) event(ruleID string, sev event.Severity, src event.Endpoint, meta map[string]any) *event.Event {
	meta["window"] = c.cfg.Window.String()
	return &event.Event{
		ID:       event.NewID(),
		Time:     c.now(),
		RuleID:   ruleID,
		Severity: sev,
		Source:   src,
		Meta:     meta,
	}
}

// alert is the fixed-high-severity form keyed to the triggering source.
func (c *Correlator) alert(trigger *event.Event, ruleID string, meta map[string]any) *event.Event {
	return c.event(ruleID, event.SeverityHigh, trigger.Source, meta)
}

// list returns the set's members, sorted and capped at MaxList.
func (c *Correlator) list(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > c.cfg.MaxList {
		out = out[:c.cfg.MaxList]
	}
	return out
}

// subnetKey reduces a source IP to its coordinating block: /24 for IPv4, /64 for
// IPv6. Returns "" for an unparseable address.
func subnetKey(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func metaStr(ev *event.Event, key string) string {
	if ev.Meta == nil {
		return ""
	}
	s, _ := ev.Meta[key].(string)
	return s
}

// metaStrings coerces a meta value (string slice, or the []any a JSON round-trip
// produces) into a []string.
func metaStrings(ev *event.Event, key string) []string {
	if ev.Meta == nil {
		return nil
	}
	switch t := ev.Meta[key].(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
