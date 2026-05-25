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

	// Scan trajectory: one source walking the address space across sensors.
	TrajectoryHits      int     // distinct destinations before evaluating
	TrajectorySensors   int     // ... spanning >= N sensors
	TrajectoryMonotonic float64 // fraction of time-ordered steps moving one way

	// Synchronized burst: many sensors spiking in the same short window.
	BurstWindow    time.Duration // the short spike window
	BurstMinEvents int           // a sensor is "spiking" at >= N events in BurstWindow
	BurstSensors   int           // fire when >= N sensors spike together

	// First fleet contact: a brand-new ASN / fingerprint reaching the fleet.
	FirstContactSensors int           // novel identity must reach >= N sensors
	FirstSeenHorizon    time.Duration // how long an identity is remembered as "seen"

	// Identity pivot: one actor across rotating IPs, linked by shared attributes.
	PivotSources int // >= N distinct IPs ...
	PivotSensors int // ... across >= N sensors

	// Geo-distributed actor: one fingerprint / credential from many countries.
	GeoCountries int // >= N distinct countries ...
	GeoSensors   int // ... across >= N sensors

	// Target-profile match: the same multi-CVE playbook from distinct sources.
	ProfileCVEs    int // a playbook needs >= N CVEs to count as a combination
	ProfileSources int // >= N distinct sources sharing it ...
	ProfileSensors int // ... across >= N sensors

	// Honeytoken spread: the same canary token tripped across the fleet.
	HoneytokenSensors int // same canary token on >= N sensors -> alert

	// CVE emergence: a brand-new CVE (novel within FirstSeenHorizon) reaching
	// several sensors — an n-day going live fleet-wide.
	CVEEmergenceSensors int

	// Cross-protocol actor: one source touching many distinct services across
	// the fleet (fleet-wide service enumeration by a single actor).
	CrossProtoHandlers int // >= N distinct handlers ...
	CrossProtoSensors  int // ... across >= N sensors

	// Fingerprint ASN spread: one fingerprint operated from many networks.
	FPASNs       int // one ja3/ja4/hassh from >= N distinct ASNs ...
	FPASNSensors int // ... across >= N sensors

	// Threat-intel surge: known-bad infra (threat-intel list / Tor) converging.
	ThreatSurgeSources int // >= N distinct flagged sources ...
	ThreatSurgeSensors int // ... across >= N sensors

	// Tool campaign: the same identified attack tool across the fleet.
	ToolSensors int // one tool on >= N sensors ...
	ToolSources int // ... from >= N distinct sources

	// C2 shared: the same harvested C2 / dropper URL across the fleet.
	C2Sensors int // one URL on >= N sensors

	// User-agent shared: the same HTTP User-Agent across the fleet.
	UASensors int // one UA on >= N sensors ...
	UASources int // ... from >= N distinct sources

	// Tactic convergence: the same MITRE technique surging across the fleet.
	TacticSources int // >= N distinct sources using one technique ...
	TacticSensors int // ... across >= N sensors

	// Recidivist network: an ASN active across many distinct time buckets — a
	// persistently-returning hostile network.
	RecidivistBucket  time.Duration // bucket size (default 24h = "days")
	RecidivistWindows int           // alert at >= N distinct buckets

	// Port campaign: a sudden focus on one destination port.
	PortCampaignSources int   // >= N distinct sources on one port ...
	PortCampaignSensors int   // ... across >= N sensors
	PortCampaignExclude []int // ports too ubiquitous to be a signal (default 22/80/443)

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
	if c.TrajectoryHits <= 0 {
		c.TrajectoryHits = 8
	}
	if c.TrajectorySensors <= 0 {
		c.TrajectorySensors = 3
	}
	if c.TrajectoryMonotonic <= 0 {
		c.TrajectoryMonotonic = 0.8
	}
	if c.BurstWindow <= 0 {
		c.BurstWindow = 5 * time.Minute
	}
	if c.BurstMinEvents <= 0 {
		c.BurstMinEvents = 20
	}
	if c.BurstSensors <= 0 {
		c.BurstSensors = 3
	}
	if c.FirstContactSensors <= 0 {
		c.FirstContactSensors = 3
	}
	if c.FirstSeenHorizon <= 0 {
		c.FirstSeenHorizon = 7 * 24 * time.Hour
	}
	if c.PivotSources <= 0 {
		c.PivotSources = 5
	}
	if c.PivotSensors <= 0 {
		c.PivotSensors = 3
	}
	if c.GeoCountries <= 0 {
		c.GeoCountries = 3
	}
	if c.GeoSensors <= 0 {
		c.GeoSensors = 2
	}
	if c.ProfileCVEs <= 0 {
		c.ProfileCVEs = 2
	}
	if c.ProfileSources <= 0 {
		c.ProfileSources = 3
	}
	if c.ProfileSensors <= 0 {
		c.ProfileSensors = 2
	}
	if c.HoneytokenSensors <= 0 {
		c.HoneytokenSensors = 2
	}
	if c.CVEEmergenceSensors <= 0 {
		c.CVEEmergenceSensors = 2
	}
	if c.CrossProtoHandlers <= 0 {
		c.CrossProtoHandlers = 4
	}
	if c.CrossProtoSensors <= 0 {
		c.CrossProtoSensors = 2
	}
	if c.FPASNs <= 0 {
		c.FPASNs = 3
	}
	if c.FPASNSensors <= 0 {
		c.FPASNSensors = 2
	}
	if c.ThreatSurgeSources <= 0 {
		c.ThreatSurgeSources = 10
	}
	if c.ThreatSurgeSensors <= 0 {
		c.ThreatSurgeSensors = 3
	}
	if c.ToolSensors <= 0 {
		c.ToolSensors = 3
	}
	if c.ToolSources <= 0 {
		c.ToolSources = 3
	}
	if c.C2Sensors <= 0 {
		c.C2Sensors = 2
	}
	if c.UASensors <= 0 {
		c.UASensors = 3
	}
	if c.UASources <= 0 {
		c.UASources = 5
	}
	if c.TacticSources <= 0 {
		c.TacticSources = 8
	}
	if c.TacticSensors <= 0 {
		c.TacticSensors = 3
	}
	if c.RecidivistBucket <= 0 {
		c.RecidivistBucket = 24 * time.Hour
	}
	if c.RecidivistWindows <= 0 {
		c.RecidivistWindows = 3
	}
	if c.PortCampaignSources <= 0 {
		c.PortCampaignSources = 5
	}
	if c.PortCampaignSensors <= 0 {
		c.PortCampaignSensors = 3
	}
	if c.PortCampaignExclude == nil {
		c.PortCampaignExclude = []int{22, 80, 443}
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
	geos    map[string]struct{} // distinct countries; lazily allocated (geo detector only)
	extra   map[string]struct{} // a detector-specific 3rd dimension (handlers / ASNs); lazy
	last    time.Time
	fired   bool
}

func newActor() *actor {
	return &actor{sensors: map[string]struct{}{}, sources: map[string]struct{}{}}
}

// sensorStat is a per-sensor windowed counter, used by the coverage classifier
// (total active sensors), the peer-relative outlier detector, and the
// synchronized-burst detector (the short rolling bucket).
type sensorStat struct {
	total int
	high  int
	last  time.Time
	fired bool

	recentCount int       // events in the current burst bucket
	recentStart time.Time // when the current burst bucket opened
}

// Correlator holds the windowed per-identity state. Safe for concurrent use.
type Correlator struct {
	cfg Config
	mu  sync.Mutex

	sources    map[string]*actor // key: source IP
	asns       map[string]*actor // key: ASN
	fps        map[string]*actor // key: "<kind>:<value>" (ja3/ja4/hassh)
	payloads   map[string]*actor // key: artifact sha256
	creds      map[string]*actor // key: "<user>\x00<pass>"
	cves       map[string]*actor // key: CVE id
	subnets    map[string]*actor // key: source block ("a.b.c.0/24" | ".../64")
	pivots     map[string]*actor // key: composite multi-attribute identity
	geoFP      map[string]*actor // key: "<kind>:<value>" fingerprint (geo)
	geoCred    map[string]*actor // key: "<user>\x00<pass>" (geo)
	profiles   map[string]*actor // key: sorted CVE-set playbook signature
	tokens     map[string]*actor // key: canary token rule_id (honeytoken spread)
	crossProto map[string]*actor // key: source IP (cross-protocol actor; extra = handlers)
	fpASN      map[string]*actor // key: "<kind>:<value>" fingerprint (extra = ASNs)
	surge      map[string]*actor // key: "" (threat-intel surge — flagged infra)
	toolc      map[string]*actor // key: tool name (tool campaign)
	c2         map[string]*actor // key: harvested URL (shared C2)
	uas        map[string]*actor // key: user-agent (shared UA)
	tactics    map[string]*actor // key: MITRE technique id (tactic convergence)
	ports      map[string]*actor // key: dest port (port campaign)

	recid       map[string]*recidEntry // key: ASN (recidivist network — long horizon)
	portExclude map[int]bool           // ports too ubiquitous for port-campaign

	sensorStats  map[string]*sensorStat // key: sensor id
	trajectories map[string]*trajectory // key: source IP (address-walk tracking)
	seenASN      map[string]*seenEntry  // long-horizon novelty memory (ASN)
	seenFP       map[string]*seenEntry  // long-horizon novelty memory (fingerprint)
	seenCVE      map[string]*seenEntry  // long-horizon novelty memory (CVE — emergence)
	srcCVEs      map[string]*cveSet     // per-source CVE set (target-profile)

	lastBurstFire time.Time // synchronized-burst cooldown

	now func() time.Time // overridable in tests
}

// New builds a correlator. Returns nil when disabled so callers can no-op.
func New(cfg Config) *Correlator {
	if !cfg.Enabled {
		return nil
	}
	cfg.withDefaults()
	c := &Correlator{
		cfg:          cfg,
		sources:      map[string]*actor{},
		asns:         map[string]*actor{},
		fps:          map[string]*actor{},
		payloads:     map[string]*actor{},
		creds:        map[string]*actor{},
		cves:         map[string]*actor{},
		subnets:      map[string]*actor{},
		pivots:       map[string]*actor{},
		geoFP:        map[string]*actor{},
		geoCred:      map[string]*actor{},
		profiles:     map[string]*actor{},
		tokens:       map[string]*actor{},
		crossProto:   map[string]*actor{},
		fpASN:        map[string]*actor{},
		surge:        map[string]*actor{},
		toolc:        map[string]*actor{},
		c2:           map[string]*actor{},
		uas:          map[string]*actor{},
		tactics:      map[string]*actor{},
		ports:        map[string]*actor{},
		recid:        map[string]*recidEntry{},
		sensorStats:  map[string]*sensorStat{},
		trajectories: map[string]*trajectory{},
		seenASN:      map[string]*seenEntry{},
		seenFP:       map[string]*seenEntry{},
		seenCVE:      map[string]*seenEntry{},
		srcCVEs:      map[string]*cveSet{},
		now:          time.Now,
	}
	c.portExclude = map[int]bool{}
	for _, p := range cfg.PortCampaignExclude {
		c.portExclude[p] = true
	}
	return c
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
	out = add(out, c.observeTrajectoryLocked(ev, sid, now))
	out = add(out, c.observeBurstLocked(sid, now))
	out = append(out, c.observeFirstContactLocked(ev, sid, now)...)
	out = add(out, c.observePivotLocked(ev, sid, now))
	out = append(out, c.observeGeoLocked(ev, sid, now)...)
	out = add(out, c.observeProfileLocked(ev, sid, now))
	out = add(out, c.observeHoneytokenLocked(ev, sid, now))
	out = add(out, c.observeCVEEmergenceLocked(ev, sid, now))
	out = add(out, c.observeCrossProtoLocked(ev, sid, now))
	out = append(out, c.observeFPASNLocked(ev, sid, now)...)
	out = add(out, c.observeThreatSurgeLocked(ev, sid, now))
	out = append(out, c.observeToolCampaignLocked(ev, sid, now)...)
	out = append(out, c.observeC2SharedLocked(ev, sid, now)...)
	out = add(out, c.observeUASharedLocked(ev, sid, now))
	out = append(out, c.observeTacticConvergenceLocked(ev, sid, now)...)
	out = add(out, c.observeRecidivistLocked(ev, sid, now))
	out = add(out, c.observePortCampaignLocked(ev, sid, now))
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
// thresholds are "within a window" and memory stays bounded. The novelty
// memory (seenASN/seenFP) uses the longer FirstSeenHorizon instead.
func (c *Correlator) pruneLocked(now time.Time) {
	cutoff := now.Add(-c.cfg.Window)
	for _, m := range []map[string]*actor{
		c.sources, c.asns, c.fps, c.payloads, c.creds, c.cves, c.subnets,
		c.pivots, c.geoFP, c.geoCred, c.profiles, c.tokens, c.crossProto, c.fpASN,
		c.surge, c.toolc, c.c2, c.uas, c.tactics, c.ports,
	} {
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
	for k, t := range c.trajectories {
		if t.last.Before(cutoff) {
			delete(c.trajectories, k)
		}
	}
	for k, s := range c.srcCVEs {
		if s.last.Before(cutoff) {
			delete(c.srcCVEs, k)
		}
	}
	horizon := now.Add(-c.cfg.FirstSeenHorizon)
	for _, m := range []map[string]*seenEntry{c.seenASN, c.seenFP, c.seenCVE} {
		for k, e := range m {
			if e.last.Before(horizon) {
				delete(m, k)
			}
		}
	}
	for k, e := range c.recid { // recidivist tracking is long-horizon, not windowed
		if e.last.Before(horizon) {
			delete(c.recid, k)
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
