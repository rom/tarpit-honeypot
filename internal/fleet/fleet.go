// Package fleet is the cross-sensor correlator that runs on an aggregator over
// the merged event stream (local + ingested). A single sensor only ever sees
// one vantage point; once events from many sensors converge, patterns invisible
// to any one node emerge — the same source IP, the same AS, or the same TLS/SSH
// fingerprint hammering multiple honeypots at once. This correlator keys events
// by attacker identity, tracks the distinct sensors (and, for fingerprints, the
// distinct sources) each identity touches within a window, and emits a
// high-severity fleet:* event the first time an identity crosses the configured
// breadth threshold.
package fleet

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Config tunes the breadth thresholds and the observation window.
type Config struct {
	Enabled       bool
	Window        time.Duration // how long an identity's activity is remembered
	SourceSensors int           // one source IP on >= N sensors -> alert
	ASNSensors    int           // one ASN on >= N sensors -> alert
	FPSensors     int           // one fingerprint on >= N sensors ...
	FPSources     int           // ... and >= M distinct sources -> alert (botnet/tool family)
	MaxList       int           // cap the sensor/source list in alert meta
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
	if c.MaxList <= 0 {
		c.MaxList = 50
	}
}

type actor struct {
	sensors map[string]struct{}
	sources map[string]struct{} // populated for fingerprint actors only
	last    time.Time
	fired   bool
}

func newActor() *actor {
	return &actor{sensors: map[string]struct{}{}, sources: map[string]struct{}{}}
}

// Correlator holds the windowed per-identity state. Safe for concurrent use.
type Correlator struct {
	cfg     Config
	mu      sync.Mutex
	sources map[string]*actor // key: source IP
	asns    map[string]*actor // key: ASN
	fps     map[string]*actor // key: "<kind>:<value>" (ja3/ja4/hassh)
	now     func() time.Time  // overridable in tests
}

// New builds a correlator. Returns nil when disabled so callers can no-op.
func New(cfg Config) *Correlator {
	if !cfg.Enabled {
		return nil
	}
	cfg.withDefaults()
	return &Correlator{
		cfg: cfg, sources: map[string]*actor{}, asns: map[string]*actor{}, fps: map[string]*actor{},
		now: time.Now,
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
	var out []*event.Event

	// One source IP across many sensors = a single attacker sweeping the fleet.
	if a := touch(c.sources, ev.Source.IP, sid, "", now); !a.fired && len(a.sensors) >= c.cfg.SourceSensors {
		a.fired = true
		out = append(out, c.alert(ev, "fleet:source-multi-sensor", map[string]any{
			"source": ev.Source.IP, "asn": metaStr(ev, "asn"),
			"sensor_count": len(a.sensors), "sensors": c.list(a.sensors),
		}))
	}

	// One ASN across many sensors = coordinated / distributed from one network.
	if asn := metaStr(ev, "asn"); asn != "" {
		if a := touch(c.asns, asn, sid, "", now); !a.fired && len(a.sensors) >= c.cfg.ASNSensors {
			a.fired = true
			out = append(out, c.alert(ev, "fleet:asn-multi-sensor", map[string]any{
				"asn": asn, "asn_org": metaStr(ev, "asn_org"),
				"sensor_count": len(a.sensors), "sensors": c.list(a.sensors),
			}))
		}
	}

	// One fingerprint across many sensors AND many sources = a shared toolkit /
	// botnet (the IPs differ but the client stack is identical).
	for _, kind := range []string{"ja3", "ja4", "hassh"} {
		v := metaStr(ev, kind)
		if v == "" {
			continue
		}
		a := touch(c.fps, kind+":"+v, sid, ev.Source.IP, now)
		if !a.fired && len(a.sensors) >= c.cfg.FPSensors && len(a.sources) >= c.cfg.FPSources {
			a.fired = true
			out = append(out, c.alert(ev, "fleet:fingerprint-shared", map[string]any{
				"fingerprint": kind + ":" + v, "sensor_count": len(a.sensors),
				"source_count": len(a.sources), "sensors": c.list(a.sensors),
			}))
		}
	}
	return out
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

// pruneLocked drops identities idle longer than the window so thresholds are
// "within a window" and memory stays bounded.
func (c *Correlator) pruneLocked(now time.Time) {
	cutoff := now.Add(-c.cfg.Window)
	for _, m := range []map[string]*actor{c.sources, c.asns, c.fps} {
		for k, a := range m {
			if a.last.Before(cutoff) {
				delete(m, k)
			}
		}
	}
}

func (c *Correlator) alert(trigger *event.Event, ruleID string, meta map[string]any) *event.Event {
	meta["window"] = c.cfg.Window.String()
	return &event.Event{
		ID:       event.NewID(),
		Time:     c.now(),
		RuleID:   ruleID,
		Severity: event.SeverityHigh,
		Source:   trigger.Source, // the triggering source, so it correlates by IP
		Meta:     meta,
	}
}

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

func metaStr(ev *event.Event, key string) string {
	if ev.Meta == nil {
		return ""
	}
	s, _ := ev.Meta[key].(string)
	return s
}
