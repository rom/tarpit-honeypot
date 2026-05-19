// Package correlate maintains short-lived in-memory state across events to
// detect port-scans and brute-force attempts from a single source.
//
// Each call to Observe returns the original event plus any aggregate events
// that fired as a result. v0.1 of this package is single-threaded behind a
// per-source mutex; that's fine for typical sensor volumes. A later phase
// may want to shard or move counters into a streaming structure.
package correlate

import (
	"strconv"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

type Correlator struct {
	cfg       config.Correlate
	scanSev   event.Severity
	bruteSev  event.Severity

	mu     sync.Mutex
	scan   map[string]*scanState   // key: source IP
	brute  map[string]*bruteState  // key: source IP (+ ":<port>" if PerPort)

	// dedup of aggregate events so a sustained scan/brute doesn't spam.
	emitted map[string]time.Time
}

type scanState struct {
	since time.Time
	ports map[int]struct{}
}

type bruteState struct {
	since time.Time
	count int
}

func New(cfg config.Correlate) (*Correlator, error) {
	c := &Correlator{
		cfg:     cfg,
		scan:    map[string]*scanState{},
		brute:   map[string]*bruteState{},
		emitted: map[string]time.Time{},
	}
	if cfg.PortScan.Enabled {
		s, err := event.ParseSeverity(cfg.PortScan.Severity)
		if err != nil {
			return nil, err
		}
		c.scanSev = s
	}
	if cfg.BruteForce.Enabled {
		s, err := event.ParseSeverity(cfg.BruteForce.Severity)
		if err != nil {
			return nil, err
		}
		c.bruteSev = s
	}
	return c, nil
}

// Observe ingests an event and returns it plus any aggregate events that
// fired. Always returns at least one event (the original).
func (c *Correlator) Observe(ev *event.Event) []*event.Event {
	out := []*event.Event{ev}

	// Only correlate network listener events.
	if ev.Source.IP == "" || ev.Dest.Port == 0 {
		return out
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := ev.Time
	if now.IsZero() {
		now = time.Now().UTC()
	}

	if c.cfg.PortScan.Enabled {
		if extra := c.checkScan(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.BruteForce.Enabled {
		if extra := c.checkBrute(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	return out
}

func (c *Correlator) checkScan(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.PortScan
	st, ok := c.scan[ev.Source.IP]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &scanState{since: now, ports: map[int]struct{}{}}
		c.scan[ev.Source.IP] = st
	}
	st.ports[ev.Dest.Port] = struct{}{}
	if len(st.ports) < cfg.DistinctPorts {
		return nil
	}
	if !c.shouldEmit("scan|" + ev.Source.IP, cfg.Window) {
		return nil
	}
	ports := make([]int, 0, len(st.ports))
	for p := range st.ports {
		ports = append(ports, p)
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:port_scan",
		Severity: c.scanSev,
		Source:   ev.Source,
		Proto:    "tcp",
		Meta: map[string]any{
			"distinct_ports": len(ports),
			"window_s":       int(cfg.Window.Seconds()),
			"ports":          ports,
		},
	}
}

func (c *Correlator) checkBrute(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.BruteForce
	key := ev.Source.IP
	if cfg.PerPort {
		key += ":" + strconv.Itoa(ev.Dest.Port)
	}
	st, ok := c.brute[key]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &bruteState{since: now}
		c.brute[key] = st
	}
	st.count++
	if st.count < cfg.Attempts {
		return nil
	}
	if !c.shouldEmit("brute|"+key, cfg.Window) {
		return nil
	}
	meta := map[string]any{
		"attempts": st.count,
		"window_s": int(cfg.Window.Seconds()),
	}
	if cfg.PerPort {
		meta["port"] = ev.Dest.Port
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:brute_force",
		Severity: c.bruteSev,
		Source:   ev.Source,
		Dest:     ev.Dest,
		Proto:    ev.Proto,
		Meta:     meta,
	}
}

// shouldEmit collapses repeated aggregate events for the same key within
// the window so a sustained scan doesn't flood the sinks.
func (c *Correlator) shouldEmit(key string, window time.Duration) bool {
	now := time.Now()
	if t, ok := c.emitted[key]; ok && now.Sub(t) < window {
		return false
	}
	c.emitted[key] = now
	return true
}
