// Package trust scores the health of each child sensor's stream at an
// aggregator's ingest endpoint. Ingest is authenticated, but a shared token
// can't tell a healthy node from a misconfigured or compromised one that
// fabricates events. The scorer keeps per-sensor windowed counters (accepted /
// deduped / dropped / malformed), derives a 0..1 trust score, raises a
// fleet:sensor-untrusted alert when a node's score falls, and — when
// configured — quarantines a node (refuses its events) until its window rolls.
// It also enforces an optional per-sensor admission rate, so one flooding node
// can't overwhelm the store. Behavioural, not cryptographic: it catches the
// stream that *looks* fabricated.
package trust

import (
	"sync"
	"time"
)

// Outcome is what happened to one ingested event.
type Outcome int

const (
	Accepted  Outcome = iota // admitted to the bus
	Deduped                  // sensor_id:id already seen
	Dropped                  // loop/hop guard, rate limit, or quarantine
	Malformed                // missing/invalid required fields
)

// Config tunes the scorer. Zero values fall back to defaults.
type Config struct {
	Enabled         bool
	Window          time.Duration // counter window (default 5m)
	MinEvents       int           // min volume before scoring/alerting (default 50)
	AlertBelow      float64       // raise fleet:sensor-untrusted below this score (default 0.5; 0 = off)
	QuarantineBelow float64       // refuse a sensor below this score (default 0 = never)
	RatePerSec      int           // per-sensor admission cap (0 = unlimited)
	Burst           int           // token-bucket burst (default = RatePerSec)
	// MaxSensors caps how many distinct sensor_ids we keep state for, so a
	// peer spraying spoofed ids can't grow the map without bound. Idle entries
	// (windowStart older than 2*Window) are evicted on demand; if every slot
	// is active a new sensor's events are refused. Default 4096.
	MaxSensors int
}

func (c *Config) withDefaults() {
	if c.Window <= 0 {
		c.Window = 5 * time.Minute
	}
	if c.MinEvents <= 0 {
		c.MinEvents = 50
	}
	if c.AlertBelow == 0 {
		c.AlertBelow = 0.5
	}
	if c.Burst <= 0 {
		c.Burst = c.RatePerSec
	}
	if c.MaxSensors <= 0 {
		c.MaxSensors = 4096
	}
}

// Alert is emitted once per window when a sensor's score crosses AlertBelow.
type Alert struct {
	Sensor      string
	Score       float64
	Accepted    int
	Deduped     int
	Dropped     int
	Malformed   int
	Quarantined bool
}

type stat struct {
	accepted, deduped, dropped, malformed int
	windowStart                           time.Time
	alerted                               bool
	quarantined                           bool
	tokens                                float64
	lastFill                              time.Time
}

// Scorer holds per-sensor trust state. Safe for concurrent use.
type Scorer struct {
	cfg     Config
	mu      sync.Mutex
	sensors map[string]*stat
	now     func() time.Time
}

// New builds a scorer, or nil when disabled (callers no-op on nil).
func New(cfg Config) *Scorer {
	if !cfg.Enabled {
		return nil
	}
	cfg.withDefaults()
	return &Scorer{cfg: cfg, sensors: map[string]*stat{}, now: time.Now}
}

// getLocked returns the stat for sid, creating one if absent. Returns nil
// when admitting a brand-new sensor would push the map past MaxSensors and no
// idle slot is available to evict — i.e. memory protection trumps tracking the
// extra sensor. The caller treats nil as "refuse" (Admit→false, Observe→nop).
func (s *Scorer) getLocked(sid string, now time.Time) *stat {
	if st := s.sensors[sid]; st != nil {
		// Roll the window: reset counters and clear the alert/quarantine flags
		// so a recovered sensor is re-evaluated fresh (quarantine is not
		// permanent).
		if now.Sub(st.windowStart) > s.cfg.Window {
			st.accepted, st.deduped, st.dropped, st.malformed = 0, 0, 0, 0
			st.windowStart = now
			st.alerted = false
			st.quarantined = false
		}
		return st
	}
	if len(s.sensors) >= s.cfg.MaxSensors {
		// Evict any sensor whose window has rolled past 2*Window — it has been
		// idle for at least a full window and can be safely forgotten. Capped
		// at a small batch so the eviction cost stays bounded.
		threshold := now.Add(-2 * s.cfg.Window)
		evicted := 0
		for k, st := range s.sensors {
			if st.windowStart.Before(threshold) {
				delete(s.sensors, k)
				evicted++
				if evicted >= 16 {
					break
				}
			}
		}
		if len(s.sensors) >= s.cfg.MaxSensors {
			return nil
		}
	}
	st := &stat{windowStart: now, lastFill: now, tokens: float64(s.cfg.Burst)}
	s.sensors[sid] = st
	return st
}

// Admit reports whether a sensor's event may be admitted: false when the sensor
// is quarantined, has exhausted its per-sensor rate, or when the scorer is at
// MaxSensors and can't evict to make room. nil scorer admits all.
func (s *Scorer) Admit(sid string) bool {
	if s == nil {
		return true
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.getLocked(sid, now)
	if st == nil {
		return false // scorer is full; refuse rather than grow unbounded
	}
	if st.quarantined {
		return false
	}
	if s.cfg.RatePerSec <= 0 {
		return true
	}
	// Token bucket: refill at RatePerSec up to Burst.
	elapsed := now.Sub(st.lastFill).Seconds()
	st.lastFill = now
	st.tokens += elapsed * float64(s.cfg.RatePerSec)
	if st.tokens > float64(s.cfg.Burst) {
		st.tokens = float64(s.cfg.Burst)
	}
	if st.tokens >= 1 {
		st.tokens--
		return true
	}
	return false
}

// Observe records one event outcome for a sensor and returns an Alert the first
// time this window the sensor's score falls below AlertBelow. nil scorer no-ops;
// also a no-op when the per-sensor cap is full (the event was already refused
// by Admit, and we don't grow the map to score it).
func (s *Scorer) Observe(sid string, o Outcome) *Alert {
	if s == nil {
		return nil
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.getLocked(sid, now)
	if st == nil {
		return nil
	}
	switch o {
	case Accepted:
		st.accepted++
	case Deduped:
		st.deduped++
	case Dropped:
		st.dropped++
	case Malformed:
		st.malformed++
	}
	total := st.accepted + st.deduped + st.dropped + st.malformed
	if total < s.cfg.MinEvents {
		return nil
	}
	sc := scoreOf(st)
	if s.cfg.QuarantineBelow > 0 && sc < s.cfg.QuarantineBelow {
		st.quarantined = true
	}
	if sc < s.cfg.AlertBelow && !st.alerted {
		st.alerted = true
		return &Alert{
			Sensor: sid, Score: sc,
			Accepted: st.accepted, Deduped: st.deduped, Dropped: st.dropped,
			Malformed: st.malformed, Quarantined: st.quarantined,
		}
	}
	return nil
}

// Score returns a sensor's current trust score (1 = unknown/healthy).
func (s *Scorer) Score(sid string) float64 {
	if s == nil {
		return 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.sensors[sid]
	if st == nil {
		return 1
	}
	return scoreOf(st)
}

// scoreOf weights sensor-attributable badness: malformed events are the
// strongest fabrication signal, loop/quarantine drops next, dedup mild.
func scoreOf(st *stat) float64 {
	bad := float64(st.malformed)*3 + float64(st.dropped)*1 + float64(st.deduped)*0.25
	good := float64(st.accepted)
	if good+bad == 0 {
		return 1
	}
	return good / (good + bad)
}
