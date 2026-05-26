package sensor

import (
	"math"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/trust"
)

// ttlSet is a bounded time-expiring set, used to dedup forwarded events by
// sensor_id:id within a window so a fan-out / multi-path topology can't double
// count an event at an aggregator.
type ttlSet struct {
	mu  sync.Mutex
	m   map[string]int64 // key -> expiry (unix nanos)
	ttl time.Duration
}

func newTTLSet(ttl time.Duration) *ttlSet {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &ttlSet{m: map[string]int64{}, ttl: ttl}
}

// addIfNew records key and returns true if it wasn't already present (and
// unexpired). Lazily prunes when the set grows large.
func (s *ttlSet) addIfNew(key string) bool {
	now := time.Now().UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, ok := s.m[key]; ok && exp > now {
		return false
	}
	if len(s.m) > 200000 {
		for k, e := range s.m {
			if e <= now {
				delete(s.m, k)
			}
		}
	}
	s.m[key] = now + int64(s.ttl)
	return true
}

// IngestBatch admits events forwarded by child nodes into this node's pipeline.
// It drops loops (an event whose hop chain already includes this node, or that
// has traversed more than the configured cap) and duplicates (sensor_id:id seen
// within the dedup window), then pushes the rest onto the bus — so a forwarded
// event is stored, correlated, and (when this node also has forward: targets)
// relayed upward, exactly like a locally-observed one. Returns per-batch counts.
func (s *Sensor) IngestBatch(evs []*event.Event) (accepted, deduped, dropped int) {
	me := s.identity.Seed()
	now := timeNow()
	var alerts []*event.Event
	note := func(a *trust.Alert) {
		if a != nil {
			alerts = append(alerts, s.trustAlert(a))
		}
	}
	for _, ev := range evs {
		if ev == nil {
			continue
		}
		// A malformed event (no sensor_id/id, bad severity, fabricated future
		// timestamp) is the strongest "this stream is fabricated" signal — drop
		// it and penalise the sender's trust hard.
		if malformedEvent(ev, now) {
			note(s.trust.Observe(ev.SensorID, trust.Malformed))
			dropped++
			continue
		}
		// Admission control: a quarantined or rate-exceeded sensor is refused
		// before it can touch the dedup set or the bus.
		if !s.trust.Admit(ev.SensorID) {
			note(s.trust.Observe(ev.SensorID, trust.Dropped))
			dropped++
			continue
		}
		if len(ev.Hops) > s.ingestMaxHops || hopsContain(ev.Hops, me) {
			note(s.trust.Observe(ev.SensorID, trust.Dropped))
			dropped++
			continue
		}
		key := ev.SensorID + ":" + ev.ID
		if !s.ingestSeen.addIfNew(key) {
			note(s.trust.Observe(ev.SensorID, trust.Deduped))
			deduped++
			continue
		}
		select {
		case s.bus <- ev:
			accepted++
			note(s.trust.Observe(ev.SensorID, trust.Accepted))
		default:
			dropped++ // bus saturated: our overload, not the sensor's fault — unscored
		}
	}
	// Push any trust alerts onto the bus (non-blocking) so they're stored,
	// routed, and can forward upward like any other fleet:* finding.
	for _, a := range alerts {
		select {
		case s.bus <- a:
		default:
		}
	}
	return accepted, deduped, dropped
}

// malformedEvent flags an ingested event that can't be trusted as a real,
// well-formed observation: missing the fleet dedup keys, an out-of-range
// severity, or a timestamp implausibly far in the future (fabricated / clock
// abuse). A zero timestamp is tolerated (older/hand-crafted events).
func malformedEvent(ev *event.Event, now time.Time) bool {
	if ev.ID == "" || ev.SensorID == "" {
		return true
	}
	// Severity 0 means "absent" (tolerated); anything outside the real 1..4
	// range is garbage.
	if ev.Severity < 0 || ev.Severity > event.SeverityCritical {
		return true
	}
	// Tolerate up to an hour of clock skew between forwarder and aggregator;
	// anything further forward is treated as fabricated (an attacker could
	// otherwise dodge time-windowed correlation by post-dating).
	if !ev.Time.IsZero() && ev.Time.After(now.Add(time.Hour)) {
		return true
	}
	return false
}

// trustAlert builds the fleet:sensor-untrusted event for a low-trust sensor.
func (s *Sensor) trustAlert(a *trust.Alert) *event.Event {
	return &event.Event{
		ID:       event.NewID(),
		Time:     timeNow(),
		Sensor:   s.name,
		SensorID: s.identity.Seed(),
		RuleID:   "fleet:sensor-untrusted",
		Severity: event.SeverityHigh,
		Meta: map[string]any{
			"sensor": a.Sensor, "score": math.Round(a.Score*100) / 100,
			"accepted": a.Accepted, "deduped": a.Deduped,
			"dropped": a.Dropped, "malformed": a.Malformed,
			"quarantined": a.Quarantined,
		},
	}
}

func hopsContain(hops []string, id string) bool {
	for _, h := range hops {
		if h == id {
			return true
		}
	}
	return false
}
