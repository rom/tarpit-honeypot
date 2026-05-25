package sensor

import (
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
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
	for _, ev := range evs {
		if ev == nil {
			continue
		}
		if len(ev.Hops) > s.ingestMaxHops || hopsContain(ev.Hops, me) {
			dropped++
			continue
		}
		key := ev.SensorID + ":" + ev.ID
		if !s.ingestSeen.addIfNew(key) {
			deduped++
			continue
		}
		select {
		case s.bus <- ev:
			accepted++
		default:
			dropped++ // bus saturated: shed rather than block the ingest handler
		}
	}
	return accepted, deduped, dropped
}

func hopsContain(hops []string, id string) bool {
	for _, h := range hops {
		if h == id {
			return true
		}
	}
	return false
}
