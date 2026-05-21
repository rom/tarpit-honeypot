package filter

import (
	"sync"
	"time"
)

// Dedup collapses identical (key) events seen within the configured window.
// Key is opaque to the dedup; the router supplies (source, rule) typically.
type Dedup struct {
	window time.Duration
	mu     sync.Mutex
	seen   map[string]time.Time
}

func NewDedup(window time.Duration) *Dedup {
	return &Dedup{window: window, seen: map[string]time.Time{}}
}

// ShouldSend returns true if this key has not been seen within the window.
// Calling ShouldSend records the timestamp regardless, so two rapid calls
// will return true then false.
func (d *Dedup) ShouldSend(key string) bool {
	if d == nil || d.window <= 0 {
		return true
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.seen[key]; ok && now.Sub(t) < d.window {
		return false
	}
	d.seen[key] = now
	// Opportunistic prune of expired entries.
	if len(d.seen) > 4096 {
		for k, t := range d.seen {
			if now.Sub(t) >= d.window {
				delete(d.seen, k)
			}
		}
		// Hard cap: a flood of unique keys (e.g. spoofed UDP source IPs)
		// produces unexpired entries the prune above can't remove. Bound
		// the map by resetting it — dedup is best-effort, so the worst case
		// is a few duplicate events slipping through, never unbounded memory.
		if len(d.seen) > dedupMaxKeys {
			d.seen = map[string]time.Time{key: now}
		}
	}
	return true
}

// dedupMaxKeys hard-caps the dedup table so an attacker can't grow it
// without bound by sending many unique (source, rule) keys inside the
// window.
const dedupMaxKeys = 65536
