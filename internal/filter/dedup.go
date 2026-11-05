package filter

import (
	"sync"
	"time"
)

// Dedup collapses identical (key) events seen within the configured window.
// Key is opaque to the dedup; the router supplies (source, rule) typically.
type Dedup struct {
	window    time.Duration
	mu        sync.Mutex
	seen      map[string]time.Time
	lastPrune time.Time // throttles the O(n) expiry sweep
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
	if len(d.seen) > dedupPruneThreshold {
		// Throttle the O(n) expiry sweep. Once the table is hot it stays above
		// the threshold, so sweeping on every call made dedup O(n) per event on
		// a busy sensor. The per-key `now.Sub(t) < window` check above is
		// authoritative, so a not-yet-swept expired entry never causes a false
		// dedup — the sweep only reclaims memory, and reclaiming at most once per
		// window loses nothing (nothing new expires faster than that).
		if now.Sub(d.lastPrune) >= d.window {
			d.lastPrune = now
			for k, t := range d.seen {
				if now.Sub(t) >= d.window {
					delete(d.seen, k)
				}
			}
		}
		// Hard cap: a flood of unique keys (e.g. spoofed UDP source IPs)
		// produces unexpired entries the throttled sweep can't remove. Checked
		// on every call (O(1)) so memory stays bounded between sweeps — dedup is
		// best-effort, so the worst case is a few duplicate events slipping
		// through, never unbounded memory.
		if len(d.seen) > dedupMaxKeys {
			d.seen = map[string]time.Time{key: now}
		}
	}
	return true
}

// dedupPruneThreshold is the table size above which the expiry sweep + hard-cap
// guard engage. Below it the table is small enough to leave alone.
const dedupPruneThreshold = 4096

// dedupMaxKeys hard-caps the dedup table so an attacker can't grow it
// without bound by sending many unique (source, rule) keys inside the
// window.
const dedupMaxKeys = 65536
