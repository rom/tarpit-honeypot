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
	// Opportunistic prune.
	if len(d.seen) > 4096 {
		for k, t := range d.seen {
			if now.Sub(t) >= d.window {
				delete(d.seen, k)
			}
		}
	}
	return true
}
