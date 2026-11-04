// Package fastpath is the sensor's L3/L4 DoS-resistance front: a cheap
// per-source admission gate consulted at accept time, before a connection is
// allowed to spend a handler goroutine, so a connection flood from a small set
// of sources is shed early instead of exhausting workers, memory or the event
// bus.
//
// It has two tiers behind one FastPath interface:
//
//   - a pure-Go per-source token-bucket Shaper (this file) that works on every
//     platform with no privileges — the default, and the tier exercised by
//     tests; and
//   - an optional in-kernel eBPF/XDP program (xdp_linux.go, built only with the
//     `tarpit_xdp` tag on Linux) that drops abusive packets at the NIC driver
//     before they ever reach the socket, for line-rate resistance. The kernel
//     tier shares the Shaper's drop decisions through a BPF map; see
//     docs/xdp-fastpath.md. The XDP object is NOT compiled or loaded in a
//     normal build — the default build is the userspace Shaper.
package fastpath

import (
	"sync"
	"time"
)

// Config tunes the per-source token bucket. Zero values use the defaults.
type Config struct {
	// PerSourcePPS is the sustained new-connection rate allowed per source IP.
	PerSourcePPS float64
	// Burst is the bucket depth — the instantaneous burst a source may make
	// before it is rate-limited. Defaults to max(PerSourcePPS, 20).
	Burst float64
	// MaxSources bounds the tracked-source table (LRU-evicted) so the gate's
	// own memory can't be driven up by a spoofed-source flood. Default 65536.
	MaxSources int
	now        func() time.Time
}

func (c *Config) withDefaults() {
	if c.PerSourcePPS <= 0 {
		c.PerSourcePPS = 20
	}
	if c.Burst <= 0 {
		c.Burst = c.PerSourcePPS
		if c.Burst < 20 {
			c.Burst = 20
		}
	}
	if c.MaxSources <= 0 {
		c.MaxSources = 65536
	}
	if c.now == nil {
		c.now = time.Now
	}
}

// Stats is a snapshot of the gate's counters.
type Stats struct {
	Admitted uint64
	Shed     uint64
	Blocked  uint64
	Tracked  int
}

type bucket struct {
	tokens float64
	last   time.Time
	seen   time.Time
}

// Shaper is a concurrency-safe per-source token-bucket admission gate.
type Shaper struct {
	cfg Config
	mu  sync.Mutex
	src map[string]*bucket
	// drop is an O(1) hard drop-set (e.g. fed from the blocklist / risk
	// blocker): a source here is refused regardless of its token bucket.
	drop     map[string]struct{}
	admitted uint64
	shed     uint64
	blocked  uint64
}

// NewShaper builds a Shaper.
func NewShaper(cfg Config) *Shaper {
	cfg.withDefaults()
	return &Shaper{cfg: cfg, src: make(map[string]*bucket), drop: map[string]struct{}{}}
}

// Admit reports whether a new connection from ip may proceed. A source in the
// hard drop-set is always refused; otherwise one token is charged against its
// per-source bucket, refilled at PerSourcePPS up to Burst.
func (s *Shaper) Admit(ip string) bool {
	if ip == "" {
		return true // can't rate-limit an unknown source; don't shed blindly
	}
	now := s.cfg.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, bad := s.drop[ip]; bad {
		s.blocked++
		return false
	}
	b := s.src[ip]
	if b == nil {
		if len(s.src) >= s.cfg.MaxSources {
			s.evictOldestLocked(now)
		}
		b = &bucket{tokens: s.cfg.Burst, last: now}
		s.src[ip] = b
	}
	// Refill.
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * s.cfg.PerSourcePPS
		if b.tokens > s.cfg.Burst {
			b.tokens = s.cfg.Burst
		}
		b.last = now
	}
	b.seen = now
	if b.tokens >= 1 {
		b.tokens--
		s.admitted++
		return true
	}
	s.shed++
	return false
}

// Block adds ips to the hard drop-set (admitted O(1) refusals). SetBlocklist
// replaces the whole set — wire it to the risk blocker / blocklist feed.
func (s *Shaper) Block(ips ...string) {
	s.mu.Lock()
	for _, ip := range ips {
		if ip != "" {
			s.drop[ip] = struct{}{}
		}
	}
	s.mu.Unlock()
}

// SetBlocklist replaces the drop-set atomically.
func (s *Shaper) SetBlocklist(ips []string) {
	m := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if ip != "" {
			m[ip] = struct{}{}
		}
	}
	s.mu.Lock()
	s.drop = m
	s.mu.Unlock()
}

// Stats returns a counter snapshot.
func (s *Shaper) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{Admitted: s.admitted, Shed: s.shed, Blocked: s.blocked, Tracked: len(s.src)}
}

// evictOldestLocked drops the least-recently-seen source so the table stays
// bounded under a spoofed-source flood. Caller holds the lock.
func (s *Shaper) evictOldestLocked(now time.Time) {
	var oldestIP string
	var oldest time.Time
	first := true
	for ip, b := range s.src {
		if first || b.seen.Before(oldest) {
			oldestIP, oldest, first = ip, b.seen, false
		}
	}
	if oldestIP != "" {
		delete(s.src, oldestIP)
	}
}
