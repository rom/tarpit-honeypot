package filter

import (
	"sync"
	"time"
)

// RateLimiter is a simple per-key token bucket: 'perMin' tokens per minute
// with a burst of perMin. Used per channel.
type RateLimiter struct {
	perMin int
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func NewRateLimiter(perMin int) *RateLimiter {
	if perMin <= 0 {
		return nil
	}
	return &RateLimiter{
		perMin: perMin,
		tokens: float64(perMin),
		last:   time.Now(),
	}
}

func (r *RateLimiter) Allow() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(r.last).Seconds()
	r.tokens += elapsed * float64(r.perMin) / 60.0
	if r.tokens > float64(r.perMin) {
		r.tokens = float64(r.perMin)
	}
	r.last = now
	if r.tokens < 1 {
		return false
	}
	r.tokens -= 1
	return true
}
