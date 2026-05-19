// Package jitter adds randomized response delays so the honeypot doesn't
// emit identical-microsecond replies that scanners can fingerprint on.
//
// Two delay knobs: the per-write Sleep (called by handlers between writes)
// and the per-connection BannerDelay (applied once on the initial banner
// so even a single-shot scan sees variable RTT).
package jitter

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// Jitterer holds the configured min/max delays and a random source.
// Zero value means jitter is disabled (Sleep is a no-op).
type Jitterer struct {
	enabled  bool
	min, max time.Duration

	mu   sync.Mutex
	rand *rand.Rand
}

// New returns a Jitterer with min..max millisecond delay. minMS=maxMS=0
// returns a no-op jitterer.
func New(minMS, maxMS int) *Jitterer {
	if minMS <= 0 && maxMS <= 0 {
		return &Jitterer{}
	}
	if maxMS < minMS {
		maxMS = minMS
	}
	return &Jitterer{
		enabled: true,
		min:     time.Duration(minMS) * time.Millisecond,
		max:     time.Duration(maxMS) * time.Millisecond,
		rand:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Enabled reports whether the jitterer will actually sleep.
func (j *Jitterer) Enabled() bool { return j != nil && j.enabled }

// Sleep waits a random duration in [min, max]. Honors ctx cancellation;
// returns early if ctx is done.
func (j *Jitterer) Sleep(ctx context.Context) {
	if !j.Enabled() {
		return
	}
	d := j.pick()
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// pick returns a uniformly random duration in the [min, max] range.
func (j *Jitterer) pick() time.Duration {
	j.mu.Lock()
	defer j.mu.Unlock()
	span := j.max - j.min
	if span <= 0 {
		return j.min
	}
	return j.min + time.Duration(j.rand.Int63n(int64(span)))
}
