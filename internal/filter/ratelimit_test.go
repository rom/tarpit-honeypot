package filter

import (
	"testing"
	"time"
)

func TestRateLimiterAllowsBurst(t *testing.T) {
	r := NewRateLimiter(60) // 60/min, burst 60
	for i := 0; i < 60; i++ {
		if !r.Allow() {
			t.Fatalf("burst should permit 60 calls; failed at %d", i)
		}
	}
	if r.Allow() {
		t.Fatal("61st call should be denied")
	}
}

func TestRateLimiterRefills(t *testing.T) {
	r := NewRateLimiter(600) // 600/min = 10/s, burst 600
	for i := 0; i < 600; i++ {
		r.Allow()
	}
	if r.Allow() {
		t.Fatal("expected exhausted bucket")
	}
	time.Sleep(150 * time.Millisecond) // refills ~1.5 tokens
	if !r.Allow() {
		t.Fatal("expected refill after sleep")
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	r := NewRateLimiter(0)
	for i := 0; i < 1000; i++ {
		if !r.Allow() {
			t.Fatalf("rate limit 0 should always allow (iter %d)", i)
		}
	}
}
