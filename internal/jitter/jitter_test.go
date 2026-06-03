package jitter

import (
	"context"
	"testing"
	"time"
)

func TestJitterDisabledIsNoOp(t *testing.T) {
	if New(0, 0).Enabled() {
		t.Error("New(0,0) must be disabled")
	}
	// A nil Jitterer is a valid no-op (handlers hold *Jitterer that may be nil).
	var j *Jitterer
	if j.Enabled() {
		t.Error("nil Jitterer must report disabled")
	}
	j.Sleep(context.Background()) // must not panic
}

func TestJitterPickInRange(t *testing.T) {
	j := New(10, 20)
	if !j.Enabled() {
		t.Fatal("New(10,20) must be enabled")
	}
	for i := 0; i < 1000; i++ {
		d := j.pick()
		if d < 10*time.Millisecond || d > 20*time.Millisecond {
			t.Fatalf("pick() = %v, want within [10ms,20ms]", d)
		}
	}
}

func TestJitterMaxBelowMinNormalizes(t *testing.T) {
	// maxMS < minMS is clamped to minMS (a fixed delay), never negative.
	j := New(30, 10)
	if d := j.pick(); d != 30*time.Millisecond {
		t.Errorf("pick() = %v, want 30ms (clamped)", d)
	}
}

func TestJitterSleepHonorsContext(t *testing.T) {
	// A long jitter must return promptly when the context is already cancelled.
	j := New(5000, 5000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	j.Sleep(ctx)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Sleep ignored cancelled context (took %v)", elapsed)
	}
}
