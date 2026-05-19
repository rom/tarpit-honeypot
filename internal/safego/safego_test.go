package safego

import (
	"sync"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestRunRecoversPanic(t *testing.T) {
	before := PanicCount()
	done := make(chan struct{})
	Run("test.panic", func() {
		defer close(done)
		panic("boom")
	})
	<-done
	// Give the deferred recover a moment to run.
	time.Sleep(10 * time.Millisecond)
	if got := PanicCount(); got <= before {
		t.Errorf("PanicCount should have incremented; was %d, now %d", before, got)
	}
	byName := PanicCountByName()
	if byName["test.panic"] < 1 {
		t.Errorf("PanicCountByName missing test.panic; got %+v", byName)
	}
}

func TestRunWithEventEmitsEvent(t *testing.T) {
	bus := make(chan *event.Event, 4)
	var wg sync.WaitGroup
	wg.Add(1)
	RunWithEvent("test.bus", bus, "sensor-x", func() {
		defer wg.Done()
		panic("kaboom")
	})
	wg.Wait()
	time.Sleep(20 * time.Millisecond)
	select {
	case ev := <-bus:
		if ev.RuleID != "sensor:panic:test.bus" {
			t.Errorf("rule_id mismatch: %s", ev.RuleID)
		}
		if ev.Severity != event.SeverityHigh {
			t.Errorf("expected high severity; got %v", ev.Severity)
		}
		if ev.Meta["panic"] != "kaboom" {
			t.Errorf("panic meta mismatch: %v", ev.Meta["panic"])
		}
		if ev.Meta["goroutine"] != "test.bus" {
			t.Errorf("goroutine meta mismatch: %v", ev.Meta["goroutine"])
		}
		if _, ok := ev.Meta["stack"].(string); !ok {
			t.Errorf("stack should be a string; got %T", ev.Meta["stack"])
		}
	case <-time.After(time.Second):
		t.Fatal("no event emitted after panic")
	}
}

func TestRunSucceedsWithoutPanic(t *testing.T) {
	done := make(chan struct{})
	Run("test.noop", func() {
		close(done)
	})
	<-done
}
