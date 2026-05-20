// Package safego runs goroutines with a recover() guard so a panic in a
// protocol parser, a handler goroutine, a canary watcher, the bus loop,
// or any other long-running task can't take down the whole sensor.
//
// Two flavors:
//
//	safego.Run(name, fn)                — fire-and-forget
//	safego.RunWithEvent(name, bus, fn)  — same, but emits a tarpit
//	                                       panic:<name> event on the
//	                                       bus so the operator sees it
//	                                       in the regular sink path.
//
// The recover handler logs the panic value + a goroutine stack trace at
// error level and increments a process-wide counter retrievable via
// PanicCount(). The web UI's /metrics endpoint exposes that as the
// tarpit_handler_panic_total{name=...} counter.
package safego

import (
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

var (
	totalPanics atomic.Int64
	byName      sync.Map // map[string]*atomic.Int64
)

// Run starts fn in a new goroutine with a recover guard. The name is
// used in log messages and metrics — keep it short and stable (e.g.
// "listener.tcp.handle", "router.worker", "sensor.bus_loop").
func Run(name string, fn func()) {
	go runWithRecover(name, nil, fn)
}

// RunWithEvent is the bus-aware variant. On panic, in addition to the
// log + counter, a synthetic event is sent to `bus` so downstream sinks
// pick up the panic as a regular high-severity record.
func RunWithEvent(name string, bus chan<- *event.Event, sensorName string, fn func()) {
	go runWithRecover(name, &eventSink{bus: bus, sensor: sensorName}, fn)
}

type eventSink struct {
	bus    chan<- *event.Event
	sensor string
}

func (e *eventSink) emit(name string, panicVal any, stack []byte) {
	if e == nil || e.bus == nil {
		return
	}
	ev := &event.Event{
		ID:       event.NewID(),
		Time:     time.Now().UTC(),
		Sensor:   e.sensor,
		RuleID:   "sensor:panic:" + name,
		Severity: event.SeverityHigh,
		Meta: map[string]any{
			"goroutine": name,
			"panic":     truncate(stringify(panicVal), 4096),
			"stack":     truncate(string(stack), 32768),
		},
	}
	select {
	case e.bus <- ev:
	default:
		// bus full — drop the event but the log + counter still capture it.
	}
}

func runWithRecover(name string, sink *eventSink, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			totalPanics.Add(1)
			counter, _ := byName.LoadOrStore(name, new(atomic.Int64))
			counter.(*atomic.Int64).Add(1)
			slog.Error("goroutine panic recovered",
				"name", name,
				"panic", r,
				"stack", string(stack),
			)
			if sink != nil {
				sink.emit(name, r, stack)
			}
		}
	}()
	fn()
}

// PanicCount returns the total number of recovered panics since process
// start. Used by the metrics endpoint.
func PanicCount() int64 { return totalPanics.Load() }

// PanicCountByName returns a snapshot of panic counters keyed by the
// name argument that was passed to Run / RunWithEvent.
func PanicCountByName() map[string]int64 {
	out := map[string]int64{}
	byName.Range(func(k, v any) bool {
		out[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	return out
}

func stringify(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return slog.AnyValue(v).String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
