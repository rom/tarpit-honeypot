package router

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/filter"
	"github.com/rom/tarpit-honeypot/internal/mitre"
	"github.com/rom/tarpit-honeypot/internal/sink"
)

const (
	sinkQueueDepth   = 256
	sinkSendTimeout  = 10 * time.Second
	maxRetryBacklog  = 64
	initialRetryWait = 1 * time.Second
	maxRetryWait     = 60 * time.Second
)

type worker struct {
	sink    sink.Sink
	in      chan *event.Event
	rl      *filter.RateLimiter
	minSev  event.Severity
	isLocal bool
	dropped atomic.Int64 // events dropped because the in-channel was full
	failed  atomic.Int64 // events that failed Send (after retry exhaustion)
	retried atomic.Int64 // events successfully delivered on retry
}

type Router struct {
	workers map[string]*worker
	routes  []config.Route
	dedup   *filter.Dedup
	allow   *filter.Allowlist
	wg      sync.WaitGroup
}

func New(cfg *config.Config, sinks []sink.Sink) (*Router, error) {
	workers := map[string]*worker{}
	for _, ch := range cfg.Channels {
		var s sink.Sink
		for _, candidate := range sinks {
			if candidate.ID() == ch.ID {
				s = candidate
				break
			}
		}
		if s == nil {
			continue
		}
		sev, err := event.ParseSeverity(ch.MinSeverity)
		if err != nil {
			return nil, err
		}
		workers[ch.ID] = &worker{
			sink:    s,
			in:      make(chan *event.Event, sinkQueueDepth),
			rl:      filter.NewRateLimiter(ch.RateLimitPerMin),
			minSev:  sev,
			isLocal: ch.Type == "stdout" || ch.Type == "jsonlog" || ch.Type == "sqlite",
		}
	}

	allow, err := filter.NewAllowlist(cfg.Allowlist)
	if err != nil {
		return nil, err
	}

	return &Router{
		workers: workers,
		routes:  cfg.Routes,
		dedup:   filter.NewDedup(cfg.Dedup.DefaultWindow),
		allow:   allow,
	}, nil
}

// Start spins up one goroutine per sink. Call before any Dispatch.
func (r *Router) Start(ctx context.Context) {
	for id, w := range r.workers {
		r.wg.Add(1)
		go func(id string, w *worker) {
			defer r.wg.Done()
			r.runWorker(ctx, id, w)
		}(id, w)
	}
}

// Stop closes worker channels and waits for them to drain.
func (r *Router) Stop() {
	for _, w := range r.workers {
		close(w.in)
	}
	r.wg.Wait()
	for id, w := range r.workers {
		dropped := w.dropped.Load()
		failed := w.failed.Load()
		retried := w.retried.Load()
		if dropped > 0 || failed > 0 || retried > 0 {
			slog.Warn("sink final stats",
				"channel", id,
				"queue_drops", dropped,
				"send_failures", failed,
				"retry_recoveries", retried,
			)
		}
	}
}

// Dispatch fans out an event according to the configured routes. Non-local
// sinks are subject to allowlist, dedup, rate-limit and min-severity. Local
// sinks (stdout, jsonlog, sqlite) always receive the event so the local
// store stays complete.
func (r *Router) Dispatch(ev *event.Event) {
	// Stamp ATT&CK + D3FEND metadata before anything else — every
	// downstream (SIEM, MQTT, webhook, jsonlog) consumes the same
	// techniques / tactics / defenses view of the event. This is the
	// single chokepoint, so events synthesized outside the sensor bus
	// loop (device:new, malware:capture, scananalysis:profile, test-alert)
	// get the same treatment.
	if len(ev.MitreTechniques) == 0 {
		tag := mitre.Lookup(ev.RuleID, ev.Handler)
		ev.MitreTechniques = tag.Techniques
		ev.MitreTactics = tag.Tactics
	}
	if len(ev.MitreDefenses) == 0 {
		ev.MitreDefenses = mitre.DefensesFor(ev.MitreTechniques)
	}
	allowlisted := r.allow.Contains(ev.Source.IP)
	dedupKey := ev.Source.IP + "|" + ev.RuleID
	deduped := !r.dedup.ShouldSend(dedupKey)

	for _, route := range r.routes {
		if !matchEvent(route.Match, ev) {
			continue
		}
		for _, chID := range route.Channels {
			w := r.workers[chID]
			if w == nil {
				continue
			}
			if !w.isLocal {
				if allowlisted || deduped {
					continue
				}
				if !w.rl.Allow() {
					w.dropped.Add(1)
					continue
				}
			}
			if ev.Severity < w.minSev {
				continue
			}
			select {
			case w.in <- ev:
			default:
				w.dropped.Add(1)
				slog.Warn("sink queue full", "channel", chID, "rule", ev.RuleID)
			}
		}
	}
}

// runWorker pulls events off the in-channel and tries to Send them. On
// transient failure (any non-nil error) the event is queued in an in-memory
// backlog and retried with exponential backoff up to maxRetryWait. The
// backlog itself is bounded; events older than the bound are dropped with
// the "failed" counter incremented so the operator can see loss in the
// final stats line.
//
// Local sinks (jsonlog, sqlite, stdout) get the same retry treatment as
// remote ones — a flapping local disk shouldn't lose events any more than
// a flapping webhook would.
func (r *Router) runWorker(ctx context.Context, id string, w *worker) {
	var backlog []*event.Event
	retryTimer := time.NewTimer(time.Hour)
	if !retryTimer.Stop() {
		<-retryTimer.C
	}
	currentBackoff := initialRetryWait
	closed := false

	tryOne := func(ev *event.Event) error {
		sctx, cancel := context.WithTimeout(ctx, sinkSendTimeout)
		defer cancel()
		return w.sink.Send(sctx, ev)
	}

	enqueue := func(ev *event.Event) {
		if len(backlog) >= maxRetryBacklog {
			w.failed.Add(1)
			// Drop oldest so we make space for the new event — losing recent
			// data is usually less useful than retaining the older context.
			backlog = backlog[1:]
		}
		if len(backlog) == 0 {
			retryTimer.Reset(currentBackoff)
		}
		backlog = append(backlog, ev)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.in:
			if !ok {
				closed = true
				// flush whatever we can before exiting
				flushBacklog(&backlog, tryOne, w)
				return
			}
			if err := tryOne(ev); err != nil {
				if !shouldRetry(err) {
					w.failed.Add(1)
					slog.Warn("sink permanent error", "channel", id, "err", err)
					continue
				}
				slog.Warn("sink error; queued for retry", "channel", id, "err", err, "backlog_len", len(backlog)+1)
				enqueue(ev)
			}
		case <-retryTimer.C:
			delivered := 0
			remaining := backlog[:0]
			for _, ev := range backlog {
				if err := tryOne(ev); err != nil {
					if !shouldRetry(err) {
						w.failed.Add(1)
						continue
					}
					remaining = append(remaining, ev)
				} else {
					delivered++
				}
			}
			backlog = remaining
			if delivered > 0 {
				w.retried.Add(int64(delivered))
			}
			if len(backlog) > 0 {
				currentBackoff *= 2
				if currentBackoff > maxRetryWait {
					currentBackoff = maxRetryWait
				}
				if !closed {
					retryTimer.Reset(currentBackoff)
				}
				slog.Debug("retry partial drain", "channel", id, "delivered", delivered, "remaining", len(backlog), "next_wait", currentBackoff)
			} else {
				currentBackoff = initialRetryWait
				slog.Info("sink backlog drained", "channel", id, "recovered", delivered)
			}
		}
	}
}

// matchEvent applies all non-empty fields of m against ev. All set fields
// must match for the route to fire (AND semantics).
func matchEvent(m config.Match, ev *event.Event) bool {
	if m.Severity != "" {
		ok, err := config.SeverityMatches(m.Severity, ev.Severity)
		if err != nil || !ok {
			return false
		}
	}
	if m.RuleID != "" && m.RuleID != ev.RuleID {
		return false
	}
	if m.Honeynet != "" {
		if !metaEquals(ev, "honeynet", m.Honeynet) {
			return false
		}
	}
	if m.HoneynetOS != "" {
		if !metaEquals(ev, "honeynet_os", m.HoneynetOS) {
			return false
		}
	}
	return true
}

// metaEquals reports whether ev.Meta[key] is the given string. Returns
// false for missing keys or non-string values — meta is freeform, so we
// don't try to coerce.
func metaEquals(ev *event.Event, key, want string) bool {
	if ev.Meta == nil {
		return false
	}
	v, ok := ev.Meta[key]
	if !ok {
		return false
	}
	s, ok := v.(string)
	if !ok {
		return false
	}
	return s == want
}

func flushBacklog(backlog *[]*event.Event, tryOne func(*event.Event) error, w *worker) {
	for _, ev := range *backlog {
		if err := tryOne(ev); err != nil {
			w.failed.Add(1)
		} else {
			w.retried.Add(1)
		}
	}
	*backlog = nil
}

// shouldRetry classifies a sink Send error. Transient (network, busy, timeout)
// errors get retried; programmer / config errors don't. We're permissive by
// default — assume retryable unless context.Canceled.
func shouldRetry(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	return true
}

// Stats returns a per-channel snapshot (used by future /metrics endpoint).
type Stat struct {
	Dropped int64
	Failed  int64
	Retried int64
}

func (r *Router) Stats() map[string]Stat {
	out := map[string]Stat{}
	for id, w := range r.workers {
		out[id] = Stat{
			Dropped: w.dropped.Load(),
			Failed:  w.failed.Load(),
			Retried: w.retried.Load(),
		}
	}
	return out
}
