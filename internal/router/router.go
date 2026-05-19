package router

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/filter"
	"github.com/rom/tarpit-honeypot/internal/sink"
)

const sinkQueueDepth = 256
const sinkSendTimeout = 10 * time.Second

type worker struct {
	sink    sink.Sink
	in      chan *event.Event
	rl      *filter.RateLimiter
	minSev  event.Severity
	isLocal bool
	dropped atomic.Int64
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
			isLocal: ch.Type == "stdout" || ch.Type == "jsonlog",
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
		if n := w.dropped.Load(); n > 0 {
			slog.Warn("sink dropped events", "channel", id, "dropped", n)
		}
	}
}

// Dispatch fans out an event according to the configured routes. Non-local
// sinks are subject to allowlist, dedup, rate-limit and min-severity. Local
// sinks (stdout, jsonlog) always receive the event so the local store stays
// complete.
func (r *Router) Dispatch(ev *event.Event) {
	allowlisted := r.allow.Contains(ev.Source.IP)
	dedupKey := ev.Source.IP + "|" + ev.RuleID
	deduped := !r.dedup.ShouldSend(dedupKey)

	for _, route := range r.routes {
		ok, err := config.SeverityMatches(route.Match.Severity, ev.Severity)
		if err != nil || !ok {
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

func (r *Router) runWorker(ctx context.Context, id string, w *worker) {
	for ev := range w.in {
		sctx, cancel := context.WithTimeout(ctx, sinkSendTimeout)
		if err := w.sink.Send(sctx, ev); err != nil {
			slog.Warn("sink error", "channel", id, "err", err)
		}
		cancel()
	}
}
