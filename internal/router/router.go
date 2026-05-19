package router

import (
	"context"
	"log/slog"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/filter"
	"github.com/rom/tarpit-honeypot/internal/sink"
)

type bound struct {
	sink     sink.Sink
	rl       *filter.RateLimiter
	minSev   event.Severity
	isLocal  bool // jsonlog + stdout always run, even for allowlisted sources
}

type Router struct {
	channels  map[string]*bound
	routes    []config.Route
	dedup     *filter.Dedup
	allow     *filter.Allowlist
}

func New(cfg *config.Config, sinks []sink.Sink) (*Router, error) {
	chByID := map[string]*bound{}
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
		chByID[ch.ID] = &bound{
			sink:    s,
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
		channels: chByID,
		routes:   cfg.Routes,
		dedup:    filter.NewDedup(cfg.Dedup.DefaultWindow),
		allow:    allow,
	}, nil
}

// Run pulls events from bus and dispatches to configured channels until ctx
// is cancelled. Sinks are called serially per event; one slow sink will
// back-pressure others. For v0.1 this is acceptable; v0.2+ will move sink
// dispatch onto per-sink workers with bounded queues.
func (r *Router) Run(ctx context.Context, bus <-chan *event.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-bus:
			if !ok {
				return
			}
			r.dispatch(ctx, ev)
		}
	}
}

func (r *Router) dispatch(ctx context.Context, ev *event.Event) {
	allowlisted := r.allow.Contains(ev.Source.IP)
	dedupKey := ev.Source.IP + "|" + ev.RuleID
	deduped := !r.dedup.ShouldSend(dedupKey)

	for _, route := range r.routes {
		ok, err := config.SeverityMatches(route.Match.Severity, ev.Severity)
		if err != nil || !ok {
			continue
		}
		for _, chID := range route.Channels {
			b := r.channels[chID]
			if b == nil {
				continue
			}
			// Local sinks (stdout / jsonlog) bypass dedup and allowlist
			// so the event store is always complete.
			if !b.isLocal {
				if allowlisted {
					continue
				}
				if deduped {
					continue
				}
				if !b.rl.Allow() {
					slog.Warn("rate limit hit", "channel", chID, "rule", ev.RuleID, "src", ev.Source.IP)
					continue
				}
			}
			if ev.Severity < b.minSev {
				continue
			}
			sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			if err := b.sink.Send(sctx, ev); err != nil {
				slog.Warn("sink error", "channel", chID, "err", err)
			}
			cancel()
		}
	}
}
