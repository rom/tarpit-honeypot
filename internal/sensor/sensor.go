package sensor

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/rom/tarpit-honeypot/internal/canary"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/correlate"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/listener"
	"github.com/rom/tarpit-honeypot/internal/router"
	"github.com/rom/tarpit-honeypot/internal/sink"
)

type Sensor struct {
	cfg        *config.Config
	name       string
	sinks      []sink.Sink
	router     *router.Router
	correlator *correlate.Correlator
	bus        chan *event.Event
}

func New(cfg *config.Config) (*Sensor, error) {
	name := cfg.Sensor.Name
	if name == "" {
		h, err := os.Hostname()
		if err == nil {
			name = h
		} else {
			name = "tarpit"
		}
	}

	if err := os.MkdirAll(cfg.Sensor.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("data_dir %s: %w", cfg.Sensor.DataDir, err)
	}

	var sinks []sink.Sink
	for _, ch := range cfg.Channels {
		s, err := sink.Build(ch, cfg.Sensor.DataDir, cfg.Sensor.Disk.JSONLogMB)
		if err != nil {
			return nil, fmt.Errorf("build channel %s: %w", ch.ID, err)
		}
		sinks = append(sinks, s)
	}

	r, err := router.New(cfg, sinks)
	if err != nil {
		for _, s := range sinks {
			_ = s.Close()
		}
		return nil, err
	}

	cor, err := correlate.New(cfg.Correlate)
	if err != nil {
		for _, s := range sinks {
			_ = s.Close()
		}
		return nil, err
	}

	return &Sensor{
		cfg:        cfg,
		name:       name,
		sinks:      sinks,
		router:     r,
		correlator: cor,
		bus:        make(chan *event.Event, 1024),
	}, nil
}

func (s *Sensor) Name() string { return s.name }

// Router exposes the router for callers like `test-alert`.
func (s *Sensor) Router() *router.Router { return s.router }

// Correlator exposes the correlator for callers like `test-alert`.
func (s *Sensor) Correlator() *correlate.Correlator { return s.correlator }

// Run starts listeners, canaries, router workers, and the dispatch loop.
// Blocks until ctx is cancelled.
func (s *Sensor) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	s.router.Start(ctx)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for ev := range s.bus {
			for _, out := range s.correlator.Observe(ev) {
				s.router.Dispatch(out)
			}
		}
	}()

	for _, l := range s.cfg.Listeners {
		ln, err := listener.Build(l, s.name, s.cfg.Sensor.DataDir)
		if err != nil {
			return err
		}
		wg.Add(1)
		go func(ln listener.Listener) {
			defer wg.Done()
			if err := ln.Start(ctx, s.bus); err != nil {
				slog.Error("listener stopped", "id", ln.ID(), "err", err)
			}
		}(ln)
	}

	if len(s.cfg.Canaries) > 0 {
		w := canary.New(s.cfg.Canaries, s.name)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.Run(ctx, s.bus); err != nil {
				slog.Error("canary watcher stopped", "err", err)
			}
		}()
	}

	<-ctx.Done()
	close(s.bus)
	wg.Wait()
	s.router.Stop()
	for _, sk := range s.sinks {
		_ = sk.Close()
	}
	return nil
}
