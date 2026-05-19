package sensor

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/listener"
	"github.com/rom/tarpit-honeypot/internal/router"
	"github.com/rom/tarpit-honeypot/internal/sink"
)

type Sensor struct {
	cfg     *config.Config
	name    string
	sinks   []sink.Sink
	router  *router.Router
	bus     chan *event.Event
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
		// best effort close
		for _, s := range sinks {
			_ = s.Close()
		}
		return nil, err
	}

	return &Sensor{
		cfg:    cfg,
		name:   name,
		sinks:  sinks,
		router: r,
		bus:    make(chan *event.Event, 1024),
	}, nil
}

// Name returns the resolved sensor name (after hostname fallback).
func (s *Sensor) Name() string { return s.name }

// Router exposes the router for callers like `test-alert`.
func (s *Sensor) Router() *router.Router { return s.router }

// Run starts listeners and the router and blocks until ctx is cancelled.
func (s *Sensor) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.router.Run(ctx, s.bus)
	}()

	for _, l := range s.cfg.Listeners {
		ln, err := listener.Build(l, s.name)
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

	<-ctx.Done()
	close(s.bus)
	wg.Wait()
	for _, sk := range s.sinks {
		_ = sk.Close()
	}
	return nil
}
