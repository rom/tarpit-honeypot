package sensor

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/rom/tarpit-honeypot/internal/canary"
	"github.com/rom/tarpit-honeypot/internal/capture"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/correlate"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/listener"
	"github.com/rom/tarpit-honeypot/internal/router"
	"github.com/rom/tarpit-honeypot/internal/sink"
	"github.com/rom/tarpit-honeypot/internal/store"
)

type Sensor struct {
	cfg        *config.Config
	name       string
	sinks      []sink.Sink
	router     *router.Router
	correlator *correlate.Correlator
	store      *store.Store
	captureMgr *capture.Manager
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

	// Open the store once if any sqlite sink is configured OR the UI is on.
	var st *store.Store
	if needsStore(cfg) {
		s, err := store.Open(cfg.Sensor.DataDir, cfg.Sensor.Disk.SQLiteMB)
		if err != nil {
			return nil, err
		}
		st = s
	}

	// Capture manager — created only if any listener requests capture.
	var capMgr *capture.Manager
	if needsCapture(cfg) {
		mgr, err := capture.NewManager(cfg.Sensor.DataDir, cfg.Sensor.Disk.CaptureKB, cfg.Sensor.Disk.PcapMB)
		if err != nil {
			if st != nil {
				_ = st.Close()
			}
			return nil, err
		}
		capMgr = mgr
	}

	var sinks []sink.Sink
	for _, ch := range cfg.Channels {
		var s sink.Sink
		var err error
		if ch.Type == "sqlite" {
			if st == nil {
				return nil, fmt.Errorf("channel %s: sqlite sink configured but store missing", ch.ID)
			}
			s = sink.NewSQLite(ch.ID, st)
		} else {
			s, err = sink.Build(ch, cfg.Sensor.DataDir, cfg.Sensor.Disk.JSONLogMB)
		}
		if err != nil {
			if st != nil {
				_ = st.Close()
			}
			return nil, fmt.Errorf("build channel %s: %w", ch.ID, err)
		}
		sinks = append(sinks, s)
	}

	r, err := router.New(cfg, sinks)
	if err != nil {
		for _, s := range sinks {
			_ = s.Close()
		}
		if st != nil {
			_ = st.Close()
		}
		return nil, err
	}

	cor, err := correlate.New(cfg.Correlate)
	if err != nil {
		for _, s := range sinks {
			_ = s.Close()
		}
		if st != nil {
			_ = st.Close()
		}
		return nil, err
	}

	return &Sensor{
		cfg:        cfg,
		name:       name,
		sinks:      sinks,
		router:     r,
		correlator: cor,
		store:      st,
		captureMgr: capMgr,
		bus:        make(chan *event.Event, 1024),
	}, nil
}

func needsCapture(cfg *config.Config) bool {
	for _, l := range cfg.Listeners {
		if l.Capture {
			return true
		}
	}
	return false
}

func needsStore(cfg *config.Config) bool {
	if cfg.UI.Enabled {
		return true
	}
	for _, ch := range cfg.Channels {
		if ch.Type == "sqlite" {
			return true
		}
	}
	return false
}

func (s *Sensor) Name() string { return s.name }

// Router exposes the router for callers like `test-alert`.
func (s *Sensor) Router() *router.Router { return s.router }

// Correlator exposes the correlator for callers like `test-alert`.
func (s *Sensor) Correlator() *correlate.Correlator { return s.correlator }

// Store returns the SQLite event store, or nil if not configured.
func (s *Sensor) Store() *store.Store { return s.store }

// Config returns the active configuration.
func (s *Sensor) Config() *config.Config { return s.cfg }

// Reload swaps the router + correlator + canary watcher with a freshly built
// set from the new config. Listener and sensor.* changes require restart and
// are logged as a warning if they differ from the running set.
func (s *Sensor) Reload(newCfg *config.Config) error {
	// What we can hot-swap.
	var newSinks []sink.Sink
	for _, ch := range newCfg.Channels {
		var sk sink.Sink
		var err error
		if ch.Type == "sqlite" {
			if s.store == nil {
				return fmt.Errorf("reload: sqlite channel needs store; restart required")
			}
			sk = sink.NewSQLite(ch.ID, s.store)
		} else {
			sk, err = sink.Build(ch, newCfg.Sensor.DataDir, newCfg.Sensor.Disk.JSONLogMB)
		}
		if err != nil {
			return fmt.Errorf("reload: %w", err)
		}
		newSinks = append(newSinks, sk)
	}
	newRouter, err := router.New(newCfg, newSinks)
	if err != nil {
		for _, sk := range newSinks {
			_ = sk.Close()
		}
		return err
	}
	newCorrelator, err := correlate.New(newCfg.Correlate)
	if err != nil {
		for _, sk := range newSinks {
			_ = sk.Close()
		}
		return err
	}

	// Listener changes need restart.
	if listenersChanged(s.cfg.Listeners, newCfg.Listeners) {
		slog.Warn("reload: listener config changed; the new listener set requires a full restart (current listeners stay as-is)")
	}
	if s.cfg.Sensor.DataDir != newCfg.Sensor.DataDir {
		slog.Warn("reload: sensor.data_dir changed; ignored (requires restart)")
	}
	// canaries can be reloaded only if the new path set is identical — for v0.3
	// we keep things simple and ignore canary path changes.
	if canariesChanged(s.cfg.Canaries, newCfg.Canaries) {
		slog.Warn("reload: canary config changed; ignored (requires restart)")
	}

	// Hot-swap router and correlator atomically-ish: stop old workers, then
	// install the new ones. The bus loop briefly sees no router, but the
	// channel is buffered, so events queue up rather than being lost.
	oldRouter := s.router
	oldSinks := s.sinks
	s.router = newRouter
	s.correlator = newCorrelator
	s.sinks = newSinks
	s.cfg = newCfg

	newRouter.Start(context.Background())
	// Don't drain the old worker queues; the new sinks pick up from here.
	oldRouter.Stop()
	for _, sk := range oldSinks {
		_ = sk.Close()
	}
	slog.Info("reload complete", "channels", len(newCfg.Channels), "routes", len(newCfg.Routes))
	return nil
}

func listenersChanged(a, b []config.Listener) bool {
	if len(a) != len(b) {
		return true
	}
	idx := map[string]config.Listener{}
	for _, l := range a {
		idx[l.ID] = l
	}
	for _, l := range b {
		other, ok := idx[l.ID]
		if !ok {
			return true
		}
		if other.Proto != l.Proto || other.Bind != l.Bind || other.Mode != l.Mode || other.Handler != l.Handler {
			return true
		}
	}
	return false
}

func canariesChanged(a, b []config.Canary) bool {
	if len(a) != len(b) {
		return true
	}
	idx := map[string]config.Canary{}
	for _, c := range a {
		idx[c.ID] = c
	}
	for _, c := range b {
		other, ok := idx[c.ID]
		if !ok || other.Path != c.Path || other.Recursive != c.Recursive {
			return true
		}
	}
	return false
}

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
		ln, err := listener.Build(l, s.name, s.cfg.Sensor.DataDir, s.captureMgr)
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
	if s.store != nil {
		_ = s.store.Close()
	}
	return nil
}
