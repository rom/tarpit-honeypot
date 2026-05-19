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
	"github.com/rom/tarpit-honeypot/internal/dnscanary"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/listener"
	"github.com/rom/tarpit-honeypot/internal/router"
	"github.com/rom/tarpit-honeypot/internal/sink"
	"github.com/rom/tarpit-honeypot/internal/sniffer"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// listenerHandle wraps a running listener so we can stop it individually
// (hot reload) without affecting the rest of the sensor.
type listenerHandle struct {
	cfg    config.Listener
	cancel context.CancelFunc
	done   chan struct{}
}

type Sensor struct {
	cfg        *config.Config
	name       string
	sinks      []sink.Sink
	router     *router.Router
	correlator *correlate.Correlator
	store      *store.Store
	captureMgr *capture.Manager
	bus        chan *event.Event

	rootCtx context.Context // parent ctx for listener-specific child contexts

	listenersMu sync.Mutex
	listeners   map[string]*listenerHandle
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

	var st *store.Store
	if needsStore(cfg) {
		s, err := store.Open(cfg.Sensor.DataDir, cfg.Sensor.Disk.SQLiteMB)
		if err != nil {
			return nil, err
		}
		st = s
	}

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
		listeners:  map[string]*listenerHandle{},
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

func (s *Sensor) Name() string                      { return s.name }
func (s *Sensor) Router() *router.Router            { return s.router }
func (s *Sensor) Correlator() *correlate.Correlator { return s.correlator }
func (s *Sensor) Store() *store.Store               { return s.store }
func (s *Sensor) Config() *config.Config            { return s.cfg }

// startListener builds and launches a single listener. It uses the sensor's
// rootCtx (set in Run) as the parent so global shutdown still cascades.
func (s *Sensor) startListener(l config.Listener) error {
	if s.rootCtx == nil {
		return fmt.Errorf("startListener called before Run()")
	}
	ctx, cancel := context.WithCancel(s.rootCtx)
	ln, err := listener.Build(l, s.name, s.cfg.Sensor.DataDir, s.captureMgr, s.cfg.URLCanaries)
	if err != nil {
		cancel()
		return err
	}
	h := &listenerHandle{cfg: l, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(h.done)
		if err := ln.Start(ctx, s.bus); err != nil {
			slog.Error("listener stopped", "id", ln.ID(), "err", err)
		}
	}()
	s.listenersMu.Lock()
	s.listeners[l.ID] = h
	s.listenersMu.Unlock()
	return nil
}

// stopListener cancels a single listener and waits for its goroutine to
// exit. Safe to call with an unknown id (no-op).
func (s *Sensor) stopListener(id string) {
	s.listenersMu.Lock()
	h, ok := s.listeners[id]
	if ok {
		delete(s.listeners, id)
	}
	s.listenersMu.Unlock()
	if !ok {
		return
	}
	h.cancel()
	<-h.done
}

// Reload swaps router + correlator + listeners + canary-watcher set with a
// freshly-built version. SIGHUP-tolerant changes are applied; restart-only
// changes (sensor.*, dns listener, sniffer) log a clear warning per item.
//
// Listener hot-reload semantics:
//   - listeners added in newCfg: built + started with the new ctx.
//   - listeners removed in newCfg: cancelled + drained.
//   - listeners modified in newCfg (anything other than the id is equivalent
//     to "removed then added"): stopped, then a new instance is started.
func (s *Sensor) Reload(newCfg *config.Config) error {
	diff := config.DiffConfigs(s.cfg, newCfg)

	// Sinks + router + correlator first; if either fails we keep the old set.
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
			for _, b := range newSinks {
				_ = b.Close()
			}
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

	// Log restart-only deltas explicitly so the operator knows what was left
	// untouched (other than listeners; we hot-reload those now).
	for _, c := range diff.RestartNeeded {
		if c.Section == "listeners" {
			continue
		}
		slog.Warn("reload: change requires restart, ignored", "change", c.String())
	}
	for _, c := range diff.HotReloadable {
		slog.Info("reload: applying", "change", c.String())
	}

	// Apply listener diff. We do removes first so freed ports can be reused
	// by the adds.
	listenerDiffs := diff.RestartNeeded
	oldIDs := map[string]config.Listener{}
	for _, l := range s.cfg.Listeners {
		oldIDs[l.ID] = l
	}
	newIDs := map[string]config.Listener{}
	for _, l := range newCfg.Listeners {
		newIDs[l.ID] = l
	}
	for _, c := range listenerDiffs {
		if c.Section != "listeners" {
			continue
		}
		switch c.Action {
		case "removed":
			s.stopListener(c.ID)
			slog.Info("listener stopped", "id", c.ID)
		case "modified":
			s.stopListener(c.ID)
			if err := s.startListener(newIDs[c.ID]); err != nil {
				slog.Error("listener restart failed", "id", c.ID, "err", err)
			} else {
				slog.Info("listener restarted", "id", c.ID)
			}
		case "added":
			if err := s.startListener(newIDs[c.ID]); err != nil {
				slog.Error("listener start failed", "id", c.ID, "err", err)
			} else {
				slog.Info("listener started", "id", c.ID)
			}
		}
	}

	// Hot-swap router + correlator.
	oldRouter := s.router
	oldSinks := s.sinks
	s.router = newRouter
	s.correlator = newCorrelator
	s.sinks = newSinks
	s.cfg = newCfg

	newRouter.Start(s.rootCtx)
	oldRouter.Stop()
	for _, sk := range oldSinks {
		_ = sk.Close()
	}

	// Emit a synthetic reload event so the operator's downstream pipeline
	// can correlate config changes with detection-signal changes.
	s.emitReloadEvent(diff)

	slog.Info("reload complete",
		"hot_reloadable_changes", len(diff.HotReloadable),
		"restart_needed_changes", len(diff.RestartNeeded),
		"channels", len(newCfg.Channels),
		"listeners", len(newCfg.Listeners),
	)
	_ = oldIDs
	return nil
}

func (s *Sensor) emitReloadEvent(diff config.Diff) {
	changes := make([]string, 0, len(diff.HotReloadable)+len(diff.RestartNeeded))
	for _, c := range diff.HotReloadable {
		changes = append(changes, "hot:"+c.String())
	}
	for _, c := range diff.RestartNeeded {
		changes = append(changes, "restart:"+c.String())
	}
	ev := &event.Event{
		ID:       event.NewID(),
		Time:     timeNow(),
		Sensor:   s.name,
		RuleID:   "sensor:reload",
		Severity: event.SeverityLow,
		Meta: map[string]any{
			"hot_reloadable": len(diff.HotReloadable),
			"restart_needed": len(diff.RestartNeeded),
			"changes":        changes,
		},
	}
	select {
	case s.bus <- ev:
	default:
	}
}

// Run starts the bus consumer, listeners, canaries, dnscanary, and sniffer.
// Blocks until ctx is cancelled.
func (s *Sensor) Run(ctx context.Context) error {
	s.rootCtx = ctx
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
		if err := s.startListener(l); err != nil {
			return err
		}
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

	if s.cfg.DNS.Enabled && len(s.cfg.DNSCanaries) > 0 {
		srv, err := dnscanary.New(s.cfg.DNS.Bind, s.name, s.cfg.DNSCanaries)
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Run(ctx, s.bus); err != nil {
				slog.Error("dnscanary stopped", "err", err)
			}
		}()
	}

	if s.cfg.Sniffer.Enabled {
		sn, err := sniffer.New(s.cfg.Sniffer, s.name)
		if err != nil {
			slog.Warn("sniffer disabled", "err", err)
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := sn.Run(ctx, s.bus); err != nil {
					slog.Error("sniffer stopped", "err", err)
				}
			}()
		}
	}

	<-ctx.Done()
	// Cancel any running listeners and wait for them.
	s.listenersMu.Lock()
	handles := make([]*listenerHandle, 0, len(s.listeners))
	for _, h := range s.listeners {
		handles = append(handles, h)
	}
	s.listeners = map[string]*listenerHandle{}
	s.listenersMu.Unlock()
	for _, h := range handles {
		h.cancel()
		<-h.done
	}
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
