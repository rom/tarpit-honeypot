package sensor

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/canary"
	"github.com/rom/tarpit-honeypot/internal/capture"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/correlate"
	"github.com/rom/tarpit-honeypot/internal/dnscanary"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/honeynet"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/listener"
	"github.com/rom/tarpit-honeypot/internal/retention"
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
	identity   *identity.Identity
	jitter     *jitter.Jitterer
	honeynet   *honeynet.Topology
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

	id, err := identity.Load(cfg.Sensor.DataDir, cfg.Sensor.DeploymentID)
	if err != nil {
		return nil, err
	}
	jit := jitter.New(cfg.Sensor.Jitter.MinMS, cfg.Sensor.Jitter.MaxMS)
	if !cfg.Sensor.Jitter.Enabled {
		jit = jitter.New(0, 0)
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

	topo, err := honeynet.Build(cfg.Honeynets, id, jit, cfg.Sensor.DataDir, cfg.URLCanaries, cfg.Sensor.TLSRotate.Days)
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
		identity:   id,
		jitter:     jit,
		honeynet:   topo,
		bus:        make(chan *event.Event, 1024),
		listeners:  map[string]*listenerHandle{},
	}, nil
}

// Honeynet returns the configured topology, or an empty topology if none.
// Used by the list-honeynets subcommand and the DNS canary listener.
func (s *Sensor) Honeynet() *honeynet.Topology { return s.honeynet }

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
	ln, err := listener.Build(l, listener.BuildArgs{
		SensorName:  s.name,
		DataDir:     s.cfg.Sensor.DataDir,
		CaptureMgr:  s.captureMgr,
		URLCanaries: s.cfg.URLCanaries,
		Identity:    s.identity,
		Jitter:      s.jitter,
		TLSRotate:   s.cfg.Sensor.TLSRotate.Days,
		Honeynet:    s.honeynet,
	})
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

	slog.Info("sensor identity", "deployment_id", s.identity.Seed(), "jitter", s.jitter.Enabled())
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

	if s.cfg.DNS.Enabled && (len(s.cfg.DNSCanaries) > 0 || s.cfg.DNS.AmplifierDetection.Enabled || !s.honeynet.Empty()) {
		srv, err := dnscanary.New(s.cfg.DNS.Bind, s.name, s.cfg.DNSCanaries, s.cfg.DNS.AmplifierDetection)
		if err != nil {
			return err
		}
		if !s.honeynet.Empty() {
			srv.SetResolver(func(qname string) (string, string, bool) {
				if h := s.honeynet.HostByName(qname); h != nil {
					return h.IP, h.Hostname, true
				}
				return "", "", false
			})
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

	// Retention runner — only if configured.
	if s.cfg.Sensor.Disk.RetentionDays > 0 {
		r := &retention.Runner{
			Days:        s.cfg.Sensor.Disk.RetentionDays,
			JSONLogDir:  filepath.Join(s.cfg.Sensor.DataDir, "events"),
			CapturesDir: filepath.Join(s.cfg.Sensor.DataDir, "captures"),
		}
		if s.store != nil {
			r.DB = s.store.DB()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Run(ctx)
		}()
		slog.Info("retention runner up", "days", s.cfg.Sensor.Disk.RetentionDays)
	}

	<-ctx.Done()

	// Graceful drain. We cancel the listener contexts (which closes the
	// accept sockets so no new connections are accepted) and then wait
	// up to drain_timeout for already-running handler goroutines to exit
	// on their own. Each listener's Start() goroutine signals done once
	// it returns; we don't need a separate handler tracker because
	// listener.Start blocks until Accept errors out, which it does as
	// soon as we close the socket — but in-flight handler() goroutines
	// the listener spawned continue to run on the listener's ctx (which
	// is the SAME ctx as Accept used). For now we accept that handlers
	// will see ctx.Done() too; the drain timeout gives them a chance to
	// finish their reply before we hard-cancel.
	drainTimeout := s.cfg.Sensor.Shutdown.DrainTimeout
	if drainTimeout <= 0 {
		drainTimeout = 10 * time.Second
	}
	slog.Info("shutdown: draining", "timeout", drainTimeout)

	s.listenersMu.Lock()
	handles := make([]*listenerHandle, 0, len(s.listeners))
	for _, h := range s.listeners {
		handles = append(handles, h)
	}
	s.listeners = map[string]*listenerHandle{}
	s.listenersMu.Unlock()

	// Cancel each listener so Accept loops exit. handle() goroutines also
	// see the ctx cancel but can finish their current Write/Read before
	// returning. wait on all done channels with the drain budget.
	for _, h := range handles {
		h.cancel()
	}
	drainCtx, drainCancel := context.WithTimeout(context.Background(), drainTimeout)
	defer drainCancel()
	allDone := make(chan struct{})
	go func() {
		for _, h := range handles {
			<-h.done
		}
		close(allDone)
	}()
	select {
	case <-allDone:
		slog.Info("shutdown: listeners drained")
	case <-drainCtx.Done():
		slog.Warn("shutdown: drain timeout reached; some handlers may have been interrupted")
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
