package sensor

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/canary"
	"github.com/rom/tarpit-honeypot/internal/capture"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/correlate"
	"github.com/rom/tarpit-honeypot/internal/devices"
	"github.com/rom/tarpit-honeypot/internal/dnscanary"
	"github.com/rom/tarpit-honeypot/internal/enrich"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/honeynet"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/listener"
	"github.com/rom/tarpit-honeypot/internal/listener/handler"
	"github.com/rom/tarpit-honeypot/internal/mitre"
	"github.com/rom/tarpit-honeypot/internal/payload"
	"github.com/rom/tarpit-honeypot/internal/retention"
	"github.com/rom/tarpit-honeypot/internal/router"
	"github.com/rom/tarpit-honeypot/internal/safego"
	"github.com/rom/tarpit-honeypot/internal/scananalysis"
	"github.com/rom/tarpit-honeypot/internal/sessionrec"
	"github.com/rom/tarpit-honeypot/internal/sink"
	"github.com/rom/tarpit-honeypot/internal/sniffer"
	"github.com/rom/tarpit-honeypot/internal/store"
	"github.com/rom/tarpit-honeypot/internal/tunnet"
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
	archetype  *archetype.Profile
	honeynet   *honeynet.Topology
	enrich     *enrich.Enricher
	devices    *devices.Registry
	scanTrack  *scananalysis.Tracker
	payloads   *payload.Store
	sessionRec *sessionrec.Store
	deviceSev  event.Severity
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

	// Resolve the deployment-default archetype (already validated in
	// config.Validate, so Lookup returning nil here means empty).
	arch := archetype.Lookup(cfg.Sensor.Archetype)

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
	// Restore windowed detector state from a previous run so long-window
	// detectors (slow-scan in particular) survive a restart.
	if cfg.Sensor.DataDir != "" {
		if rerr := cor.Restore(correlate.StatePath(cfg.Sensor.DataDir)); rerr != nil {
			slog.Warn("correlator: state restore failed", "err", rerr)
		}
	}

	topo, err := honeynet.Build(cfg.Honeynets, id, jit, cfg.Sensor.DataDir, cfg.URLCanaries, cfg.Sensor.TLSRotate.Days, arch)
	if err != nil {
		for _, s := range sinks {
			_ = s.Close()
		}
		if st != nil {
			_ = st.Close()
		}
		return nil, err
	}

	enr, err := enrich.New(enrich.Config{
		CityDB:      cfg.Sensor.GeoIP.CityDB,
		ASNDB:       cfg.Sensor.GeoIP.ASNDB,
		RDNSEnabled: cfg.Sensor.RDNS.Enabled,
		RDNSTimeout: cfg.Sensor.RDNS.Timeout,
		RDNSCache:   cfg.Sensor.RDNS.CacheSize,
	})
	if err != nil {
		for _, s := range sinks {
			_ = s.Close()
		}
		if st != nil {
			_ = st.Close()
		}
		return nil, err
	}

	var devReg *devices.Registry
	devSev := event.SeverityHigh
	if cfg.Devices.Enabled {
		devReg = devices.New(devices.Config{
			DataDir: cfg.Sensor.DataDir,
			Allow:   cfg.Devices.Allow,
			Learn:   cfg.Devices.Learn,
		})
		if cfg.Devices.Severity != "" {
			if s, err := event.ParseSeverity(cfg.Devices.Severity); err == nil {
				devSev = s
			}
		}
	}

	var sessRec *sessionrec.Store
	if cfg.Sensor.SessionRecording.Enabled {
		sr, err := sessionrec.NewStore(filepath.Join(cfg.Sensor.DataDir, "sessions"),
			cfg.Sensor.SessionRecording.MaxBytes, cfg.Sensor.SessionRecording.MaxTotalMB)
		if err != nil {
			slog.Warn("session recording disabled: cannot create store", "err", err)
		} else {
			sessRec = sr
		}
	}

	var payloadStore *payload.Store
	if cfg.Sensor.Payloads.Enabled {
		ps, err := payload.NewStore(filepath.Join(cfg.Sensor.DataDir, "payloads"),
			cfg.Sensor.Payloads.MaxBytes, cfg.Sensor.Payloads.MaxTotalMB)
		if err != nil {
			slog.Warn("payload harvesting disabled: cannot create store", "err", err)
		} else {
			payloadStore = ps
		}
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
		archetype:  arch,
		honeynet:   topo,
		enrich:     enr,
		devices:    devReg,
		deviceSev:  devSev,
		scanTrack:  scananalysis.NewTracker(5 * time.Minute),
		payloads:   payloadStore,
		sessionRec: sessRec,
		bus:        make(chan *event.Event, 1024),
		listeners:  map[string]*listenerHandle{},
	}, nil
}

// Honeynet returns the configured topology, or an empty topology if none.
// Used by the list-honeynets subcommand and the DNS canary listener.
func (s *Sensor) Honeynet() *honeynet.Topology { return s.honeynet }

// Devices returns the learned-device registry (nil when devices are
// disabled). Used by the list-devices subcommand.
func (s *Sensor) Devices() *devices.Registry { return s.devices }

// observeScan feeds a listener event into the scan-analysis Tracker
// and returns a scananalysis:profile event when the source crosses the
// confidence threshold (timing template + scope + probe variety). Only
// per-connection listener events are interesting; aggregate / canary /
// internal events are skipped.
func (s *Sensor) observeScan(ev *event.Event, payload []byte) *event.Event {
	if s.scanTrack == nil || ev == nil || ev.Source.IP == "" {
		return nil
	}
	if !strings.HasPrefix(ev.RuleID, "listener:") {
		return nil
	}
	verdict := scananalysis.ClassifyPayload(payload, ev.Handler)
	osHint := false
	if ev.Proto == "icmp" {
		osHint = true // ICMP timestamp/mask probes are OS-fingerprint inputs
	}
	r := s.scanTrack.Observe(scananalysis.Observation{
		SourceIP:    ev.Source.IP,
		DestPort:    ev.Dest.Port,
		Handler:     ev.Handler,
		Time:        ev.Time,
		Verdict:     verdict,
		OSProbeHint: osHint,
	})
	if r == nil {
		return nil
	}
	meta := map[string]any{
		"timing_profile": r.TimingProfile,
		"distinct_ports": r.DistinctPorts,
		"connections":    r.Conns,
		"version_scan":   r.VersionScan,
		"os_scan":        r.OSScan,
		"aggressive":     r.Aggressive,
	}
	if len(r.NSEScripts) > 0 {
		meta["nse_scripts"] = r.NSEScripts
	}
	sev := event.SeverityMedium
	if r.Aggressive || r.VersionScan {
		sev = event.SeverityHigh
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     ev.Time,
		Sensor:   s.name,
		RuleID:   "scananalysis:profile",
		Severity: sev,
		Source:   ev.Source,
		Proto:    "tcp",
		Meta:     meta,
	}
}

// observePayload harvests malware / shellcode / ingress URLs from an
// event's captured bytes. It enriches the event in place (anomaly
// markers + harvested_urls / payload_artifacts meta), persists any
// binary / script / shellcode artifact to <data_dir>/payloads/ when
// harvesting is enabled, and returns a malware:capture event when an
// executable-class artifact was found. Detection + collection only —
// nothing is executed or fetched.
func (s *Sensor) observePayload(ev *event.Event, data []byte) *event.Event {
	if ev == nil || ev.RuleID == "malware:capture" {
		return nil
	}
	keep := s.payloads != nil
	f := payload.Scan(data, keep)
	// Also harvest IOCs from interactive-shell command lines: URLs and
	// base64 droppers typed into the emulated shell aren't in the
	// connection payload, so scan each captured command too.
	for _, cmd := range shellCommandText(ev) {
		f = f.Merge(payload.Scan([]byte(cmd), keep))
	}
	if f.Empty() {
		return nil
	}
	if ev.Meta == nil {
		ev.Meta = map[string]any{}
	}
	for _, m := range f.Markers {
		ev.Anomalies = appendUniqueStr(ev.Anomalies, m)
	}
	if len(f.URLs) > 0 {
		ev.Meta["harvested_urls"] = f.URLs
	}

	// Persist artifacts + build a compact descriptor list for the meta.
	var descs []string
	worst := event.SeverityHigh
	for i := range f.Artifacts {
		a := f.Artifacts[i]
		d := a.Kind + ":" + a.SHA256
		if s.payloads != nil {
			if path, perr := s.payloads.Persist(a); perr == nil && path != "" {
				d += " -> " + filepath.Base(path)
			}
		}
		descs = append(descs, d)
		// Only a magic-confirmed executable warrants Critical; the
		// shellcode/script/archive heuristics stay High to avoid
		// alert-fatigue on the occasional binary-protocol false positive.
		switch a.Kind {
		case payload.KindELF, payload.KindPE, payload.KindMachO:
			worst = event.SeverityCritical
		}
	}
	if len(descs) == 0 {
		// URLs / markers only — enrich the event but don't emit a
		// separate malware event.
		return nil
	}
	ev.Meta["payload_artifacts"] = descs

	return &event.Event{
		ID:       event.NewID(),
		Time:     ev.Time,
		Sensor:   s.name,
		RuleID:   "malware:capture",
		Severity: worst,
		Source:   ev.Source,
		Dest:     ev.Dest,
		Proto:    ev.Proto,
		Handler:  ev.Handler,
		Meta: map[string]any{
			"trigger_event_id": ev.ID,
			"artifacts":        descs,
			"markers":          f.Markers,
		},
	}
}

// shellCommandText returns the attacker's interactive-shell input from an
// event's meta (the ssh_interactive / telnet handlers store typed lines
// in "shell_commands" and one-shot exec lines in "exec_command"), so the
// payload harvester can pull URLs / droppers out of them.
func shellCommandText(ev *event.Event) []string {
	if ev.Meta == nil {
		return nil
	}
	var out []string
	if cmds, ok := ev.Meta["shell_commands"].([]string); ok {
		out = append(out, cmds...)
	}
	if c, ok := ev.Meta["exec_command"].(string); ok && c != "" {
		out = append(out, c)
	}
	return out
}

// appendUniqueStr appends s to list only if absent.
func appendUniqueStr(list []string, s string) []string {
	for _, e := range list {
		if e == s {
			return list
		}
	}
	return append(list, s)
}

// observeDevice extracts host identity from an event and feeds it into
// the device registry. Returns a device:new event when the host is
// previously-unseen and not allow-listed, else nil. Returns nil
// immediately when device tracking is disabled.
//
// The richest source is the dhcp handler (client_mac + hostname); the
// ARP sniffer supplies sender_mac/sender_ip; everything else
// contributes the source IP.
func (s *Sensor) observeDevice(ev *event.Event) *event.Event {
	if s.devices == nil || ev == nil {
		return nil
	}
	// Don't recurse on our own device events.
	if ev.RuleID == "device:new" {
		return nil
	}
	obs := devices.Observation{Time: ev.Time, Source: devices.SourceConn}
	if ev.Source.IP != "" {
		obs.IP = ev.Source.IP
	}
	if ev.Meta != nil {
		if m, ok := ev.Meta["client_mac"].(string); ok && m != "" {
			obs.MAC = m
			obs.Source = devices.SourceDHCP
		} else if m, ok := ev.Meta["sender_mac"].(string); ok && m != "" {
			obs.MAC = m
			obs.Source = devices.SourceARP
		} else if m, ok := ev.Meta["mac"].(string); ok && m != "" {
			obs.MAC = m
		}
		if h, ok := ev.Meta["hostname"].(string); ok && h != "" {
			obs.Hostname = h
		}
		// DHCP requested_ip is the client's intended address; prefer
		// it over the (often 0.0.0.0) UDP source for DHCP DISCOVER.
		if rip, ok := ev.Meta["requested_ip"].(string); ok && rip != "" {
			obs.IP = rip
		}
	}
	if obs.IP == "" && obs.MAC == "" {
		return nil
	}
	d, isNew := s.devices.Observe(obs)
	if !isNew {
		return nil
	}
	meta := map[string]any{
		"device_ip":    d.IP,
		"device_mac":   d.MAC,
		"learned_from": string(d.Source),
		"first_seen":   d.FirstSeen.UTC().Format(time.RFC3339),
	}
	if d.Hostname != "" {
		meta["device_hostname"] = d.Hostname
	}
	if d.Vendor != "" {
		meta["device_vendor"] = d.Vendor
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     ev.Time,
		Sensor:   s.name,
		RuleID:   "device:new",
		Severity: s.deviceSev,
		Source:   event.Endpoint{IP: d.IP},
		Proto:    "device",
		Meta:     meta,
	}
}

// honeynetSnapshot converts a Topology to the handler-friendly view that
// SNMP / LDAP / DCE-RPC use to advertise the honeynet hosts in their
// query responses. Caller passes the result via listener.BuildArgs.
func honeynetSnapshot(t *honeynet.Topology) handler.HoneynetSnapshot {
	if t == nil {
		return handler.HoneynetSnapshot{}
	}
	src := t.SnapshotForHandlers()
	if len(src) == 0 {
		return handler.HoneynetSnapshot{}
	}
	out := make([]handler.HoneynetHost, 0, len(src))
	for _, h := range src {
		services := make([]handler.HoneynetService, 0, len(h.Services))
		for _, s := range h.Services {
			services = append(services, handler.HoneynetService{Port: s.Port, Handler: s.Handler})
		}
		out = append(out, handler.HoneynetHost{
			NetID:    h.NetID,
			IP:       h.IP,
			Hostname: h.Hostname,
			OS:       h.OS,
			MAC:      h.MAC,
			Services: services,
		})
	}
	var nets []handler.HoneynetNetwork
	for _, n := range t.NetworkSnapshot() {
		nets = append(nets, handler.HoneynetNetwork{
			ID: n.ID, CIDR: n.CIDR, Domain: n.Domain, DNS: n.DNS, Gateway: n.Gateway,
		})
	}
	return handler.HoneynetSnapshot{Hosts: out, Networks: nets}
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
	ln, err := listener.Build(l, listener.BuildArgs{
		SensorName:       s.name,
		DataDir:          s.cfg.Sensor.DataDir,
		CaptureMgr:       s.captureMgr,
		URLCanaries:      s.cfg.URLCanaries,
		Identity:         s.identity,
		Jitter:           s.jitter,
		TLSRotate:        s.cfg.Sensor.TLSRotate.Days,
		SensorArchetype:  s.archetype,
		Honeynet:         s.honeynet,
		HoneynetSnapshot: honeynetSnapshot(s.honeynet),
		VulnEmulation:    s.cfg.Sensor.VulnEmulation,
		SessionRec:       s.sessionRec,
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
			s.emitOpEvent("sensor:listener_stopped", event.SeverityMedium, map[string]any{
				"listener": ln.ID(), "error": err.Error(),
			})
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
	// Carry detector state across the reload so a config change doesn't
	// reset in-flight scan/brute/slow/sweep windows.
	if s.correlator != nil {
		newCorrelator.LoadSnapshot(s.correlator.Snapshot())
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
				s.emitOpEvent("sensor:listener_error", event.SeverityHigh, map[string]any{"listener": c.ID, "phase": "restart", "error": err.Error()})
			} else {
				slog.Info("listener restarted", "id", c.ID)
			}
		case "added":
			if err := s.startListener(newIDs[c.ID]); err != nil {
				slog.Error("listener start failed", "id", c.ID, "err", err)
				s.emitOpEvent("sensor:listener_error", event.SeverityHigh, map[string]any{"listener": c.ID, "phase": "start", "error": err.Error()})
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

// emitOpEvent pushes an operational/health event (listener stopped,
// canary watcher stopped, listener start error, …) onto the bus so it is
// stored + routed and surfaces in the web UI's /errors view. Non-blocking
// so a full bus during shutdown can't deadlock the caller.
func (s *Sensor) emitOpEvent(ruleID string, sev event.Severity, meta map[string]any) {
	ev := &event.Event{
		ID:       event.NewID(),
		Time:     timeNow(),
		Sensor:   s.name,
		RuleID:   ruleID,
		Severity: sev,
		Meta:     meta,
	}
	select {
	case s.bus <- ev:
	default:
	}
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
		// Bus loop runs under a panic guard: a malformed handler result
		// or a correlator bug shouldn't take down event flow for the
		// whole sensor. The guard logs + emits a high-severity panic
		// event before continuing with the next event.
		for ev := range s.bus {
			func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Error("bus loop panic recovered", "panic", r, "event_id", ev.ID)
					}
				}()
				s.enrich.Decorate(ev)
				// ATT&CK-tag the event before correlation so the
				// storyline correlator can build its tactic chain from
				// the same techniques every downstream sees. D3FEND
				// defenses are stamped centrally by router.Dispatch.
				if len(ev.MitreTechniques) == 0 {
					tag := mitre.Lookup(ev.RuleID, ev.Handler)
					ev.MitreTechniques = tag.Techniques
					ev.MitreTactics = tag.Tactics
				}
				// Decode the captured payload once; share it with the
				// payload harvester and scan-analysis (both need the bytes).
				var payloadBytes []byte
				if ev.PayloadBase64 != "" {
					if b, err := base64.StdEncoding.DecodeString(ev.PayloadBase64); err == nil {
						payloadBytes = b
					}
				}
				// Device learning: feed the source/MAC/hostname into
				// the registry and emit device:new for never-before-
				// seen, non-allow-listed hosts.
				if devNew := s.observeDevice(ev); devNew != nil {
					s.router.Dispatch(devNew)
				}
				// Payload harvesting: extract malware / shellcode /
				// ingress URLs from the captured bytes; persist
				// artifacts and emit malware:capture when one is found.
				if mw := s.observePayload(ev, payloadBytes); mw != nil {
					s.router.Dispatch(mw)
				}
				// Scan analysis: feed listener events into the
				// per-source Tracker; emit scananalysis:profile when a
				// source's timing / scope / probe variety crosses the
				// confidence threshold.
				if scanEv := s.observeScan(ev, payloadBytes); scanEv != nil {
					s.router.Dispatch(scanEv)
				}
				for _, out := range s.correlator.Observe(ev) {
					if out != ev {
						s.enrich.Decorate(out)
					}
					s.router.Dispatch(out)
				}
			}()
		}
	}()
	_ = safego.PanicCount // keep import alive when sensor body has no other safego use yet

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
				s.emitOpEvent("sensor:canary_stopped", event.SeverityMedium, map[string]any{"error": err.Error()})
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

	// One ARP responder per honeynet (each can pin to its own interface).
	for _, hn := range s.cfg.Honeynets {
		if hn.ARP.Enabled {
			ifaceName := hn.ARP.Interface
			netID := hn.ID
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := s.honeynet.StartARPResponder(ctx, ifaceName); err != nil {
					slog.Warn("honeynet arp responder disabled", "honeynet", netID, "err", err)
				}
				<-ctx.Done()
			}()
		}
		if hn.ICMP.Enabled {
			ifaceName := hn.ICMP.Interface
			netID := hn.ID
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := s.honeynet.StartICMPResponder(ctx, ifaceName); err != nil {
					slog.Warn("honeynet icmp responder disabled", "honeynet", netID, "err", err)
				}
				<-ctx.Done()
			}()
		}
		if hn.LLDP.Enabled {
			lldpCfg := honeynet.LLDPCfg{
				Enabled:    true,
				Interface:  hn.LLDP.Interface,
				Interval:   hn.LLDP.IntervalS,
				IncludeCDP: hn.LLDP.IncludeCDP,
			}
			netID := hn.ID
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := honeynet.StartLLDPResponder(ctx, lldpCfg, s.honeynet); err != nil {
					slog.Warn("honeynet lldp responder disabled", "honeynet", netID, "err", err)
				}
				<-ctx.Done()
			}()
		}
		if hn.PROFINET.Enabled {
			pnCfg := honeynet.ProfinetCfg{
				Enabled:   true,
				Interface: hn.PROFINET.Interface,
			}
			sev := event.SeverityHigh
			if s, err := event.ParseSeverity(hn.PROFINET.Severity); err == nil {
				sev = s
			}
			netID := hn.ID
			onProbe := func(srcMAC string, meta map[string]any) {
				if meta == nil {
					meta = map[string]any{}
				}
				meta["src_mac"] = srcMAC
				meta["honeynet"] = netID
				ev := &event.Event{
					ID:       event.NewID(),
					Time:     timeNow(),
					Sensor:   s.name,
					RuleID:   "honeynet:profinet_dcp_identify",
					Severity: sev,
					Proto:    "profinet",
					Meta:     meta,
				}
				select {
				case s.bus <- ev:
				default:
				}
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := honeynet.StartProfinetDCP(ctx, pnCfg, s.honeynet, onProbe); err != nil {
					slog.Warn("honeynet profinet responder disabled", "honeynet", netID, "err", err)
				}
				<-ctx.Done()
			}()
		}
		if hn.TUN.Enabled {
			hostIPs := make([]string, 0, len(hn.Hosts))
			personas := make(map[string]int, len(hn.Hosts))
			for _, h := range hn.Hosts {
				hostIPs = append(hostIPs, h.IP)
				// TCP/IP stack personality: stamp synthesized RST + ICMP
				// replies with the host's OS-characteristic initial TTL.
				if prof := archetype.Lookup(h.Archetype); prof != nil {
					personas[h.IP] = prof.ICMPTTL()
				} else if prof := archetype.Lookup(h.OS); prof != nil {
					personas[h.IP] = prof.ICMPTTL()
				}
			}
			cidrs := []string{hn.CIDR}
			tunCfg := tunnet.Config{
				DeviceName: hn.TUN.Device,
				CIDRs:      cidrs,
				HostIPs:    hostIPs,
				MTU:        hn.TUN.MTU,
				Personas:   personas,
			}
			netID := hn.ID
			wg.Add(1)
			go func() {
				defer wg.Done()
				adapter, err := tunnet.New(tunCfg)
				if err != nil {
					slog.Warn("honeynet tun adapter disabled", "honeynet", netID, "err", err)
					return
				}
				if err := adapter.Run(ctx); err != nil {
					slog.Error("honeynet tun adapter stopped", "honeynet", netID, "err", err)
				}
				_ = adapter.Close()
			}()
		}
	}

	// Device-registry periodic save — flushes the learned baseline to
	// disk every 60s so an unclean shutdown doesn't lose much.
	if s.devices != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t := time.NewTicker(60 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := s.devices.Save(); err != nil {
						slog.Warn("device registry periodic save failed", "err", err)
					}
				}
			}
		}()
		slog.Info("device tracking up", "learn", s.cfg.Devices.Learn, "allow_entries", len(s.cfg.Devices.Allow))
	}

	// Correlator state periodic save — windowed detector state to disk
	// every 60s so an unclean shutdown doesn't lose much (slow-scan in
	// particular spans 24h).
	if s.cfg.Sensor.DataDir != "" {
		statePath := correlate.StatePath(s.cfg.Sensor.DataDir)
		wg.Add(1)
		go func() {
			defer wg.Done()
			t := time.NewTicker(60 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := s.correlator.Save(statePath); err != nil {
						slog.Warn("correlator periodic save failed", "err", err)
					}
				}
			}
		}()
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
	if s.enrich != nil {
		_ = s.enrich.Close()
	}
	if s.devices != nil {
		if err := s.devices.Save(); err != nil {
			slog.Warn("device registry save failed", "err", err)
		}
	}
	if s.correlator != nil && s.cfg.Sensor.DataDir != "" {
		if err := s.correlator.Save(correlate.StatePath(s.cfg.Sensor.DataDir)); err != nil {
			slog.Warn("correlator state save failed", "err", err)
		}
	}
	return nil
}
