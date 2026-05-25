package sensor

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/url"
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
	"github.com/rom/tarpit-honeypot/internal/egress"
	"github.com/rom/tarpit-honeypot/internal/enrich"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/forward"
	"github.com/rom/tarpit-honeypot/internal/fuzzdos"
	"github.com/rom/tarpit-honeypot/internal/honeynet"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/listener"
	"github.com/rom/tarpit-honeypot/internal/listener/handler"
	"github.com/rom/tarpit-honeypot/internal/mitre"
	"github.com/rom/tarpit-honeypot/internal/payload"
	"github.com/rom/tarpit-honeypot/internal/retention"
	"github.com/rom/tarpit-honeypot/internal/risk"
	"github.com/rom/tarpit-honeypot/internal/router"
	"github.com/rom/tarpit-honeypot/internal/safego"
	"github.com/rom/tarpit-honeypot/internal/scananalysis"
	"github.com/rom/tarpit-honeypot/internal/sessionrec"
	"github.com/rom/tarpit-honeypot/internal/sink"
	"github.com/rom/tarpit-honeypot/internal/sniffer"
	"github.com/rom/tarpit-honeypot/internal/store"
	"github.com/rom/tarpit-honeypot/internal/tunnet"
	"github.com/rom/tarpit-honeypot/internal/version"
)

// listenerHandle wraps a running listener so we can stop it individually
// (hot reload) without affecting the rest of the sensor.
type listenerHandle struct {
	cfg    config.Listener
	cancel context.CancelFunc
	done   chan struct{}
}

type Sensor struct {
	cfg         *config.Config
	name        string
	sinks       []sink.Sink
	router      *router.Router
	correlator  *correlate.Correlator
	store       *store.Store
	captureMgr  *capture.Manager
	identity    *identity.Identity
	jitter      *jitter.Jitterer
	archetype   *archetype.Profile
	honeynet    *honeynet.Topology
	enrich      *enrich.Enricher
	devices     *devices.Registry
	scanTrack   *scananalysis.Tracker
	fuzzTrack   *fuzzdos.Tracker
	sniffer     sniffer.Sniffer // set in Run when the AF_PACKET sniffer starts (guarded by stateMu)
	payloads    *payload.Store
	sessionRec  *sessionrec.Store
	risk        *risk.Scorer
	deviceSev   event.Severity
	seenSources map[string]struct{} // bus-loop-only: source:first_seen dedup
	bus         chan *event.Event
	forward     *forward.Group // fleet event forwarding (nil when no targets)

	rootCtx context.Context // parent ctx for listener-specific child contexts

	// stateMu guards the four fields that Reload() hot-swaps (cfg, router,
	// correlator, sinks) against concurrent reads from the bus loop, the
	// periodic save ticker, shutdown, and the public accessors.
	stateMu sync.RWMutex

	listenersMu sync.Mutex
	listeners   map[string]*listenerHandle
}

// curRouter / curCorrelator / curConfig / curSinks return the current
// hot-swappable state under the read lock, so a concurrent Reload() can't
// race the reader.
func (s *Sensor) curRouter() *router.Router {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.router
}

func (s *Sensor) curCorrelator() *correlate.Correlator {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.correlator
}

func (s *Sensor) curConfig() *config.Config {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.cfg
}

func (s *Sensor) curSinks() []sink.Sink {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.sinks
}

func (s *Sensor) curEnricher() *enrich.Enricher {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.enrich
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

	// Egress allowlist: install before building sinks (some sinks dial at
	// construction time) so the sensor's outbound telemetry is permitted to
	// exactly its configured channel destinations + Egress.Allow, and every
	// other outbound connection is refused. Off unless enabled, in which case
	// egress is unrestricted (no behavior change).
	var egPol *egress.Policy
	if cfg.Sensor.Egress.On() {
		egPol = egress.New()
		for _, ch := range cfg.Channels {
			for _, d := range sink.Dests(ch) {
				egPol.Allow(d)
			}
		}
		for _, f := range cfg.Forward {
			if d := forwardDest(f.URL); d != "" {
				egPol.Allow(d)
			}
		}
		for _, d := range cfg.Sensor.Egress.Allow {
			egPol.Allow(d)
		}
		egress.SetDefault(egPol)
		slog.Info("egress allowlist enabled", "channels", len(cfg.Channels), "extra_allow", len(cfg.Sensor.Egress.Allow))
	}

	// Fleet forwarding: ship this node's events to parent aggregator(s).
	var fwdGroup *forward.Group
	if fwds := buildForwarders(cfg, id); len(fwds) > 0 {
		fwdGroup = forward.NewGroup(fwds...)
		slog.Info("fleet forwarding enabled", "targets", len(fwds), "node", id.Seed())
	}

	var sinks []sink.Sink
	for _, ch := range cfg.Channels {
		if !ch.On() {
			slog.Info("channel disabled, skipping", "id", ch.ID, "type", ch.Type)
			continue
		}
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

	enr, err := enrich.New(enrichConfigFor(cfg))
	if err != nil {
		for _, s := range sinks {
			_ = s.Close()
		}
		if st != nil {
			_ = st.Close()
		}
		return nil, err
	}

	// Load the full MAC-vendor (OUI) database if one is configured, so both
	// the device inventory and event enrichment resolve vendors from it. Off
	// the hot path; failure is non-fatal (the built-in table still applies).
	if p := cfg.Sensor.OUIFile; p != "" {
		if n, err := devices.LoadOUIFile(p); err != nil {
			slog.Warn("oui database load failed; using built-in table", "path", p, "err", err)
		} else {
			slog.Info("oui database loaded", "path", p, "entries", n)
		}
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

	s := &Sensor{
		cfg:         cfg,
		name:        name,
		sinks:       sinks,
		router:      r,
		correlator:  cor,
		store:       st,
		captureMgr:  capMgr,
		identity:    id,
		jitter:      jit,
		archetype:   arch,
		honeynet:    topo,
		enrich:      enr,
		devices:     devReg,
		deviceSev:   devSev,
		scanTrack:   scananalysis.NewTracker(5 * time.Minute),
		fuzzTrack:   fuzzdos.NewTracker(60 * time.Second),
		payloads:    payloadStore,
		sessionRec:  sessRec,
		risk:        newRiskScorer(cfg.Risk),
		seenSources: map[string]struct{}{},
		bus:         make(chan *event.Event, 1024),
		forward:     fwdGroup,
		listeners:   map[string]*listenerHandle{},
	}
	// A refused outbound connection is a high-severity finding: it means a
	// handler (or a tampered config) tried to make the sensor connect somewhere
	// off the allowlist — an SSRF / relay / exfil attempt.
	if egPol != nil {
		egPol.SetOnDeny(func(network, addr, reason string) {
			s.emitOpEvent("egress:denied", event.SeverityHigh, map[string]any{
				"network": network, "addr": addr, "reason": reason,
			})
		})
	}
	return s, nil
}

// buildForwarders constructs the fleet forwarders from the config (resolving
// token / HMAC secrets from env, stamping this node's id).
func buildForwarders(cfg *config.Config, id *identity.Identity) []*forward.Forwarder {
	var out []*forward.Forwarder
	for _, f := range cfg.Forward {
		if !f.On() {
			continue
		}
		t := forward.Target{
			ID: f.ID, URL: f.URL, NodeID: id.Seed(),
			MaxBatch: f.MaxBatch, MaxAge: f.MaxAge, QueueSize: f.QueueSize, Timeout: f.Timeout,
		}
		if f.TokenEnv != "" {
			t.Token = os.Getenv(f.TokenEnv)
		}
		if f.HMACSecretEnv != "" {
			t.HMACSecret = []byte(os.Getenv(f.HMACSecretEnv))
		}
		if f.MinSeverity != "" {
			if sev, err := event.ParseSeverity(f.MinSeverity); err == nil {
				t.MinSeverity = sev
			}
		}
		out = append(out, forward.NewForwarder(t))
	}
	return out
}

// forwardDest extracts the "host:port" of a forward target URL for the egress
// allowlist.
func forwardDest(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// dispatch sends an event to the routing/sink fan-out and, when fleet
// forwarding is configured, to the parent aggregator(s). It stamps the
// originating sensor id (the fleet dedup key) when not already set — a
// forwarded event arriving at an aggregator keeps its original SensorID.
func (s *Sensor) dispatch(rt *router.Router, ev *event.Event) {
	if ev.SensorID == "" {
		ev.SensorID = s.identity.Seed()
	}
	rt.Dispatch(ev)
	if s.forward != nil {
		s.forward.Send(ev)
	}
}

// newRiskScorer returns a configured per-source risk scorer, or nil when
// risk scoring is disabled.
func newRiskScorer(c config.RiskScoring) *risk.Scorer {
	if !c.Enabled {
		return nil
	}
	return risk.New(risk.Config{
		Enabled: true, HalfLife: c.HalfLife,
		Elevated: c.Elevated, High: c.High, Critical: c.Critical,
	})
}

// Risk returns the per-source risk scorer (nil when disabled).
func (s *Sensor) Risk() *risk.Scorer { return s.risk }

// scoreRisk folds a dispatched event into the per-source risk scorer and,
// when the source escalates into a higher level, dispatches a risk:<level>
// alert. risk:* events are not re-scored (no feedback loop).
func (s *Sensor) scoreRisk(rt *router.Router, ev *event.Event) {
	if s.risk == nil || ev == nil || ev.Source.IP == "" || strings.HasPrefix(ev.RuleID, "risk:") {
		return
	}
	if level, score, crossed := s.risk.Observe(ev.Source.IP, ev.RuleID, int(ev.Severity), timeNow()); crossed {
		rt.Dispatch(s.riskEvent(ev, level, score))
	}
}

func (s *Sensor) riskEvent(src *event.Event, level string, score float64) *event.Event {
	sev := event.SeverityHigh
	switch level {
	case "critical":
		sev = event.SeverityCritical
	case "elevated":
		sev = event.SeverityMedium
	}
	e := &event.Event{
		ID:       event.NewID(),
		Time:     timeNow(),
		Sensor:   s.name,
		RuleID:   "risk:" + level,
		Severity: sev,
		Source:   src.Source,
		Proto:    src.Proto,
		Meta:     map[string]any{"score": score, "trigger_rule": src.RuleID},
	}
	if en := s.curEnricher(); en != nil {
		en.Decorate(e)
	}
	return e
}

// Honeynet returns the configured topology, or an empty topology if none.
// Used by the list-honeynets subcommand and the DNS canary listener.
func (s *Sensor) Honeynet() *honeynet.Topology { return s.honeynet }

// Devices returns the learned-device registry (nil when devices are
// disabled). Used by the list-devices subcommand.
func (s *Sensor) Devices() *devices.Registry { return s.devices }

// SnifferStats returns the AF_PACKET sniffer's L2 frame counters, and false
// when no sniffer is running (disabled, no CAP_NET_RAW, or non-Linux).
func (s *Sensor) SnifferStats() (sniffer.Stats, bool) {
	s.stateMu.RLock()
	sn := s.sniffer
	s.stateMu.RUnlock()
	if sn == nil {
		return sniffer.Stats{}, false
	}
	return sn.Stats(), true
}

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
		DestIP:      ev.Dest.IP,
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
		"distinct_hosts": r.DistinctHosts,
		"connections":    r.Conns,
		"version_scan":   r.VersionScan,
		"vuln_scan":      r.VulnScan,
		"os_scan":        r.OSScan,
		"aggressive":     r.Aggressive,
		"confidence":     r.Confidence,
	}
	if r.ScanShape != "" {
		meta["scan_shape"] = r.ScanShape
	}
	if r.PortOrder != "" {
		meta["port_order"] = r.PortOrder
	}
	if r.Stealthy {
		meta["stealthy"] = true
	}
	if r.Tool != "" {
		meta["tool"] = r.Tool
	}
	if len(r.Tools) > 0 {
		meta["tools"] = r.Tools
	}
	if len(r.NSEScripts) > 0 {
		meta["nse_scripts"] = r.NSEScripts
	}
	sev := event.SeverityMedium
	if r.Aggressive || r.VersionScan || r.VulnScan {
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

// observeFuzzDoS classifies fuzzing and denial-of-service activity. It
// runs the stateless payload classifier — stamping a fuzzing-<technique>
// anomaly + meta on the event in place so the protocol_violation
// correlator and downstream SIEM inherit it — and feeds the per-source
// Tracker, returning attack:dos / attack:fuzzing events when a source
// crosses a flood / campaign threshold. Must run before the correlator so
// the in-place anomaly is visible to it.
func (s *Sensor) observeFuzzDoS(ev *event.Event, payload []byte) []*event.Event {
	if s.fuzzTrack == nil || ev == nil || ev.Source.IP == "" {
		return nil
	}
	if !strings.HasPrefix(ev.RuleID, "listener:") {
		return nil
	}
	v := fuzzdos.ClassifyPayload(payload, ev.Handler)
	if v.Fuzzing {
		marker := "fuzzing-" + v.Technique
		if !containsStr(ev.Anomalies, marker) {
			ev.Anomalies = append(ev.Anomalies, marker)
		}
		if ev.Meta == nil {
			ev.Meta = map[string]any{}
		}
		ev.Meta["fuzz_technique"] = v.Technique
		ev.Meta["payload_entropy"] = math.Round(v.Entropy*100) / 100
	}
	bytesIn := int64(len(payload))
	if int64(ev.PayloadLen) > bytesIn {
		bytesIn = int64(ev.PayloadLen)
	}
	r := s.fuzzTrack.Observe(fuzzdos.Observation{
		SourceIP: ev.Source.IP,
		DestPort: ev.Dest.Port,
		Time:     ev.Time,
		Bytes:    bytesIn,
		Fuzz:     v,
		Slow:     containsStr(ev.Anomalies, "slow-request"),
	})
	if r == nil {
		return nil
	}
	var out []*event.Event
	if r.DoS {
		out = append(out, &event.Event{
			ID:       event.NewID(),
			Time:     ev.Time,
			Sensor:   s.name,
			RuleID:   "attack:dos",
			Severity: event.SeverityHigh,
			Source:   ev.Source,
			Proto:    ev.Proto,
			Meta: map[string]any{
				"dos_type":    r.DoSType,
				"connections": r.Conns,
				"bytes":       r.Bytes,
				"window_s":    int(r.Window.Seconds()),
				"confidence":  r.Confidence,
			},
		})
	}
	if r.Fuzzing {
		out = append(out, &event.Event{
			ID:       event.NewID(),
			Time:     ev.Time,
			Sensor:   s.name,
			RuleID:   "attack:fuzzing",
			Severity: event.SeverityHigh,
			Source:   ev.Source,
			Proto:    ev.Proto,
			Handler:  ev.Handler,
			Meta: map[string]any{
				"technique":  r.Technique,
				"fuzz_count": r.FuzzCount,
				"dest_port":  ev.Dest.Port,
				"window_s":   int(r.Window.Seconds()),
				"confidence": r.Confidence,
			},
		})
	}
	return out
}

// containsStr reports whether xs contains s.
func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
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
	if ev.RuleID == "device:new" || ev.RuleID == "device:changed" {
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
	// Enrich the observation so device knowledge builds up over time: the
	// sensor port hit, the handler interacted with, broadcast/multicast
	// learning, and client-fingerprint attributes other listeners captured.
	obs.Port = ev.Dest.Port
	if ev.Handler != "" {
		obs.Service = ev.Handler
		if obs.Source == devices.SourceConn && isBroadcastHandler(ev.Handler) {
			obs.Source = devices.SourceBroadcast
		}
	}
	obs.Attrs = deviceAttrsFromEvent(ev)
	if obs.IP == "" && obs.MAC == "" {
		return nil
	}
	res := s.devices.Observe(obs)
	d := res.Device
	if !res.New && len(res.Changed) == 0 {
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
	rule := "device:new"
	if !res.New {
		// An already-known device's IP/MAC/hostname rebound — a possible
		// ARP-spoof / impersonation / re-IP. Distinct from a brand-new host.
		rule = "device:changed"
		meta["changed"] = res.Changed
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     ev.Time,
		Sensor:   s.name,
		RuleID:   rule,
		Severity: s.deviceSev,
		Source:   event.Endpoint{IP: d.IP},
		Proto:    "device",
		Meta:     meta,
	}
}

// enrichConfigFor builds the enricher input from the sensor config. Shared
// by New and ReloadEnrichment so a SIGHUP re-reads the same set of files.
func enrichConfigFor(cfg *config.Config) enrich.Config {
	return enrich.Config{
		CityDB:      cfg.Sensor.GeoIP.CityDB,
		ASNDB:       cfg.Sensor.GeoIP.ASNDB,
		RDNSEnabled: cfg.Sensor.RDNS.Enabled,
		RDNSTimeout: cfg.Sensor.RDNS.Timeout,
		RDNSCache:   cfg.Sensor.RDNS.CacheSize,
		ThreatLists: threatListsFromConfig(cfg.Sensor.ThreatIntel),
		TorExitFile: torExitFile(cfg.Sensor.Tor),
		NetClass:    cfg.Sensor.NetClass.Enabled,
	}
}

// threatListsFromConfig maps the config threat-intel lists to the enrich
// package's input. Returns nil when disabled (no lists loaded).
func threatListsFromConfig(ti config.ThreatIntel) []enrich.ThreatList {
	if !ti.Enabled || len(ti.Lists) == 0 {
		return nil
	}
	out := make([]enrich.ThreatList, 0, len(ti.Lists))
	for _, l := range ti.Lists {
		out = append(out, enrich.ThreatList{Label: l.Label, File: l.File})
	}
	return out
}

// torExitFile returns the Tor exit-node list path when Tor tagging is on.
func torExitFile(t config.TorIntel) string {
	if !t.Enabled {
		return ""
	}
	return t.ExitFile
}

// isBroadcastHandler reports whether a handler answers a broadcast /
// multicast discovery protocol — a source seen on one is learned as a
// SourceBroadcast device.
func isBroadcastHandler(name string) bool {
	switch name {
	case "ssdp", "llmnr", "nbns", "mdns", "ws-discovery", "cldap", "coap":
		return true
	}
	return false
}

// deviceAttrsFromEvent extracts the client-fingerprint / capability
// attributes a handler captured into the event meta, so the device
// inventory accumulates them. Returns nil when there's nothing to record.
func deviceAttrsFromEvent(ev *event.Event) map[string]string {
	if ev.Meta == nil {
		return nil
	}
	attrs := map[string]string{}
	add := func(metaKey, attrKey string) {
		if v, ok := ev.Meta[metaKey].(string); ok && v != "" {
			attrs[attrKey] = v
		}
	}
	add("ja3", "ja3")
	add("ja4", "ja4")
	add("ja4h", "ja4h")
	add("hassh", "hassh")
	add("hassh_server", "hassh_server")
	add("user_agent", "ua")
	add("client_id", "ssh_client")
	// Snoop identity hints out of other protocols' captures.
	add("helo", "smtp_helo") // SMTP HELO/EHLO name the client announced
	add("vendor_class", "dhcp_vendor")
	add("os", "os")
	add("os_guess", "os_guess") // passive TTL fingerprint from the sniffer
	add("realm", "domain")
	if b, ok := ev.Meta["automation"].(bool); ok && b {
		attrs["automation"] = "true"
	}
	if ev.Handler != "" {
		attrs["last_service"] = ev.Handler
	}
	if tools := metaStringSlice(ev.Meta["tools"]); len(tools) > 0 {
		attrs["tools"] = strings.Join(tools, ",")
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

// metaStringSlice coerces a meta value (string / []string / the []any JSON
// decodes to) into a []string.
func metaStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{t}
	}
	return nil
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
func (s *Sensor) Router() *router.Router            { return s.curRouter() }
func (s *Sensor) Correlator() *correlate.Correlator { return s.curCorrelator() }
func (s *Sensor) Store() *store.Store               { return s.store }
func (s *Sensor) Config() *config.Config            { return s.curConfig() }

// DiskUsedPercent returns the data_dir filesystem usage percent (and ok=false
// on platforms without statfs). Used by the stats provider for the UI health
// dashboard + /metrics.
func (s *Sensor) DiskUsedPercent() (int, bool) {
	return diskUsedPercent(s.curConfig().Sensor.DataDir)
}

// effIface returns sectionIface if set, else the sensor's first configured
// interface, else "" — the AF_PACKET default-interface fallback.
func (s *Sensor) effIface(sectionIface string) string {
	if sectionIface != "" {
		return sectionIface
	}
	ifaces := s.curConfig().Sensor.Interfaces
	if len(ifaces) > 0 {
		return ifaces[0]
	}
	return ""
}

// bindForInterfaces rewrites a wildcard bind host to the primary IP of the
// first configured interface so sensor.interfaces constrains where
// listeners bind. Non-wildcard binds and the no-interfaces case pass
// through unchanged; if the interface has no usable IP we warn and keep
// the wildcard so the sensor still starts.
func (s *Sensor) bindForInterfaces(bind string) string {
	ifaces := s.curConfig().Sensor.Interfaces
	if len(ifaces) == 0 {
		return bind
	}
	host, port, err := net.SplitHostPort(bind)
	if err != nil || !isWildcardHost(host) {
		return bind
	}
	ip := ifacePrimaryIP(ifaces[0])
	if ip == "" {
		slog.Warn("interface has no usable IP; leaving bind wildcard",
			"interface", ifaces[0], "bind", bind)
		return bind
	}
	return net.JoinHostPort(ip, port)
}

func isWildcardHost(h string) bool {
	switch h {
	case "", "0.0.0.0", "::", "*":
		return true
	}
	return false
}

// ifacePrimaryIP returns the interface's primary global-unicast IP,
// preferring IPv4. Returns "" if the interface is unknown / has none.
func ifacePrimaryIP(name string) string {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return ""
	}
	var v6 string
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if ip.To4() != nil {
			return ip.String()
		}
		if v6 == "" {
			v6 = ip.String()
		}
	}
	return v6
}

// startListener builds and launches a single listener. It uses the sensor's
// rootCtx (set in Run) as the parent so global shutdown still cascades.
func (s *Sensor) startListener(l config.Listener) error {
	if s.rootCtx == nil {
		return fmt.Errorf("startListener called before Run()")
	}
	ctx, cancel := context.WithCancel(s.rootCtx)
	cfg := s.curConfig()
	// sensor.interfaces constrains where wildcard listeners bind.
	l.Bind = s.bindForInterfaces(l.Bind)
	ln, err := listener.Build(l, listener.BuildArgs{
		SensorName:       s.name,
		DataDir:          cfg.Sensor.DataDir,
		CaptureMgr:       s.captureMgr,
		URLCanaries:      cfg.URLCanaries,
		Identity:         s.identity,
		Jitter:           s.jitter,
		TLSRotate:        cfg.Sensor.TLSRotate.Days,
		SensorArchetype:  s.archetype,
		Honeynet:         s.honeynet,
		HoneynetSnapshot: honeynetSnapshot(s.honeynet),
		VulnEmulation:    cfg.Sensor.VulnEmulation,
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

	// Egress allowlist is additive on reload: permit any newly-configured
	// channel's destination so a reloaded sink isn't refused. (Removed
	// destinations stay allowed until restart — fail-open on the operator's own
	// telemetry, never on attacker egress.)
	if p := egress.Default(); p != nil {
		for _, ch := range newCfg.Channels {
			for _, d := range sink.Dests(ch) {
				p.Allow(d)
			}
		}
		for _, d := range newCfg.Sensor.Egress.Allow {
			p.Allow(d)
		}
	}

	// Sinks + router + correlator first; if either fails we keep the old set.
	var newSinks []sink.Sink
	for _, ch := range newCfg.Channels {
		if !ch.On() {
			continue
		}
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

	// Hot-swap router + correlator + sinks + cfg under the write lock so
	// the bus loop / accessors never see a torn pointer.
	s.stateMu.Lock()
	oldRouter := s.router
	oldSinks := s.sinks
	s.router = newRouter
	s.correlator = newCorrelator
	s.sinks = newSinks
	s.cfg = newCfg
	s.stateMu.Unlock()

	// Start the new router and tear down the old one outside the lock.
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

// ReloadEnrichment re-reads the enrichment databases (GeoIP, threat-intel,
// Tor exit list, OUI) from the paths in the CURRENT config and hot-swaps the
// enricher. Unlike Reload it does not depend on a config diff — the file
// CONTENTS may have changed (e.g. the enrichment installer refreshed them)
// while the config text is identical — so SIGHUP calls it unconditionally.
// Safe to call concurrently with the bus loop (the enricher is swapped under
// the same lock the bus loop reads it through).
func (s *Sensor) ReloadEnrichment() error {
	cfg := s.curConfig()
	if p := cfg.Sensor.OUIFile; p != "" {
		if n, err := devices.LoadOUIFile(p); err != nil {
			slog.Warn("reload: oui database re-read failed", "path", p, "err", err)
		} else {
			slog.Info("reload: oui database re-read", "path", p, "entries", n)
		}
	}
	enr, err := enrich.New(enrichConfigFor(cfg))
	if err != nil {
		return err
	}
	s.stateMu.Lock()
	old := s.enrich
	s.enrich = enr
	s.stateMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	slog.Info("reload: enrichment databases re-read")
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

	s.curRouter().Start(ctx)

	// Fleet forwarders: drain the per-target queues until shutdown.
	if s.forward != nil && !s.forward.Empty() {
		wg.Add(1)
		go func() { defer wg.Done(); s.forward.Run(ctx) }()
	}

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
				// Snapshot the hot-swappable router + correlator + enricher
				// once per event so a concurrent Reload() can't race us.
				rt := s.curRouter()
				co := s.curCorrelator()
				en := s.curEnricher()
				en.Decorate(ev)
				// ATT&CK-tag the event before correlation so the
				// storyline correlator can build its tactic chain from
				// the same techniques every downstream sees. D3FEND
				// defenses are stamped centrally by router.Dispatch.
				if len(ev.MitreTechniques) == 0 {
					tag := mitre.Lookup(ev.RuleID, ev.Handler)
					ev.MitreTechniques = tag.Techniques
					ev.MitreTactics = tag.Tactics
				}
				// First-seen: emit source:first_seen the first time a source
				// produces a >= medium event (opt-in, low-noise).
				if fs := s.observeFirstSeen(ev); fs != nil {
					s.dispatch(rt, fs)
					s.scoreRisk(rt, fs)
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
					s.dispatch(rt, devNew)
					s.scoreRisk(rt, devNew)
				}
				// Payload harvesting: extract malware / shellcode /
				// ingress URLs from the captured bytes; persist
				// artifacts and emit malware:capture when one is found.
				if mw := s.observePayload(ev, payloadBytes); mw != nil {
					s.dispatch(rt, mw)
					s.scoreRisk(rt, mw)
				}
				// Scan analysis: feed listener events into the
				// per-source Tracker; emit scananalysis:profile when a
				// source's timing / scope / probe variety crosses the
				// confidence threshold.
				if scanEv := s.observeScan(ev, payloadBytes); scanEv != nil {
					s.dispatch(rt, scanEv)
					s.scoreRisk(rt, scanEv)
				}
				// Fuzzing / DoS classification: stamps a fuzzing-<technique>
				// anomaly on ev in place (so the correlator below sees it)
				// and emits attack:dos / attack:fuzzing on a flood/campaign.
				for _, fdEv := range s.observeFuzzDoS(ev, payloadBytes) {
					s.dispatch(rt, fdEv)
					s.scoreRisk(rt, fdEv)
				}
				for _, out := range co.Observe(ev) {
					if out != ev {
						en.Decorate(out)
					}
					s.dispatch(rt, out)
					s.scoreRisk(rt, out)
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

	// Sensor lifecycle + health/digest operational events.
	s.emitOpEvent("sensor:started", event.SeverityMedium, map[string]any{
		"listeners": len(s.cfg.Listeners), "channels": len(s.curConfig().Channels),
		"honeynets": len(s.cfg.Honeynets), "version": version.Version,
	})
	wg.Add(1)
	go func() { defer wg.Done(); s.runHealthMonitor(ctx) }()
	if s.cfg.Sensor.Alerts.DigestInterval > 0 && s.store != nil {
		wg.Add(1)
		go func() { defer wg.Done(); s.runDigest(ctx) }()
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
		snCfg := s.cfg.Sniffer
		snCfg.Interface = s.effIface(snCfg.Interface)
		sn, err := sniffer.New(snCfg, s.name)
		if err != nil {
			slog.Warn("sniffer disabled", "err", err)
		} else {
			s.stateMu.Lock()
			s.sniffer = sn
			s.stateMu.Unlock()
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
			ifaceName := s.effIface(hn.ARP.Interface)
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
			ifaceName := s.effIface(hn.ICMP.Interface)
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
				Interface:  s.effIface(hn.LLDP.Interface),
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
				Interface: s.effIface(hn.PROFINET.Interface),
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
			netID := hn.ID
			tunCfg := tunnet.Config{
				DeviceName: hn.TUN.Device,
				CIDRs:      cidrs,
				HostIPs:    hostIPs,
				MTU:        hn.TUN.MTU,
				Personas:   personas,
				Hosts:      buildTUNDecoys(hn.Hosts),
				Emit:       s.tcpDecoyEmitter(netID),
			}
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
					if err := s.curCorrelator().Save(statePath); err != nil {
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
	drainTimeout := s.curConfig().Sensor.Shutdown.DrainTimeout
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

	// Final lifecycle event before the bus closes (still drained downstream).
	s.emitOpEvent("sensor:stopped", event.SeverityMedium, map[string]any{"sensor": s.name})

	close(s.bus)
	wg.Wait()
	s.curRouter().Stop()
	for _, sk := range s.curSinks() {
		_ = sk.Close()
	}
	if s.store != nil {
		_ = s.store.Close()
	}
	if en := s.curEnricher(); en != nil {
		_ = en.Close()
	}
	if s.devices != nil {
		if err := s.devices.Save(); err != nil {
			slog.Warn("device registry save failed", "err", err)
		}
	}
	if co, cfg := s.curCorrelator(), s.curConfig(); co != nil && cfg.Sensor.DataDir != "" {
		if err := co.Save(correlate.StatePath(cfg.Sensor.DataDir)); err != nil {
			slog.Warn("correlator state save failed", "err", err)
		}
	}
	return nil
}
