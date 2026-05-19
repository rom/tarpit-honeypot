package listener

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/rom/tarpit-honeypot/internal/capture"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/honeynet"
	"github.com/rom/tarpit-honeypot/internal/listener/handler"
	"github.com/rom/tarpit-honeypot/internal/safego"
)

var errUnknownProto = errors.New("unknown proto")

type tcpListener struct {
	cfg          config.Listener
	sensorName   string
	sev          event.Severity
	handler      handler.Handler
	tarpit       *tarpitState
	captureMgr   *capture.Manager
	urlCanarySev map[string]event.Severity
	topo         *honeynet.Topology

	// sema is non-nil when the listener has a max_concurrent cap.
	// We acquire one slot per accepted connection and release on exit.
	sema chan struct{}
}

func newTCP(l config.Listener, sensorName string, deps handler.Deps, capMgr *capture.Manager, urlSevByID map[string]event.Severity, topo *honeynet.Topology) (*tcpListener, error) {
	sev, err := event.ParseSeverity(l.Severity)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", l.ID, err)
	}
	t := &tcpListener{cfg: l, sensorName: sensorName, sev: sev, urlCanarySev: urlSevByID, topo: topo}
	if l.Mode == "banner" {
		h, err := handler.Get(l.Handler, deps)
		if err != nil {
			return nil, fmt.Errorf("listener %s: %w", l.ID, err)
		}
		if aware, ok := h.(handler.HoneynetAware); ok && len(deps.HoneynetView.Hosts) > 0 {
			aware.SetHoneynetView(deps.HoneynetView)
		}
		t.handler = h
	}
	if l.Mode == "tarpit" {
		t.tarpit = newTarpitState()
	}
	if l.Capture {
		if capMgr == nil {
			return nil, fmt.Errorf("listener %s: capture requested but capture manager unavailable", l.ID)
		}
		t.captureMgr = capMgr
	}
	if l.MaxConcurrent > 0 {
		t.sema = make(chan struct{}, l.MaxConcurrent)
	}
	return t, nil
}

func (t *tcpListener) ID() string { return t.cfg.ID }

func (t *tcpListener) Start(ctx context.Context, bus chan<- *event.Event) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", t.cfg.Bind)
	if err != nil {
		return fmt.Errorf("listener %s: listen %s: %w", t.cfg.ID, t.cfg.Bind, err)
	}
	slog.Info("listener up", "id", t.cfg.ID, "proto", "tcp", "bind", t.cfg.Bind, "mode", t.cfg.Mode, "handler", t.cfg.Handler, "capture", t.captureMgr != nil)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("accept error", "id", t.cfg.ID, "err", err)
			continue
		}
		if t.sema != nil {
			select {
			case t.sema <- struct{}{}:
				// Acquired a slot. handle() will release on exit.
			default:
				// Cap exceeded. Drop with a low-severity event and close.
				go t.emitAcceptCap(ctx, conn, bus)
				continue
			}
		}
		safego.RunWithEvent("listener.tcp.handle/"+t.cfg.ID, bus, t.sensorName, func() {
			defer func() {
				if t.sema != nil {
					<-t.sema
				}
			}()
			t.handle(ctx, conn, bus)
		})
	}
}

// emitAcceptCap records that we refused a connection because the per-listener
// max_concurrent cap was hit. We emit at low severity — the operator likely
// already has a port_scan or brute_force aggregate for the source.
func (t *tcpListener) emitAcceptCap(ctx context.Context, conn net.Conn, bus chan<- *event.Event) {
	src, dst := splitAddr(conn.RemoteAddr()), splitAddr(conn.LocalAddr())
	_ = conn.Close()
	ev := &event.Event{
		ID:       event.NewID(),
		Time:     time.Now().UTC(),
		Sensor:   t.sensorName,
		RuleID:   "listener:" + t.cfg.ID + ":accept_cap",
		Severity: event.SeverityLow,
		Source:   src,
		Dest:     dst,
		Proto:    "tcp",
		Handler:  t.cfg.Handler,
		Meta: map[string]any{
			"reason":         "max_concurrent_reached",
			"max_concurrent": t.cfg.MaxConcurrent,
		},
	}
	send(ctx, bus, ev)
}

func (t *tcpListener) handle(ctx context.Context, conn net.Conn, bus chan<- *event.Event) {
	src, dst := splitAddr(conn.RemoteAddr()), splitAddr(conn.LocalAddr())
	start := time.Now()

	// Honeynet override: if the destination IP is part of a configured
	// honeynet host that serves this port, dispatch to the host-specific
	// handler instance (which has its own derived Identity, so banner /
	// version strings differ per virtual host).
	var hnHost *honeynet.Host
	hnHandler := t.handler
	if host, h, _ := t.topo.Lookup(dst.IP, dst.Port); host != nil && h != nil {
		hnHost = host
		hnHandler = h
	}

	eventID := event.NewID()
	var sess *capture.Session
	if t.captureMgr != nil && t.cfg.Mode != "drop" {
		// drop mode never reads/writes, so capturing it produces empty pcaps
		// — skip it. Tarpit and banner modes both benefit.
		sess = t.captureMgr.Begin(eventID, conn.RemoteAddr(), conn.LocalAddr())
		conn = &capture.Conn{Conn: conn, Sess: sess}
	}

	finish := func(ev *event.Event) {
		if sess != nil {
			path, truncated, err := sess.End()
			if err != nil {
				slog.Warn("capture end failed", "id", t.cfg.ID, "err", err)
			} else if path != "" {
				if ev.Meta == nil {
					ev.Meta = map[string]any{}
				}
				ev.Meta["capture_path"] = path
				if truncated {
					ev.Meta["capture_truncated"] = true
				}
			}
		}
		send(ctx, bus, ev)
	}

	switch t.cfg.Mode {
	case "drop":
		ev := t.baseEvent(eventID, src, dst, start)
		if hnHost != nil {
			tagHoneynet(ev, hnHost)
		}
		_ = conn.Close()
		finish(ev)

	case "banner":
		ev := t.baseEvent(eventID, src, dst, start)
		if hnHost != nil {
			tagHoneynet(ev, hnHost)
		}
		var canaryHits []string
		if hnHandler != nil {
			res, _ := hnHandler.Handle(ctx, conn, t.cfg)
			ev.BannerSent = res.BannerSent
			if len(res.Payload) > 0 {
				ev.PayloadLen = len(res.Payload)
				ev.PayloadBase64 = base64.StdEncoding.EncodeToString(res.Payload)
			}
			if res.Meta != nil {
				if ev.Meta == nil {
					ev.Meta = map[string]any{}
				}
				for k, v := range res.Meta {
					ev.Meta[k] = v
				}
				// Promote anomalies into a first-class event
				// field so SIEM routing rules can match on it
				// without re-parsing meta.
				if anoms, ok := res.Meta["anomalies"].([]string); ok {
					ev.Anomalies = append(ev.Anomalies, anoms...)
				}
			}
			canaryHits = res.CanaryHits
		}
		_ = conn.Close()
		finish(ev)
		for _, id := range canaryHits {
			sev := t.urlCanarySev[id]
			if sev == 0 {
				sev = event.SeverityCritical
			}
			ce := &event.Event{
				ID:       event.NewID(),
				Time:     time.Now().UTC(),
				Sensor:   t.sensorName,
				RuleID:   "canary:url:" + id,
				Severity: sev,
				Source:   src,
				Dest:     dst,
				Proto:    "tcp",
				Handler:  t.cfg.Handler,
				Meta:     map[string]any{"trigger_event_id": ev.ID},
			}
			send(ctx, bus, ce)
		}

	case "tarpit":
		maxPS, maxT := tarpitLimits(t.cfg)
		if !t.tarpit.tryAcquire(src.IP, maxPS, maxT) {
			t.emitTarpitDrop(ctx, bus, src, dst)
			_ = conn.Close()
			if sess != nil {
				_, _, _ = sess.End()
			}
			return
		}
		// Emit a tarpit_start event immediately so operators see who's stuck.
		startEv := t.baseEvent(eventID, src, dst, start)
		startEv.RuleID = "listener:" + t.cfg.ID + ":tarpit_start"
		if startEv.Meta == nil {
			startEv.Meta = map[string]any{}
		}
		startEv.Meta["tarpit_strategy"] = t.cfg.Tarpit.Strategy
		if hnHost != nil {
			tagHoneynet(startEv, hnHost)
		}
		send(ctx, bus, startEv)
		// runTarpit closes the connection and releases the state slot.
		// We bypass finish() because the tarpit_end event is emitted from
		// runTarpit itself; the capture write happens there.
		t.runTarpitWithCapture(ctx, conn, bus, start, src, dst, sess)
	}
}

func (t *tcpListener) baseEvent(id string, src, dst event.Endpoint, when time.Time) *event.Event {
	return &event.Event{
		ID:       id,
		Time:     when.UTC(),
		Sensor:   t.sensorName,
		RuleID:   "listener:" + t.cfg.ID,
		Severity: t.sev,
		Source:   src,
		Dest:     dst,
		Proto:    "tcp",
		Handler:  t.cfg.Handler,
	}
}

func send(ctx context.Context, bus chan<- *event.Event, ev *event.Event) {
	select {
	case bus <- ev:
	case <-ctx.Done():
	}
}

// tagHoneynet stamps an event with the artificial host's metadata so
// downstream sinks can group events by virtual machine identity.
func tagHoneynet(ev *event.Event, h *honeynet.Host) {
	if h == nil || ev == nil {
		return
	}
	if ev.Meta == nil {
		ev.Meta = map[string]any{}
	}
	ev.Meta["honeynet"] = h.NetID
	ev.Meta["honeynet_host"] = h.IP
	if h.Hostname != "" {
		ev.Meta["honeynet_hostname"] = h.Hostname
	}
	if h.OS != "" {
		ev.Meta["honeynet_os"] = h.OS
	}
}

func splitAddr(a net.Addr) event.Endpoint {
	host, portStr, err := net.SplitHostPort(a.String())
	if err != nil {
		return event.Endpoint{IP: a.String()}
	}
	port := 0
	for _, c := range portStr {
		if c < '0' || c > '9' {
			port = 0
			break
		}
		port = port*10 + int(c-'0')
	}
	return event.Endpoint{IP: host, Port: port}
}
