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
	"github.com/rom/tarpit-honeypot/internal/listener/handler"
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
}

func newTCP(l config.Listener, sensorName, dataDir string, capMgr *capture.Manager, urlCanaries []config.URLCanary, urlSevByID map[string]event.Severity) (*tcpListener, error) {
	sev, err := event.ParseSeverity(l.Severity)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", l.ID, err)
	}
	t := &tcpListener{cfg: l, sensorName: sensorName, sev: sev, urlCanarySev: urlSevByID}
	if l.Mode == "banner" {
		h, err := handler.Get(l.Handler, dataDir, urlCanaries)
		if err != nil {
			return nil, fmt.Errorf("listener %s: %w", l.ID, err)
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
		go t.handle(ctx, conn, bus)
	}
}

func (t *tcpListener) handle(ctx context.Context, conn net.Conn, bus chan<- *event.Event) {
	src, dst := splitAddr(conn.RemoteAddr()), splitAddr(conn.LocalAddr())
	start := time.Now()

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
		_ = conn.Close()
		finish(ev)

	case "banner":
		ev := t.baseEvent(eventID, src, dst, start)
		var canaryHits []string
		if t.handler != nil {
			res, _ := t.handler.Handle(ctx, conn, t.cfg)
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
