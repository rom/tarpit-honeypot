package listener

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/honeynet"
	"github.com/rom/tarpit-honeypot/internal/listener/handler"
)

type udpListener struct {
	cfg        config.Listener
	sensorName string
	sev        event.Severity
	handler    handler.UDPHandler
	topo       *honeynet.Topology
}

func newUDP(l config.Listener, sensorName string, topo *honeynet.Topology, hnView handler.HoneynetSnapshot, deps handler.Deps) (*udpListener, error) {
	sev, err := event.ParseSeverity(l.Severity)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", l.ID, err)
	}
	u := &udpListener{cfg: l, sensorName: sensorName, sev: sev, topo: topo}
	if l.Mode == "banner" {
		h, err := handler.GetUDP(l.Handler, deps)
		if err != nil {
			return nil, fmt.Errorf("listener %s: %w", l.ID, err)
		}
		if aware, ok := h.(handler.HoneynetAware); ok && len(hnView.Hosts) > 0 {
			aware.SetHoneynetView(hnView)
		}
		u.handler = h
	}
	return u, nil
}

func (u *udpListener) ID() string { return u.cfg.ID }

func (u *udpListener) Start(ctx context.Context, bus chan<- *event.Event) error {
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp", u.cfg.Bind)
	if err != nil {
		return fmt.Errorf("listener %s: listen %s: %w", u.cfg.ID, u.cfg.Bind, err)
	}
	slog.Info("listener up", "id", u.cfg.ID, "proto", "udp", "bind", u.cfg.Bind, "mode", u.cfg.Mode, "handler", u.cfg.Handler)
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()

	bufSize := u.cfg.ReadBytes
	if bufSize == 0 {
		bufSize = 1500
	}
	buf := make([]byte, bufSize)

	dstHost, dstPort := hostPort(pc.LocalAddr())

	for {
		_ = pc.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			slog.Warn("udp read error", "id", u.cfg.ID, "err", err)
			continue
		}
		srcHost, srcPort := hostPort(raddr)
		ev := &event.Event{
			ID:       event.NewID(),
			Time:     time.Now().UTC(),
			Sensor:   u.sensorName,
			RuleID:   "listener:" + u.cfg.ID,
			Severity: u.sev,
			Source:   event.Endpoint{IP: srcHost, Port: srcPort},
			Dest:     event.Endpoint{IP: dstHost, Port: dstPort},
			Proto:    "udp",
			Handler:  u.cfg.Handler,
		}
		// Honeynet dispatch (same model as TCP): destination IP may map to
		// a virtual host; if so, use the host-specific handler instance.
		activeHandler := u.handler
		if h, uh, _ := u.topo.LookupUDP(dstHost, dstPort); h != nil && uh != nil {
			activeHandler = uh
			tagHoneynet(ev, h)
		}
		// Copy out the packet before launching the handler goroutine because
		// the next ReadFrom will reuse buf.
		payload := append([]byte(nil), buf[:n]...)
		var res handler.Result
		if activeHandler != nil && u.cfg.Mode == "banner" {
			func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Error("udp handler panic recovered",
							"listener", u.cfg.ID, "panic", r)
					}
				}()
				res, _ = activeHandler.Handle(ctx, payload, raddr, pc, u.cfg)
			}()
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
		} else if n > 0 {
			ev.PayloadLen = n
			ev.PayloadBase64 = base64.StdEncoding.EncodeToString(payload)
		}
		select {
		case bus <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}

func hostPort(a net.Addr) (string, int) {
	host, portStr, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), 0
	}
	port := 0
	for _, c := range portStr {
		if c < '0' || c > '9' {
			port = 0
			break
		}
		port = port*10 + int(c-'0')
	}
	return host, port
}
