package listener

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/honeynet"
	"github.com/rom/tarpit-honeypot/internal/listener/handler"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

type udpListener struct {
	cfg        config.Listener
	sensorName string
	sev        event.Severity
	handler    handler.UDPHandler
	topo       *honeynet.Topology
	// binds is the set of host:port addresses to listen on. Empty = [cfg.Bind].
	binds []string
	// sessions tracks live connection-oriented UDP sessions by source address
	// (only used when cfg.UDPSession is set and the handler is session-aware).
	sessMu   sync.Mutex
	sessions map[string]*handler.UDPSession
}

// maxUDPSessions bounds the per-listener live-session table so a flood of
// distinct sources can't exhaust memory; beyond it we fall back to the
// stateless single-datagram path (still captured).
const maxUDPSessions = 2048

func newUDP(l config.Listener, sensorName string, topo *honeynet.Topology, hnView handler.HoneynetSnapshot, deps handler.Deps, binds []string) (*udpListener, error) {
	sev, err := event.ParseSeverity(l.Severity)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", l.ID, err)
	}
	u := &udpListener{cfg: l, sensorName: sensorName, sev: sev, topo: topo, binds: binds}
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
	binds := u.binds
	if len(binds) == 0 {
		binds = []string{u.cfg.Bind}
	}
	lc := net.ListenConfig{}
	var conns []net.PacketConn
	for _, b := range binds {
		pc, err := lc.ListenPacket(ctx, "udp", b)
		if err != nil {
			slog.Warn("listener bind failed", "id", u.cfg.ID, "proto", "udp", "bind", b, "err", err)
			continue
		}
		slog.Info("listener up", "id", u.cfg.ID, "proto", "udp", "bind", b, "mode", u.cfg.Mode, "handler", u.cfg.Handler)
		conns = append(conns, pc)
	}
	if len(conns) == 0 {
		return fmt.Errorf("listener %s: no usable bind among %v", u.cfg.ID, binds)
	}
	go func() {
		<-ctx.Done()
		for _, pc := range conns {
			_ = pc.Close()
		}
	}()
	var wg sync.WaitGroup
	for _, pc := range conns {
		wg.Add(1)
		go func(pc net.PacketConn) {
			defer wg.Done()
			u.readLoop(ctx, pc, bus)
		}(pc)
	}
	wg.Wait()
	return nil
}

// readLoop services one UDP socket until ctx is cancelled. Shared by every bind
// the listener owns; each gets its own receive buffer (concurrent reads).
func (u *udpListener) readLoop(ctx context.Context, pc net.PacketConn, bus chan<- *event.Event) {
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
				return
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

		// Connection-oriented path: when udp_session is enabled and the handler
		// is session-aware, demux this datagram into a per-source multi-datagram
		// session (one event emitted when the session ends). Falls through to
		// the stateless path if the session table is full.
		if sh, ok := activeHandler.(handler.UDPSessionHandler); ok && u.cfg.UDPSession && u.cfg.Mode == "banner" {
			if u.routeToSession(ctx, pc, raddr, payload, ev, bus, sh) {
				continue
			}
		}

		var res handler.Result
		if activeHandler != nil && u.cfg.Mode == "banner" {
			func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Error("udp handler panic recovered",
							"listener", u.cfg.ID, "panic", r)
					}
				}()
				// Reply-policy gate: mute / OT-muted policy discards WriteTo so
				// the handler captures the datagram but emits no reply / reflection.
				res, _ = activeHandler.Handle(ctx, payload, raddr, handler.GatePacketConn(pc, u.cfg.Handler), u.cfg)
			}()
		} else if n > 0 {
			ev.PayloadLen = n
			ev.PayloadBase64 = base64.StdEncoding.EncodeToString(payload)
		}
		u.finishUDPResult(ctx, ev, res, n, bus)
	}
}

// finishUDPResult merges a handler Result into the event, stamps traffic
// accounting + intent, and publishes it. Shared by the stateless datagram path
// and the connection-oriented session path.
func (u *udpListener) finishUDPResult(ctx context.Context, ev *event.Event, res handler.Result, n int, bus chan<- *event.Event) {
	if res.BannerSent != "" {
		ev.BannerSent = res.BannerSent
	}
	if len(res.Payload) > 0 {
		ev.PayloadLen = len(res.Payload)
		ev.PayloadBase64 = base64.StdEncoding.EncodeToString(res.Payload)
	}
	if res.Meta != nil {
		// Sanitize attacker-controlled string values recursively before merging
		// into the event meta — see tcp.go for the threat-model rationale.
		safe.SanitizeMetaStrings(res.Meta)
		if ev.Meta == nil {
			ev.Meta = map[string]any{}
		}
		for k, v := range res.Meta {
			ev.Meta[k] = v
		}
		if anoms, ok := res.Meta["anomalies"].([]string); ok {
			ev.Anomalies = append(ev.Anomalies, anoms...)
		}
	}
	if ev.Meta == nil {
		ev.Meta = map[string]any{}
	}
	ev.Meta["bytes_in"] = int64(n)
	ev.Meta["pkts_in"] = int64(1)
	if out := len(res.BannerSent); out > 0 {
		ev.Meta["bytes_out"] = int64(out)
		ev.Meta["pkts_out"] = int64(1)
	}
	deriveEventIntent(ev) // authoritative intent in exports/search/UI
	select {
	case bus <- ev:
	case <-ctx.Done():
	}
}

// routeToSession demuxes a datagram into a per-source UDP session, creating one
// (and a goroutine running the handler's HandleSession) on the first datagram.
// Returns false when the session table is full so the caller falls back to the
// stateless path. base is the per-datagram event template used to emit the
// session's single event on completion.
func (u *udpListener) routeToSession(ctx context.Context, pc net.PacketConn, raddr net.Addr, payload []byte, base *event.Event, bus chan<- *event.Event, sh handler.UDPSessionHandler) bool {
	key := raddr.String()
	u.sessMu.Lock()
	if u.sessions == nil {
		u.sessions = map[string]*handler.UDPSession{}
	}
	if s := u.sessions[key]; s != nil {
		u.sessMu.Unlock()
		s.Deliver(payload) // subsequent datagram for an in-flight session
		return true
	}
	if len(u.sessions) >= maxUDPSessions {
		u.sessMu.Unlock()
		return false
	}
	sess := handler.NewUDPSession(raddr, handler.GatePacketConn(pc, u.cfg.Handler), 64)
	u.sessions[key] = sess
	u.sessMu.Unlock()
	sess.Deliver(payload) // first datagram

	go func() {
		var res handler.Result
		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("udp session handler panic recovered", "listener", u.cfg.ID, "panic", r)
				}
			}()
			res, _ = sh.HandleSession(ctx, sess, u.cfg)
		}()
		u.sessMu.Lock()
		delete(u.sessions, key)
		u.sessMu.Unlock()
		sess.Close()
		u.finishUDPResult(ctx, base, res, len(payload), bus)
	}()
	return true
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
