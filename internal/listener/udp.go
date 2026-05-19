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
)

type udpListener struct {
	cfg        config.Listener
	sensorName string
	sev        event.Severity
}

func newUDP(l config.Listener, sensorName string) (*udpListener, error) {
	sev, err := event.ParseSeverity(l.Severity)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", l.ID, err)
	}
	return &udpListener{cfg: l, sensorName: sensorName, sev: sev}, nil
}

func (u *udpListener) ID() string { return u.cfg.ID }

func (u *udpListener) Start(ctx context.Context, bus chan<- *event.Event) error {
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp", u.cfg.Bind)
	if err != nil {
		return fmt.Errorf("listener %s: listen %s: %w", u.cfg.ID, u.cfg.Bind, err)
	}
	slog.Info("listener up", "id", u.cfg.ID, "proto", "udp", "bind", u.cfg.Bind, "mode", u.cfg.Mode)
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
			// timeout is expected; keep looping
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
		if n > 0 {
			ev.PayloadLen = n
			ev.PayloadBase64 = base64.StdEncoding.EncodeToString(buf[:n])
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
