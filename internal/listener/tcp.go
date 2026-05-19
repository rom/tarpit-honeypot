package listener

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

var errUnknownProto = errors.New("unknown proto")

type tcpListener struct {
	cfg        config.Listener
	sensorName string
	sev        event.Severity
}

func newTCP(l config.Listener, sensorName string) (*tcpListener, error) {
	sev, err := event.ParseSeverity(l.Severity)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", l.ID, err)
	}
	return &tcpListener{cfg: l, sensorName: sensorName, sev: sev}, nil
}

func (t *tcpListener) ID() string { return t.cfg.ID }

func (t *tcpListener) Start(ctx context.Context, bus chan<- *event.Event) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", t.cfg.Bind)
	if err != nil {
		return fmt.Errorf("listener %s: listen %s: %w", t.cfg.ID, t.cfg.Bind, err)
	}
	slog.Info("listener up", "id", t.cfg.ID, "proto", "tcp", "bind", t.cfg.Bind, "mode", t.cfg.Mode)

	// Close on context cancel so Accept returns.
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
			// Transient accept errors shouldn't kill the listener.
			slog.Warn("accept error", "id", t.cfg.ID, "err", err)
			continue
		}
		go t.handle(ctx, conn, bus)
	}
}

func (t *tcpListener) handle(ctx context.Context, conn net.Conn, bus chan<- *event.Event) {
	defer conn.Close()

	src, dst := splitAddr(conn.RemoteAddr()), splitAddr(conn.LocalAddr())
	ev := &event.Event{
		ID:       event.NewID(),
		Time:     time.Now().UTC(),
		Sensor:   t.sensorName,
		RuleID:   "listener:" + t.cfg.ID,
		Severity: t.sev,
		Source:   src,
		Dest:     dst,
		Proto:    "tcp",
		Handler:  t.cfg.Handler,
	}

	if t.cfg.Mode == "banner" && t.cfg.Banner != "" {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte(t.cfg.Banner)); err != nil {
			ev.Meta = map[string]any{"banner_write_err": err.Error()}
		}
		ev.BannerSent = t.cfg.Banner
	}

	if t.cfg.ReadBytes > 0 && t.cfg.Mode != "drop" {
		_ = conn.SetReadDeadline(time.Now().Add(t.cfg.ReadTimeout))
		buf := make([]byte, t.cfg.ReadBytes)
		n, err := io.ReadFull(conn, buf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			// timeout or read error — still useful, just record it
			if ev.Meta == nil {
				ev.Meta = map[string]any{}
			}
			ev.Meta["read_err"] = err.Error()
		}
		if n > 0 {
			ev.PayloadLen = n
			ev.PayloadBase64 = base64.StdEncoding.EncodeToString(buf[:n])
		}
	}

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
