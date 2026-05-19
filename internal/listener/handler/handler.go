// Package handler holds the built-in TCP application-layer handlers used by
// the "banner" listener mode. They send a small, plausible response and read
// a bounded amount of client data so the listener can record what the
// attacker sent.
//
// Handlers are intentionally minimal: enough to fool a banner-grab tool,
// not enough to support a real protocol session. Full ICS / DB protocol
// handshakes are planned for v0.3.
package handler

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// Result is what a handler returns after a single connection interaction.
type Result struct {
	BannerSent string
	Payload    []byte
	Meta       map[string]any
}

// Handler is the contract that all banner-mode handlers implement.
type Handler interface {
	Name() string
	Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error)
}

// Get returns the handler implementation for the named handler.
// Caller is expected to have validated the name via config validation;
// unknown names return an error rather than panic.
func Get(name string, dataDir string) (Handler, error) {
	switch name {
	case "raw":
		return &raw{}, nil
	case "ssh":
		return &ssh{}, nil
	case "http":
		return &httpH{}, nil
	case "https":
		return newHTTPS(dataDir)
	case "telnet":
		return &telnet{}, nil
	case "ftp":
		return &ftp{}, nil
	}
	return nil, fmt.Errorf("unknown handler %q", name)
}

// withTimeout sets the read+write deadline on conn for the duration d.
func withTimeout(conn net.Conn, d time.Duration) {
	deadline := time.Now().Add(d)
	_ = conn.SetReadDeadline(deadline)
	_ = conn.SetWriteDeadline(deadline)
}
