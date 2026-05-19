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
	// CanaryHits names any URL canaries (or other token canaries) that fired
	// while handling this connection. The listener turns each id into a
	// separate canary:url:<id> event so they correlate with the trap visit
	// but stand on their own for routing/severity.
	CanaryHits []string
}

// Handler is the contract that all banner-mode handlers implement.
type Handler interface {
	Name() string
	Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error)
}

// Get returns the handler implementation for the named handler.
// The dataDir is used by handlers that need to persist state (https cert
// cache). urlCanaries is passed to the http/https handlers for URL token
// matching; other handlers ignore it.
func Get(name string, dataDir string, urlCanaries []config.URLCanary) (Handler, error) {
	switch name {
	case "raw":
		return &raw{}, nil
	case "ssh":
		return &ssh{}, nil
	case "http":
		return &httpH{urlCanaries: urlCanaries}, nil
	case "https":
		h, err := newHTTPS(dataDir)
		if err != nil {
			return nil, err
		}
		h.urlCanaries = urlCanaries
		return h, nil
	case "telnet":
		return &telnet{}, nil
	case "ftp":
		return &ftp{}, nil
	case "modbus":
		return &modbus{}, nil
	case "s7":
		return &s7{}, nil
	case "iec104":
		return &iec104{}, nil
	case "mqtt":
		return &mqtt{}, nil
	case "opcua":
		return &opcua{}, nil
	case "ethernetip":
		return &ethernetip{}, nil
	case "smb":
		return &smb{}, nil
	}
	return nil, fmt.Errorf("unknown handler %q", name)
}

// withTimeout sets the read+write deadline on conn for the duration d.
func withTimeout(conn net.Conn, d time.Duration) {
	deadline := time.Now().Add(d)
	_ = conn.SetReadDeadline(deadline)
	_ = conn.SetWriteDeadline(deadline)
}
