// Package handler holds the built-in TCP application-layer handlers used by
// the "banner" listener mode. They send a small, plausible response and read
// a bounded amount of client data so the listener can record what the
// attacker sent.
//
// Handlers are intentionally minimal: enough to fool a banner-grab tool,
// not enough to support a real protocol session.
package handler

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
)

// Deps carries the cross-cutting dependencies handlers need: deployment
// identity (for per-deployment uniqueness in fixed strings), jitter for
// response timing noise, dataDir for cert / state persistence, and the
// URL canary list for HTTP/HTTPS matching.
type Deps struct {
	Identity    *identity.Identity
	Jitter      *jitter.Jitterer
	DataDir     string
	URLCanaries []config.URLCanary
	TLSRotate   int // days; 0 = never rotate
	// HoneynetView is a side-channel for topology-exposing handlers
	// (snmp / ldap / dcerpc) so they can advertise the honeynet hosts
	// in their query responses. Avoids importing internal/honeynet
	// directly (which would create a build cycle with the listener
	// dispatch path).
	HoneynetView HoneynetSnapshot
}

// HoneynetSnapshot is a flat read-only view of every honeynet host. The
// sensor populates it from internal/honeynet.Topology at New time. It's
// safe to share by value because the underlying slices are owned by the
// snapshot itself.
type HoneynetSnapshot struct {
	Hosts []HoneynetHost
}

type HoneynetHost struct {
	NetID    string
	IP       string
	Hostname string
	OS       string
	MAC      string
	Services []HoneynetService
}

type HoneynetService struct {
	Port    int
	Handler string
}

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

// Get returns the handler implementation for the named handler. Pass a
// Deps struct so handlers can use identity / jitter / URL canaries.
// nil-safe: handlers degrade to the static defaults when Deps fields
// are nil.
func Get(name string, deps Deps) (Handler, error) {
	switch name {
	case "raw":
		return &raw{}, nil
	case "ssh":
		return &ssh{id: deps.Identity, jit: deps.Jitter}, nil
	case "http":
		return &httpH{urlCanaries: deps.URLCanaries, id: deps.Identity, jit: deps.Jitter}, nil
	case "https":
		h, err := newHTTPS(deps.DataDir, deps.TLSRotate)
		if err != nil {
			return nil, err
		}
		h.urlCanaries = deps.URLCanaries
		h.id = deps.Identity
		h.jit = deps.Jitter
		return h, nil
	case "telnet":
		return &telnet{jit: deps.Jitter}, nil
	case "ftp":
		return &ftp{jit: deps.Jitter}, nil
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
		return &ethernetip{id: deps.Identity}, nil
	case "smb":
		return &smb{id: deps.Identity}, nil
	case "vnc":
		return &vnc{id: deps.Identity}, nil
	case "smtp_recv":
		return &smtpRecv{id: deps.Identity, jit: deps.Jitter}, nil
	case "rdp":
		return &rdp{}, nil
	case "winrm":
		return &winrm{}, nil
	case "dcerpc":
		return &dcerpc{}, nil
	case "ldap":
		return &ldap{}, nil
	case "kerberos":
		return &kerberos{}, nil
	case "postgres":
		return &postgres{}, nil
	case "mysql":
		return &mysql{id: deps.Identity}, nil
	case "redis":
		return &redis{}, nil
	case "syslog_tcp":
		return &syslogTCP{}, nil
	case "rtsp":
		return &rtsp{}, nil
	case "dockerapi":
		return &dockerapi{}, nil
	case "melsec":
		return &melsec{}, nil
	}
	return nil, fmt.Errorf("unknown handler %q", name)
}

// withTimeout sets the read+write deadline on conn for the duration d.
func withTimeout(conn net.Conn, d time.Duration) {
	deadline := time.Now().Add(d)
	_ = conn.SetReadDeadline(deadline)
	_ = conn.SetWriteDeadline(deadline)
}
