// Package egress is the sensor's outbound allowlist. A honeypot must never be
// usable as an SSRF pivot, open relay, reflector, or exfil channel — but its own
// telemetry has to leave the box: forwarding events to a central collector /
// SIEM and exporting IOCs to a feed are themselves outbound sockets. So egress
// is not blanket-denied; it is allowlisted to exactly the destinations the
// operator configured (sink / forward / export endpoints), and every other
// outbound connection is refused and reported.
//
// All of the sensor's outbound consumers dial through this package's DialContext
// / HTTPClient, which consult a process-wide default Policy the sensor installs
// at startup. When no policy is installed (e.g. unit tests) egress is
// unrestricted, so the guard never changes behavior unless explicitly enabled.
package egress

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Policy is the outbound allowlist.
type Policy struct {
	mu      sync.RWMutex
	hosts   map[string]bool // "host" (any port) or "host:port"
	cidrs   []*net.IPNet
	onDeny  func(network, addr, reason string)
	dialer  *net.Dialer
	enabled bool
}

// New returns an empty, enabled policy (allows nothing until Allow is called).
func New() *Policy {
	return &Policy{hosts: map[string]bool{}, enabled: true, dialer: &net.Dialer{Timeout: 30 * time.Second}}
}

// SetOnDeny registers a callback invoked when a connection is refused (the
// sensor wires this to emit an egress:denied event).
func (p *Policy) SetOnDeny(f func(network, addr, reason string)) {
	p.mu.Lock()
	p.onDeny = f
	p.mu.Unlock()
}

// Allow permits a destination: a CIDR ("10.0.0.0/8"), a bare host/IP (any port),
// or a "host:port". Empty strings are ignored.
func (p *Policy) Allow(dest string) {
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ipnet, err := net.ParseCIDR(dest); err == nil {
		p.cidrs = append(p.cidrs, ipnet)
		return
	}
	// A bare host matches any port; a "host:port" is the tighter match. Register
	// whatever form was given (the sensor registers both where useful).
	p.hosts[strings.ToLower(dest)] = true
}

// Entries returns the allowlist as strings (hosts, host:ports, and CIDRs) — the
// source of truth the OS-level firewall mirrors.
func (p *Policy) Entries() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.hosts)+len(p.cidrs))
	for h := range p.hosts {
		out = append(out, h)
	}
	for _, c := range p.cidrs {
		out = append(out, c.String())
	}
	return out
}

// Allowed reports whether addr ("host:port") is permitted.
func (p *Policy) Allowed(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.ToLower(host)
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.hosts[strings.ToLower(addr)] || p.hosts[host] {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, c := range p.cidrs {
			if c.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// DialContext dials addr if it is allowlisted, else refuses and reports it.
func (p *Policy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if p == nil || !p.enabled || p.Allowed(addr) {
		return dialerOf(p).DialContext(ctx, network, addr)
	}
	p.mu.RLock()
	onDeny := p.onDeny
	p.mu.RUnlock()
	if onDeny != nil {
		onDeny(network, addr, "destination not in egress allowlist")
	}
	return nil, fmt.Errorf("egress denied: %s %s not in allowlist", network, addr)
}

// HTTPClient returns an http.Client whose connections are governed by the policy.
func (p *Policy) HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           p.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}}
}

func dialerOf(p *Policy) *net.Dialer {
	if p != nil && p.dialer != nil {
		return p.dialer
	}
	return &net.Dialer{Timeout: 30 * time.Second}
}

// --- process-wide default ---------------------------------------------------

var def atomic.Pointer[Policy]

// SetDefault installs the process-wide policy that the package-level DialContext
// / HTTPClient consult. Passing nil restores unrestricted egress.
func SetDefault(p *Policy) { def.Store(p) }

// Default returns the installed policy, or nil.
func Default() *Policy { return def.Load() }

// DialContext dials through the default policy (unrestricted if none installed).
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if p := def.Load(); p != nil {
		return p.DialContext(ctx, network, addr)
	}
	return (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, network, addr)
}

// HTTPClient returns an http.Client governed by the default policy. It binds to
// the package-level DialContext (which resolves the current default on every
// dial), so a client built before SetDefault still enforces once a policy is
// installed — order-independent.
func HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}}
}
