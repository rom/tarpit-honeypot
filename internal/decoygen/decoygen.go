// Package decoygen scans an operator's own network and generates a
// tarpit-honeypot listener config that mirrors the services it finds — so the
// honeypot blends into the environment it is deployed in instead of exposing a
// tell-tale generic service set.
//
// SCOPE & SAFETY. This is a benign TCP connect scanner: it completes a normal
// three-way handshake, optionally reads a server banner (or sends one minimal,
// well-formed probe for client-first protocols), records the port/banner, and
// closes. It never sends exploit traffic, never does stealth/SYN scanning, and
// never writes to the target. It is bounded by an explicit target list, a host
// cap, bounded concurrency, and per-connection timeouts. It is intended to be
// run by the network's operator against their own authorized estate; callers
// (the CLI) surface that requirement to the user.
package decoygen

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultPorts is the curated set the scanner probes when the operator does
// not specify --ports: the common enterprise / datastore / web / ICS services
// this sensor can emulate. TCP only (a connect scan to UDP is not meaningful).
var DefaultPorts = []int{
	21, 22, 23, 25, 80, 102, 110, 143, 389, 443, 445, 502, 587, 631, 636,
	993, 995, 1433, 1521, 1883, 2375, 2376, 3306, 3389, 5432, 5900, 5985,
	5986, 6379, 8080, 8443, 9200, 11211, 27017,
}

// tlsPorts are probed with a TLS handshake (to read the cert CN for a more
// faithful decoy) rather than a plaintext banner read.
var tlsPorts = map[int]bool{
	443: true, 8443: true, 636: true, 993: true, 995: true, 5986: true, 2376: true,
}

// portHandler maps a well-known port to the honeypot handler that emulates it.
// Banner-based refinement (classify) can override this when a service is found
// on a non-standard port.
var portHandler = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp_recv", 80: "http",
	102: "s7", 110: "pop3", 143: "imap", 389: "ldap", 443: "https",
	445: "smb", 502: "modbus", 587: "smtp_recv", 631: "ipp", 636: "ldaps",
	993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle_tns", 1883: "mqtt",
	2375: "dockerapi", 2376: "dockerapi", 3306: "mysql", 3389: "rdp",
	5432: "postgres", 5900: "vnc", 5985: "winrm", 5986: "winrm", 6379: "redis",
	8080: "http", 8443: "https", 9200: "elasticsearch", 11211: "memcached",
	27017: "mongodb",
}

// Options controls a scan.
type Options struct {
	Targets     []string // hosts, host:port, or CIDRs
	Ports       []int    // ports to probe when a target has no explicit port
	Timeout     time.Duration
	Concurrency int
	MaxHosts    int  // hard cap on expanded host count (anti-mass-scan)
	GrabBanners bool // read a server banner / cert CN for refinement
}

// PortsOrDefault returns the configured ports, or DefaultPorts when none were
// set. Lets callers report the effective port count before a scan.
func (o Options) PortsOrDefault() []int {
	if len(o.Ports) == 0 {
		return DefaultPorts
	}
	return o.Ports
}

// Service is one discovered open port on one host.
type Service struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Handler string `json:"handler"`
	TLS     bool   `json:"tls"`
	Banner  string `json:"banner,omitempty"`
	CertCN  string `json:"cert_cn,omitempty"`
}

// Result is the outcome of a scan.
type Result struct {
	Hosts    int       `json:"hosts_scanned"`
	Ports    int       `json:"ports_probed"`
	Services []Service `json:"services"`
}

const (
	maxBannerBytes  = 512
	hardHostCeiling = 65536 // never expand beyond this regardless of MaxHosts
)

// Scan probes the targets and returns the open services found. It returns an
// error only for misconfiguration (bad targets, scope too large); individual
// connection failures are simply "port closed".
func Scan(ctx context.Context, opts Options) (Result, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 64
	}
	if opts.MaxHosts <= 0 {
		opts.MaxHosts = 256
	}
	if opts.MaxHosts > hardHostCeiling {
		opts.MaxHosts = hardHostCeiling
	}
	if len(opts.Ports) == 0 {
		opts.Ports = DefaultPorts
	}

	// Expand targets into (host, []port) probe units.
	type unit struct {
		host  string
		ports []int
	}
	var units []unit
	hostSeen := map[string]bool{}
	addHost := func(h string, ports []int) error {
		if hostSeen[h] {
			return nil
		}
		if len(hostSeen) >= opts.MaxHosts {
			return fmt.Errorf("target scope exceeds --max-hosts=%d; narrow the targets (this is a setup helper, not a mass scanner)", opts.MaxHosts)
		}
		hostSeen[h] = true
		units = append(units, unit{host: h, ports: ports})
		return nil
	}

	for _, t := range opts.Targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		switch {
		case strings.Contains(t, "/"): // CIDR
			ips, err := expandCIDR(t, opts.MaxHosts)
			if err != nil {
				return Result{}, err
			}
			for _, ip := range ips {
				if err := addHost(ip, opts.Ports); err != nil {
					return Result{}, err
				}
			}
		default:
			if host, portStr, err := net.SplitHostPort(t); err == nil {
				p, perr := strconv.Atoi(portStr)
				if perr != nil || p < 1 || p > 65535 {
					return Result{}, fmt.Errorf("bad port in target %q", t)
				}
				if err := addHost(host, []int{p}); err != nil {
					return Result{}, err
				}
			} else {
				if err := addHost(t, opts.Ports); err != nil {
					return Result{}, err
				}
			}
		}
	}
	if len(units) == 0 {
		return Result{}, fmt.Errorf("no targets to scan")
	}

	// Probe (host,port) pairs with bounded concurrency.
	type job struct {
		host string
		port int
	}
	jobs := make(chan job)
	var (
		mu      sync.Mutex
		found   []Service
		nProbes int
	)
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for j := range jobs {
			if ctx.Err() != nil {
				return
			}
			if svc, ok := probe(ctx, j.host, j.port, opts); ok {
				mu.Lock()
				found = append(found, svc)
				mu.Unlock()
			}
		}
	}
	n := opts.Concurrency
	wg.Add(n)
	for i := 0; i < n; i++ {
		go worker()
	}
	for _, u := range units {
		for _, p := range u.ports {
			nProbes++
			select {
			case <-ctx.Done():
			case jobs <- job{u.host, p}:
			}
		}
	}
	close(jobs)
	wg.Wait()

	sort.Slice(found, func(i, j int) bool {
		if found[i].Host != found[j].Host {
			return found[i].Host < found[j].Host
		}
		return found[i].Port < found[j].Port
	})
	return Result{Hosts: len(units), Ports: nProbes, Services: found}, ctx.Err()
}

// probe connects to host:port, optionally grabs a banner / cert, and classifies
// the service. ok=false means the port was closed/filtered.
func probe(ctx context.Context, host string, port int, opts Options) (Service, bool) {
	dctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := net.Dialer{}
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return Service{}, false
	}
	defer conn.Close()

	svc := Service{Host: host, Port: port, Handler: portHandler[port]}

	if opts.GrabBanners {
		if tlsPorts[port] {
			svc.TLS = true
			if cn := grabCertCN(host, conn, opts.Timeout); cn != "" {
				svc.CertCN = cn
			}
		} else {
			svc.Banner = grabBanner(conn, port, opts.Timeout)
		}
	}
	// Refine the handler from the banner when the port is unknown or the banner
	// clearly identifies a different protocol.
	if h := classify(port, svc.Banner); h != "" {
		svc.Handler = h
	}
	if svc.Handler == "" {
		svc.Handler = "auto" // unknown service → generic catch-all
	}
	return svc, true
}

// grabBanner reads a server-first banner; for known client-first protocols it
// sends one minimal, well-formed probe first. Never sends anything abusive.
func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, maxBannerBytes)
	n, _ := conn.Read(buf)
	if n == 0 {
		// Client-first protocols (HTTP) won't speak first; nudge with a
		// benign request, then read the response line.
		if port == 80 || port == 8080 || port == 8888 {
			_ = conn.SetWriteDeadline(time.Now().Add(timeout))
			_, _ = conn.Write([]byte("GET / HTTP/1.0\r\nHost: scan\r\n\r\n"))
			_ = conn.SetReadDeadline(time.Now().Add(timeout))
			n, _ = conn.Read(buf)
		}
	}
	return sanitizeBanner(buf[:n])
}

// grabCertCN does a TLS handshake (no verification — we are fingerprinting, not
// trusting) and returns the leaf certificate's Common Name.
func grabCertCN(host string, conn net.Conn, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	c := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host}) //nolint:gosec
	if err := c.Handshake(); err != nil {
		return ""
	}
	st := c.ConnectionState()
	if len(st.PeerCertificates) > 0 {
		return st.PeerCertificates[0].Subject.CommonName
	}
	return ""
}

// sanitizeBanner trims a captured banner to one printable, single-line snippet
// safe to drop into a YAML comment.
func sanitizeBanner(b []byte) string {
	s := string(b)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	var out strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			out.WriteRune(r)
		}
	}
	res := strings.TrimSpace(out.String())
	if len(res) > 120 {
		res = res[:120]
	}
	return res
}

// classify refines the handler from a captured banner so a service on a
// non-standard port is still emulated correctly. Returns "" to keep the
// port-based default.
func classify(port int, banner string) string {
	if banner == "" {
		return ""
	}
	b := strings.ToLower(banner)
	switch {
	case strings.HasPrefix(banner, "SSH-"):
		return "ssh"
	case strings.HasPrefix(b, "http/"):
		return "http"
	case strings.HasPrefix(banner, "220") && strings.Contains(b, "ftp"):
		return "ftp"
	case strings.HasPrefix(banner, "220") && (strings.Contains(b, "smtp") || strings.Contains(b, "esmtp")):
		return "smtp_recv"
	case strings.HasPrefix(banner, "+OK") && strings.Contains(b, "pop"):
		return "pop3"
	case strings.HasPrefix(banner, "* OK") && strings.Contains(b, "imap"):
		return "imap"
	case strings.HasPrefix(b, "-err") || strings.Contains(b, "redis"):
		return "redis"
	}
	return ""
}

// expandCIDR lists host addresses in a CIDR, refusing ranges wider than the
// cap (so a stray /8 can't turn this into a mass scanner).
func expandCIDR(cidr string, max int) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("bad CIDR %q: %w", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	// 2^hostBits hosts; guard before allocating.
	if hostBits > 20 { // > ~1M addresses: refuse outright
		return nil, fmt.Errorf("CIDR %q is too large (%d host bits); narrow it", cidr, hostBits)
	}
	var out []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); incIP(cur) {
		out = append(out, cur.String())
		if len(out) > max {
			return nil, fmt.Errorf("CIDR %q expands to more than --max-hosts=%d addresses; narrow it", cidr, max)
		}
	}
	return out, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
