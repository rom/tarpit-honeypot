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
	"os"
	"path/filepath"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/luaengine"
	"github.com/rom/tarpit-honeypot/internal/sessionrec"
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
	// Archetype, if set, pins SSH / HTTP / FTP / Telnet / SMTP /
	// MySQL banners to values consistent with a stock install of a
	// specific OS. nil = fall back to the identity-based variant
	// pool (v1.0 behavior).
	Archetype *archetype.Profile
	// AcceptCreds is the credential accept-policy for handlers that
	// can let an attacker "in" (ftp_files). One of "" / "none" /
	// "defaults" / "any".
	AcceptCreds string
	// HoneynetView is a side-channel for topology-exposing handlers
	// (snmp / ldap / dcerpc) so they can advertise the honeynet hosts
	// in their query responses. Avoids importing internal/honeynet
	// directly (which would create a build cycle with the listener
	// dispatch path).
	HoneynetView HoneynetSnapshot
	// VulnEmulation, when true, tells a banner-aware handler to
	// advertise a known-vulnerable version / patch-level (driven by
	// internal/cve) so a version scanner records an unpatched box. The
	// service never becomes actually exploitable. CVE exploit-attempt
	// detection runs regardless of this flag.
	VulnEmulation bool
	// Script is the path to a Lua dynamic-response script (handler "lua").
	Script string
	// Scripted is the declarative fake-protocol spec (handler "scripted").
	Scripted config.ScriptedProto
	// SessionRec records interactive shell sessions (telnet /
	// ssh_interactive) as asciinema casts. nil = recording disabled.
	SessionRec *sessionrec.Store
}

// HoneynetSnapshot is a flat read-only view of every honeynet host. The
// sensor populates it from internal/honeynet.Topology at New time. It's
// safe to share by value because the underlying slices are owned by the
// snapshot itself.
type HoneynetSnapshot struct {
	Hosts    []HoneynetHost
	Networks []HoneynetNetwork
}

// HoneynetNetwork carries the per-network metadata the DNS handler needs
// to answer coherently (domain for SRV/NS/SOA, the resolver/gateway IPs).
type HoneynetNetwork struct {
	ID      string
	CIDR    string
	Domain  string
	DNS     string
	Gateway string
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
	// CVEHits names CVE ids whose exploit signature appeared in the
	// attacker's request (from internal/cve.MatchPayload). The listener
	// turns each into a separate high-severity cve:<id> event. Detection
	// only — the handler never actually executes the exploit.
	CVEHits []string
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
	case "scripted":
		return compileScripted(deps.Scripted)
	case "lua":
		if deps.Script == "" {
			return nil, fmt.Errorf("lua handler requires a script: path")
		}
		src, err := os.ReadFile(deps.Script)
		if err != nil {
			return nil, fmt.Errorf("lua: read script %s: %w", deps.Script, err)
		}
		archName, archFamily := "", ""
		if deps.Archetype != nil {
			archName, archFamily = deps.Archetype.Name, deps.Archetype.Family
		}
		eng, err := luaengine.Compile(filepath.Base(deps.Script), src, deps.Identity, archName, archFamily)
		if err != nil {
			return nil, err
		}
		return &luaH{eng: eng, jit: deps.Jitter}, nil
	case "ssh":
		return &ssh{id: deps.Identity, jit: deps.Jitter, arch: deps.Archetype, vuln: deps.VulnEmulation}, nil
	case "ssh_interactive":
		return &sshInteractive{
			id:   deps.Identity,
			jit:  deps.Jitter,
			arch: deps.Archetype,
			dir:  filepath.Join(deps.DataDir, "tls"),
			rec:  deps.SessionRec,
		}, nil
	case "http":
		return &httpH{urlCanaries: deps.URLCanaries, id: deps.Identity, jit: deps.Jitter, arch: deps.Archetype, vuln: deps.VulnEmulation}, nil
	case "https":
		h, err := newHTTPS(deps.DataDir, deps.TLSRotate)
		if err != nil {
			return nil, err
		}
		h.urlCanaries = deps.URLCanaries
		h.id = deps.Identity
		h.jit = deps.Jitter
		h.arch = deps.Archetype
		h.vuln = deps.VulnEmulation
		return h, nil
	case "telnet":
		return &telnet{jit: deps.Jitter, arch: deps.Archetype, rec: deps.SessionRec}, nil
	case "ftp":
		return &ftp{jit: deps.Jitter, arch: deps.Archetype, id: deps.Identity}, nil
	case "ftp_files":
		return &ftpFiles{id: deps.Identity, arch: deps.Archetype, acceptCreds: deps.AcceptCreds}, nil
	case "modbus":
		return &modbus{}, nil
	case "s7":
		return &s7{}, nil
	case "s7comm_plus":
		return &s7commPlus{}, nil
	case "dnp3":
		return &dnp3{}, nil
	case "ge_srtp":
		return &geSRTP{}, nil
	case "codesys":
		return &codesys{}, nil
	case "iec104":
		return &iec104{}, nil
	case "atg":
		return &atg{id: deps.Identity}, nil
	case "fox":
		return &foxH{id: deps.Identity}, nil
	case "hartip":
		return &hartIP{}, nil
	case "pcworx":
		return &pcworx{}, nil
	case "mms":
		return &mms{}, nil
	case "pjl":
		return &pjl{arch: deps.Archetype}, nil
	case "lpd":
		return &lpd{}, nil
	case "ads":
		return &ads{}, nil
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
		return &smtpRecv{id: deps.Identity, jit: deps.Jitter, arch: deps.Archetype}, nil
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
		return &mysql{id: deps.Identity, arch: deps.Archetype}, nil
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
	case "xmpp":
		return &xmpp{}, nil
	case "amqp":
		return &amqp{}, nil
	case "ipp":
		return &ipp{arch: deps.Archetype}, nil
	case "mssql":
		return &mssql{id: deps.Identity}, nil
	case "oracle_tns":
		return &oracleTNS{}, nil
	case "teamviewer":
		return &teamviewer{}, nil
	case "anydesk":
		return &anydesk{}, nil
	case "openvpn":
		return &openvpn{}, nil
	case "citrix_ica":
		return &citrixICA{}, nil
	case "vmware_authd":
		return &vmwareAuthd{}, nil
	case "x11":
		return &x11{}, nil
	case "rlogin":
		return &rlogin{}, nil
	case "nx":
		return &nx{}, nil
	case "redfish":
		return &redfish{}, nil
	case "intel_amt", "ilo", "idrac", "esxi", "fortinet",
		"pulse", "citrix_gateway", "horizon", "moxa_mgmt":
		return &mgmtWeb{kind: name}, nil
	case "echo":
		return &echoTCP{}, nil
	case "discard":
		return &discardTCP{}, nil
	case "daytime":
		return &daytimeTCP{}, nil
	case "qotd":
		return &qotdTCP{}, nil
	case "chargen":
		return &chargenTCP{}, nil
	case "time":
		return &timeTCP{}, nil
	}
	return nil, fmt.Errorf("unknown handler %q", name)
}

// withTimeout sets the read+write deadline on conn for the duration d.
func withTimeout(conn net.Conn, d time.Duration) {
	deadline := time.Now().Add(d)
	_ = conn.SetReadDeadline(deadline)
	_ = conn.SetWriteDeadline(deadline)
}
