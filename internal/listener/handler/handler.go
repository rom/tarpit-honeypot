// Package handler holds the built-in TCP application-layer handlers used by
// the "banner" listener mode. They send a small, plausible response and read
// a bounded amount of client data so the listener can record what the
// attacker sent.
//
// Handlers are intentionally minimal: enough to fool a banner-grab tool,
// not enough to support a real protocol session.
package handler

import (
	"bufio"
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
	Identity *identity.Identity
	Jitter   *jitter.Jitterer
	// Hostname, when set (honeynet per-host services), is the virtual host's
	// short name — used by identity-bearing handlers (e.g. the LDAP rootDSE) so
	// each virtual DC presents its own serverName/dnsHostName instead of a shared
	// default. Empty = handler default.
	Hostname string
	DataDir  string
	// MaxUploadBytes caps how much of an uploaded file (FTP STOR / web upload)
	// a handler captures for retention + classification (0 = handler default).
	MaxUploadBytes int
	URLCanaries    []config.URLCanary
	TLSRotate      int // days; 0 = never rotate
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
	// TLSIntercept is the per-listener config for the tls_intercept handler.
	TLSIntercept config.TLSIntercept
	// SessionRec records interactive shell sessions (telnet /
	// ssh_interactive) as asciinema casts. nil = recording disabled.
	SessionRec *sessionrec.Store
	// SSHKexExtended unlocks best-effort capture beyond the client KEXINIT
	// (HASSH): the negotiated KEX, the full algorithm breakdown including
	// the server-host-key list, and the client's first KEX message (the
	// ephemeral public value from KEXDH/ECDH_INIT, or a GEX group request).
	// Gated behind interaction.ssh_kex_depth: extended_experimental.
	SSHKexExtended bool
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
	case "auto":
		return &auto{}, nil
	case "scripted":
		return compileScripted(deps.Scripted)
	case "tls_intercept":
		return newTLSIntercept(deps, deps.TLSIntercept)
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
		return &ssh{id: deps.Identity, jit: deps.Jitter, arch: deps.Archetype, vuln: deps.VulnEmulation, kexExt: deps.SSHKexExtended}, nil
	case "ssh_interactive":
		return &sshInteractive{
			id:      deps.Identity,
			jit:     deps.Jitter,
			arch:    deps.Archetype,
			dir:     filepath.Join(deps.DataDir, "tls"),
			dataDir: deps.DataDir,
			rec:     deps.SessionRec,
			vuln:    deps.VulnEmulation,
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
		return &telnet{jit: deps.Jitter, arch: deps.Archetype, id: deps.Identity, rec: deps.SessionRec, dataDir: deps.DataDir}, nil
	case "ftp":
		return &ftp{jit: deps.Jitter, arch: deps.Archetype, id: deps.Identity, tlsMgr: maybeCertMgr(deps), maxUpload: deps.MaxUploadBytes}, nil
	case "ftp_files":
		return &ftpFiles{id: deps.Identity, arch: deps.Archetype, acceptCreds: deps.AcceptCreds, tlsMgr: maybeCertMgr(deps), maxUpload: deps.MaxUploadBytes}, nil
	case "modbus":
		return &modbus{}, nil
	case "modbus_security", "modbuss":
		return newModbusSecurity(deps)
	case "neo4j":
		return &neo4j{}, nil
	case "rethinkdb":
		return &rethinkdb{}, nil
	case "kubelet":
		return &kubelet{}, nil
	case "kubelets":
		return newTLSWrap("kubelet", "kubelets", deps)
	case "couchdb":
		return &couchdb{}, nil
	case "influxdb":
		return &influxdb{}, nil
	case "docker_registry":
		return &dockerRegistry{}, nil
	case "s7":
		return &s7{}, nil
	case "s7comm_plus":
		return &s7commPlus{}, nil
	case "dnp3":
		return &dnp3{}, nil
	case "ge_srtp":
		return &geSRTP{}, nil
	case "c37118":
		return &c37118{}, nil
	case "osdp":
		return &osdp{}, nil
	case "focas":
		return &focas{}, nil
	case "proconos":
		return &proconos{}, nil
	case "osisoft_pi":
		return &osisoftPI{id: deps.Identity}, nil
	case "proficy_historian":
		return &historian{
			proto: "proficy_historian", label: "GE Proficy Historian Data Archiver",
			version: "Historian 2023 (10.5)", marker: []byte{'G', 'E', 'H', 'I'}, id: deps.Identity,
		}, nil
	case "canary_historian":
		return &historian{
			proto: "canary_historian", label: "Canary Labs Historian (Sender)",
			version: "Canary 23.3", marker: []byte{'C', 'N', 'R', 'Y'}, id: deps.Identity,
		}, nil
	case "aspen_ip21":
		return &historian{
			proto: "aspen_ip21", label: "AspenTech InfoPlus.21",
			version: "aspenONE V14 (IP.21)", marker: []byte{'I', 'P', '2', '1'}, id: deps.Identity,
		}, nil
	case "nts":
		return &nts{mgr: maybeCertMgr(deps), arch: deps.Archetype}, nil
	case "codesys":
		return &codesys{}, nil
	case "rsync":
		return rsyncH{}, nil
	case "gopher":
		return gopherH{}, nil
	case "socks":
		return socksH{}, nil
	case "bgp":
		return bgpH{id: deps.Identity}, nil
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
	case "iccp_secure":
		// Secure ICCP / TASE.2 (IEC 62351) — MMS-over-TLS, typically TCP 3782.
		return newTLSWrap("mms", "iccp_secure", deps)
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
		return &vnc{id: deps.Identity, acceptCreds: deps.AcceptCreds}, nil
	case "smtp_recv":
		return newSMTPRecv(deps), nil
	case "rdp":
		return newRDP(deps), nil
	case "winrm":
		return &winrm{}, nil
	case "dcerpc":
		d := &dcerpc{}
		if deps.Archetype != nil {
			d.opcVendor = deps.Archetype.OPCVendor()
		}
		return d, nil
	case "ldap":
		return &ldap{arch: deps.Archetype, hostname: deps.Hostname}, nil
	case "kerberos":
		return &kerberos{}, nil
	case "postgres":
		return newPostgres(deps), nil
	case "smtps":
		return newTLSWrap("smtp_recv", "smtps", deps)
	case "imaps":
		return newTLSWrap("imap", "imaps", deps)
	case "pop3s":
		return newTLSWrap("pop3", "pop3s", deps)
	case "ldaps":
		return newTLSWrap("ldap", "ldaps", deps)
	case "mqtts":
		return newTLSWrap("mqtt", "mqtts", deps)
	case "bacnet_sc":
		return &bacnetSC{}, nil
	case "bacnet_scs":
		return newTLSWrap("bacnet_sc", "bacnet_scs", deps)
	case "c2_emulator":
		return &c2Emulator{}, nil
	case "agent":
		return &agentH{}, nil
	case "irc":
		return &ircH{}, nil
	case "finger":
		return &fingerH{}, nil
	case "stomp":
		return &stompH{}, nil
	case "mbus":
		return &mbusH{}, nil
	case "nntp":
		return &nntpH{}, nil
	case "ident":
		return &identH{}, nil
	case "dlms":
		return &dlmsH{}, nil
	case "afp":
		return &afpH{}, nil
	case "beanstalkd":
		return &beanstalkdH{}, nil
	case "ftps":
		return newTLSWrap("ftp", "ftps", deps)
	case "mysql":
		return &mysql{id: deps.Identity, arch: deps.Archetype}, nil
	case "redis":
		return &redis{id: deps.Identity}, nil
	case "memcached":
		return &memcached{id: deps.Identity}, nil
	case "pop3":
		return newPOP3(deps), nil
	case "imap":
		return newIMAP(deps), nil
	case "dns":
		// DNS over TCP (zone transfers, truncation fallback, tunneling). The
		// UDP resolver lives in GetUDP; this is the stream-framed variant.
		return newDNSTCP(deps), nil
	case "mongodb":
		return &mongodb{id: deps.Identity}, nil
	case "elasticsearch":
		return &elasticsearch{id: deps.Identity}, nil
	case "syslog_tcp":
		return &syslogTCP{}, nil
	case "rtsp":
		return &rtsp{}, nil
	case "dockerapi":
		return &dockerapi{}, nil
	case "cloud_metadata":
		return newCloudMeta(deps.Identity), nil
	case "etcd":
		return newEtcd(deps.Identity), nil
	case "websocket":
		return &websocketH{}, nil
	case "grpc":
		return &grpcH{}, nil
	case "ssrf_canary":
		return &ssrfCanary{}, nil
	case "kubernetes_api":
		return newK8sAPI(deps.Identity), nil
	case "vault":
		return newVault(deps.Identity), nil
	case "melsec":
		return &melsec{}, nil
	case "jdwp":
		return &jdwp{}, nil
	case "rmi":
		return &rmiRegistry{}, nil
	case "git":
		return &gitDaemon{}, nil
	case "svn":
		return &svn{}, nil
	case "nbd":
		return &nbd{}, nil
	case "roc_plus":
		return &rocPlus{}, nil
	case "crimson":
		return &crimson{}, nil
	case "zookeeper":
		return &zookeeper{}, nil
	case "kafka":
		return &kafkaBroker{}, nil
	case "cassandra":
		return &cassandra{}, nil
	case "nats":
		return &natsBroker{}, nil
	case "rpcbind":
		return &rpcbind{}, nil
	case "nfs":
		return &nfs{}, nil
	case "pptp":
		return &pptp{}, nil
	case "adb":
		return &adb{}, nil
	case "ajp13":
		return &ajp13{}, nil
	case "epmd":
		return &epmd{}, nil
	case "tacacs":
		return &tacacs{}, nil
	case "fins_tcp":
		return &finsTCP{}, nil
	case "secs_gem":
		return &secsGEM{}, nil
	case "pcom":
		return &pcom{}, nil
	case "rexec":
		return &rexec{}, nil
	case "rsh":
		return &rsh{}, nil
	case "pcanywhere":
		return &pcanywhere{}, nil
	case "radmin":
		return &radmin{}, nil
	case "dameware":
		return &dameware{}, nil
	case "pcoip":
		return &pcoip{}, nil
	case "spice":
		return &spice{}, nil
	case "lantronix":
		return &lantronix{}, nil
	case "tn3270":
		return &tn3270{}, nil
	case "ard":
		return &ard{}, nil
	case "sip_tcp":
		return &sipTCP{}, nil
	case "sccp":
		return &sccp{}, nil
	case "h323":
		return &h323{}, nil
	case "asterisk_ami":
		return &asteriskAMI{}, nil
	case "xmpp":
		return &xmpp{id: deps.Identity}, nil
	case "amqp":
		return &amqp{}, nil
	case "ibmmq", "mq", "websphere_mq":
		return &ibmmq{}, nil
	case "ipp":
		return &ipp{arch: deps.Archetype}, nil
	case "mssql":
		return &mssql{id: deps.Identity}, nil
	case "oracle_tns":
		return &oracleTNS{id: deps.Identity}, nil
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
	case "tr069":
		return &tr069{id: deps.Identity}, nil
	case "upnp":
		return &upnp{id: deps.Identity}, nil
	case "tr369":
		return &tr369{}, nil
	case "intel_amt", "ilo", "idrac", "esxi", "fortinet",
		"pulse", "citrix_gateway", "horizon", "moxa_mgmt":
		return &mgmtWeb{kind: name}, nil
	case "danfoss_aksm":
		return &danfoss{id: deps.Identity, vuln: deps.VulnEmulation}, nil
	case "danfoss_aksms":
		return newTLSWrap("danfoss_aksm", "danfoss_aksms", deps)
	case "ollama":
		return &llmAPI{kind: "ollama"}, nil
	case "llm_openai":
		return &llmAPI{kind: "llm_openai"}, nil
	case "mcp":
		return &mcp{}, nil
	case "jupyter", "selenium", "consul", "nomad", "minio", "clickhouse":
		return &cloudsvc{kind: name}, nil
	case "dixell", "carel", "trane", "resideo":
		return &bmsWeb{kind: name}, nil
	case "ocpp":
		return &ocppH{}, nil
	case "hl7":
		return &hl7{id: deps.Identity}, nil
	case "dicom":
		return &dicom{}, nil
	case "hl7s":
		// HL7 over TLS (some interface engines wrap MLLP in TLS).
		return newTLSWrap("hl7", "hl7s", deps)
	case "dicoms":
		// DICOM-TLS (secure DICOM Upper Layer, typically TCP 2762).
		return newTLSWrap("dicom", "dicoms", deps)
	case "astm":
		return &astm{}, nil
	case "poct1":
		return &poct1{}, nil
	case "fhir":
		return &fhir{}, nil
	case "fhirs":
		// FHIR over TLS (production FHIR servers mandate HTTPS).
		return newTLSWrap("fhir", "fhirs", deps)
	// Building-automation / BMS protocols (bas.go).
	case "niagara_platform":
		return &niagaraPlatform{}, nil
	case "obix":
		return &obix{}, nil
	case "enocean":
		return &enocean{}, nil
	// TLS-fronted variants of the new HTTP-ish handlers (decrypt → inner).
	case "ollamas":
		return newTLSWrap("ollama", "ollamas", deps)
	case "llm_openais":
		return newTLSWrap("llm_openai", "llm_openais", deps)
	case "mcps":
		return newTLSWrap("mcp", "mcps", deps)
	case "jupyters":
		return newTLSWrap("jupyter", "jupyters", deps)
	case "minios":
		return newTLSWrap("minio", "minios", deps)
	case "clickhouses":
		return newTLSWrap("clickhouse", "clickhouses", deps)
	case "consuls":
		return newTLSWrap("consul", "consuls", deps)
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

// localIPOf returns the bare IP string of a local net.Addr, correctly handling
// both IPv4 (`1.2.3.4:port`) and IPv6 (`[::1]:port`) forms — the LastIndex(":")
// trick mangles v6, so use the typed address when available and fall back to
// SplitHostPort. Returns "" when no IP can be recovered.
func localIPOf(a net.Addr) string {
	switch v := a.(type) {
	case *net.UDPAddr:
		if v != nil && v.IP != nil {
			return v.IP.String()
		}
	case *net.TCPAddr:
		if v != nil && v.IP != nil {
			return v.IP.String()
		}
	}
	if a == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(a.String()); err == nil {
		return host
	}
	return a.String()
}

// maxLineBytes caps a single text-protocol line read. The read deadline bounds
// how long a client can take, but not how much memory an unterminated flood can
// accumulate before it fires; this bounds the allocation. 8 KiB is generous for
// any command / header line we model.
const maxLineBytes = 8192

// readLineCapped reads through the next '\n' but never more than max bytes,
// returning what it read (including the '\n' when present), plus any read
// error. A line that reaches the cap is returned as-is with a nil error — it is
// treated as a (truncated) line rather than allowed to grow without bound. This
// mirrors bufio.Reader.ReadString('\n') for the callers' purposes while making
// a newline-less flood safe.
func readLineCapped(br *bufio.Reader, max int) (string, error) {
	buf := make([]byte, 0, 128)
	for len(buf) < max {
		c, err := br.ReadByte()
		if err != nil {
			return string(buf), err
		}
		buf = append(buf, c)
		if c == '\n' {
			break
		}
	}
	return string(buf), nil
}

// readDelimCapped is the bounded analogue of bufio.Reader.ReadBytes(delim): it
// reads up to max bytes or until delim (inclusive), whichever comes first, so an
// unterminated stream can't grow an unbounded buffer before the read deadline
// fires. When the cap is hit the returned slice does NOT end in delim, so
// callers that strip a trailing delimiter must check for it first.
func readDelimCapped(br *bufio.Reader, delim byte, max int) ([]byte, error) {
	buf := make([]byte, 0, 128)
	for len(buf) < max {
		c, err := br.ReadByte()
		if err != nil {
			return buf, err
		}
		buf = append(buf, c)
		if c == delim {
			break
		}
	}
	return buf, nil
}
