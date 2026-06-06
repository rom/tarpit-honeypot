// Package scananalysis classifies scanning behaviour from the signals a
// connection-level honeypot can actually observe. It has two halves:
//
//  1. Per-payload classification (stateless): does this banner-grab /
//     request look like an nmap service-version probe, an NSE script,
//     or a generic connect-scan? Handlers call ClassifyPayload.
//
//  2. Per-source sequencing (stateful): a Tracker accumulates each
//     source's connection cadence + port spread + probe variety and
//     estimates the nmap timing template (-T0..-T5), flags aggressive
//     scans (-A: version + OS + traceroute + NSE in one run), OS-probe
//     scans (-O), and scan-sequencing patterns. The sensor feeds every
//     event into the Tracker; it emits a scananalysis:* event when a
//     source crosses a confidence threshold.
//
// What we CANNOT see at the connection layer (and therefore defer to
// the AF_PACKET sniffer): half-open SYN scans, FIN/NULL/Xmas/ACK scans
// (they never complete the handshake), raw fragmentation, and IP-level
// decoy floods (-D). ClassifyPayload + Tracker mark those as
// "needs-packet-capture" where relevant rather than guessing.
package scananalysis

import (
	"sort"
	"strings"
	"time"
)

// PayloadVerdict is the stateless per-connection classification.
type PayloadVerdict struct {
	// NmapProbe names the nmap service-scan probe this payload matches
	// (e.g. "GetRequest", "NULL", "Help", "GenericLines"), or "".
	NmapProbe string
	// NSEScript names the NSE script the request looks like (e.g.
	// "http-vuln", "smb-os-discovery"), or "".
	NSEScript string
	// VersionProbe is true for any nmap -sV service/version probe.
	VersionProbe bool
	// ConnectScan is true when the connection completed the handshake
	// but sent no application data (a classic -sT connect scan).
	ConnectScan bool
	// Tool, when non-empty, names the scanning / exploitation tool the
	// payload fingerprints as — from a self-identifying User-Agent, a
	// characteristic request path, or a distinctive probe shape (e.g.
	// "masscan", "zgrab", "nuclei", "nikto", "sqlmap", "gobuster",
	// "wpscan", "nessus", "nmap-nse"). High-signal only.
	Tool string
	// VulnScan is true for a request that is unmistakably a vulnerability
	// scanner / content-discovery probe rather than a service-version
	// grab — a stronger "this source is actively hunting bugs" signal
	// than a bare banner grab.
	VulnScan bool
}

// ClassifyPayload inspects the bytes a client sent on a TCP connection
// (may be empty for a bare connect scan) plus the protocol the listener
// emulates. handlerName is the listener's handler (e.g. "http").
func ClassifyPayload(payload []byte, handlerName string) PayloadVerdict {
	v := PayloadVerdict{}
	if len(payload) == 0 {
		// Completed handshake, no data, then close = connect scan.
		v.ConnectScan = true
		return v
	}
	s := string(payload)
	low := strings.ToLower(s)

	// nmap service-scan probes (from nmap-service-probes). These exact
	// strings are what `nmap -sV` sends.
	switch {
	case strings.HasPrefix(s, "GET / HTTP/1.0\r\n\r\n"):
		v.NmapProbe = "GetRequest"
		v.VersionProbe = true
	case strings.HasPrefix(s, "OPTIONS / HTTP/1.0\r\n"):
		v.NmapProbe = "HTTPOptions"
		v.VersionProbe = true
	case strings.HasPrefix(s, "OPTIONS / RTSP/1.0\r\n"):
		v.NmapProbe = "RTSPRequest"
		v.VersionProbe = true
	case strings.HasPrefix(low, "options sip:") || strings.Contains(low, " sip/2.0\r\n"):
		v.NmapProbe = "SIPOptions"
		v.VersionProbe = true
	case strings.HasPrefix(s, "GET / HTTP/1.1\r\nHost:") && strings.Contains(s, "Accept:"):
		// Real-ish; not a strong probe signal on its own.
	case s == "\r\n\r\n":
		v.NmapProbe = "NULL"
		v.VersionProbe = true
	case strings.HasPrefix(s, "HELP\r\n"), strings.HasPrefix(s, "Help\r\n"):
		v.NmapProbe = "Help"
		v.VersionProbe = true
	case strings.HasPrefix(s, "\x16\x03") && len(s) >= 3:
		// TLS ClientHello — nmap's SSLSessionReq / a TLS version grab.
		v.NmapProbe = "SSLSessionReq"
		v.VersionProbe = true
	case strings.HasPrefix(s, "\x80") && len(s) >= 4:
		// nmap's RPCCheck / SSLv2-style binary probes.
		v.NmapProbe = "BinaryProbe"
		v.VersionProbe = true
	case strings.HasPrefix(low, "stats\r\n") || strings.HasPrefix(low, "version\r\n"):
		v.NmapProbe = "GenericLines"
		v.VersionProbe = true
	case strings.HasPrefix(s, "JRMI"):
		v.NmapProbe = "JavaRMI"
		v.VersionProbe = true
	}

	// NSE script signatures — the http-* scripts hit characteristic
	// paths; the discovery scripts send protocol-specific probes.
	switch {
	case strings.Contains(low, "/nmaplowercheck"):
		v.NSEScript = "http-nmap-probe"
		v.VersionProbe = true
	case strings.Contains(low, "/.git/") || strings.Contains(low, "/.svn/"):
		v.NSEScript = "http-vcs-discovery"
		v.VulnScan = true
	case strings.Contains(low, "/.env") || strings.Contains(low, "/.aws/"):
		v.NSEScript = "http-config-leak"
		v.VulnScan = true
	case strings.Contains(low, "/robots.txt"):
		v.NSEScript = "http-robots"
	case strings.Contains(low, "/hnap1"):
		v.NSEScript = "http-hnap"
		v.VulnScan = true
	case strings.Contains(low, "/manager/html") || strings.Contains(low, "/manager/text"):
		v.NSEScript = "http-tomcat-manager"
		v.VulnScan = true
	case strings.Contains(low, "/actuator/") || strings.Contains(low, "/actuator/env"):
		v.NSEScript = "http-spring-actuator"
		v.VulnScan = true
	case strings.Contains(low, "/server-status"):
		v.NSEScript = "http-apache-status"
	case strings.Contains(low, "/wp-login.php") || strings.Contains(low, "/xmlrpc.php"):
		v.NSEScript = "http-wordpress"
		v.VulnScan = true
	case strings.Contains(low, "user-agent:") && strings.Contains(low, "nmap"):
		v.NSEScript = "nse-generic"
		v.VersionProbe = true
	case handlerName == "smb" && strings.Contains(low, "smbghost"):
		v.NSEScript = "smb-vuln"
		v.VulnScan = true
	}

	// ICS / OT recon probes. The OT discovery tools (nmap's ICS NSE
	// scripts, Metasploit's scada modules, plcscan/s7scan, the ISF
	// framework) reach an ICS listener over the *binary* protocol, not
	// HTTP — so they never carry a User-Agent. We recognize them by the
	// documented probe bytes they send instead.
	if nse, tool, ver := classifyICSProbe(payload, handlerName); nse != "" {
		if v.NSEScript == "" {
			v.NSEScript = nse
		}
		if v.Tool == "" {
			v.Tool = tool
		}
		if ver {
			v.VersionProbe = true
		}
	}

	// Self-identifying scanner / exploitation tools. Most reveal
	// themselves in a User-Agent or a wholly distinctive request shape.
	if v.Tool == "" {
		v.Tool = fingerprintTool(low)
	}
	if v.Tool != "" {
		// A recognized vuln scanner / fuzzer is a bug-hunt, not a banner
		// grab. masscan/zgrab are mass *version* sweeps; the rest hunt.
		switch v.Tool {
		case "masscan", "zgrab":
			v.VersionProbe = true
		default:
			v.VulnScan = true
		}
	}
	return v
}

// toolSig pairs a substring with the tool it identifies. Ordered so the
// most specific / highest-signal markers win when several could match.
var toolSigs = []struct{ sub, tool string }{
	{"masscan", "masscan"},
	{"zgrab", "zgrab"},
	{"zmap", "zgrab"},
	{"nuclei", "nuclei"},
	{"nikto", "nikto"},
	{"sqlmap", "sqlmap"},
	{"gobuster", "gobuster"},
	{"dirbuster", "gobuster"},
	{"ffuf", "ffuf"},
	{"feroxbuster", "ffuf"},
	{"wpscan", "wpscan"},
	{"nessus", "nessus"},
	{"qualys", "qualys"},
	{"acunetix", "acunetix"},
	{"netsparker", "acunetix"},
	{"masscan/", "masscan"},
	{"nmap scripting engine", "nmap-nse"},
	{"(compatible; nmap", "nmap-nse"},
}

// fingerprintTool returns the scanning/exploitation tool a lowercased
// payload self-identifies as, or "". High-signal substrings only.
func fingerprintTool(low string) string {
	for _, ts := range toolSigs {
		if strings.Contains(low, ts.sub) {
			return ts.tool
		}
	}
	return ""
}

// classifyICSProbe recognizes the OT/ICS reconnaissance probes that asset
// scanners and exploitation frameworks send over a *binary* control-system
// protocol (so they never carry an HTTP User-Agent). It returns the NSE/
// recon-script name, a best-effort tool attribution (only when the probe
// shape is genuinely distinctive — otherwise ""), and whether it counts as
// a version/identity probe.
//
// These signatures are the documented, on-the-wire bytes of the public
// tools — nmap's *-info / *-discover NSE scripts, Metasploit's scada/ics
// auxiliary modules, and the s7scan / plcscan / ISF toolkits. Where several
// tools share an identical probe (e.g. every Modbus scanner sends the same
// Read-Device-Identification PDU) we name the script but leave the tool
// unattributed rather than guess a vendor.
func classifyICSProbe(payload []byte, handler string) (nse, tool string, version bool) {
	switch handler {
	case "modbus", "modbus_security":
		return classifyModbusProbe(payload)
	case "s7", "s7comm_plus":
		return classifyS7Probe(payload)
	case "bacnet":
		// BACnet ReadProperty for the Device object — nmap bacnet-info /
		// BACnet asset scanners. APDU confirmed-request (0x00) + ReadProperty
		// service (0x0c).
		if len(payload) >= 8 && payload[0] == 0x81 && bacnetAPDUService(payload) == 0x0c {
			return "bacnet-info", "", true
		}
	case "dnp3":
		// DNP3 link header 0x05 0x64 with a Read (function 0x01) request —
		// dnp3-info / DNP3 outstation enumeration.
		if len(payload) >= 4 && payload[0] == 0x05 && payload[1] == 0x64 {
			return "dnp3-enumerate", "", true
		}
	case "ethernetip":
		// ENIP ListIdentity (0x0063) — enip-info / EtherNet/IP discovery.
		if len(payload) >= 2 && payload[0] == 0x63 && payload[1] == 0x00 {
			return "enip-info", "", true
		}
	case "pcworx":
		// Phoenix Contact PCWorx identify request — nmap pcworx-info.
		if len(payload) >= 4 {
			return "pcworx-info", "", true
		}
	case "fox":
		// Niagara Fox opens with the ASCII "fox a 1 ..." hello — nmap
		// fox-info / Tridium asset discovery.
		if strings.HasPrefix(string(payload), "fox a ") {
			return "fox-info", "", true
		}
	}
	return "", "", false
}

// classifyModbusProbe inspects a Modbus/TCP ADU for the function codes the
// recon tools use to enumerate a device. A valid ADU carries the MBAP
// header (txn[2] proto[2]=0 len[2] unit[1]) followed by the function code.
func classifyModbusProbe(p []byte) (nse, tool string, version bool) {
	if len(p) < 8 || p[2] != 0x00 || p[3] != 0x00 {
		return "", "", false
	}
	fn := p[7]
	switch fn {
	case 0x2b:
		// Encapsulated Interface Transport. Sub-function 0x0e =
		// Read Device Identification (vendor/product/version strings) —
		// the canonical Modbus asset-discovery probe shared by nmap
		// modbus-discover, plcscan, and every OT asset scanner.
		if len(p) >= 9 && p[8] == 0x0e {
			return "modbus-device-id", "", true
		}
	case 0x11:
		// Report Server ID — nmap modbus-discover's other identity probe.
		return "modbus-discover", "", true
	case 0x07:
		// Read Exception Status — Metasploit's modbus_detect liveness probe.
		return "modbus-detect", "metasploit", true
	case 0x08:
		// Diagnostics — sub-function probing / loopback used by smod and
		// Metasploit modbusdetect.
		return "modbus-diagnostics", "", true
	}
	return "", "", false
}

// classifyS7Probe recognizes the S7comm / COTP probe an S7 scanner sends:
// a TPKT (0x03 0x00) framing a COTP Connection-Request (PDU type 0xE0).
// nmap s7-info, plcscan, s7scan, and Metasploit's s7 modules all open this
// way before reading the SZL module/component identification.
func classifyS7Probe(p []byte) (nse, tool string, version bool) {
	if len(p) < 6 || p[0] != 0x03 || p[1] != 0x00 {
		return "", "", false
	}
	// COTP header starts at byte 4 (after the 4-byte TPKT header):
	// byte 4 = COTP length, byte 5 = PDU type. Connection-Request = 0xE0.
	if len(p) >= 6 && p[5] == 0xe0 {
		return "s7-info", "", true
	}
	return "", "", false
}

// bacnetAPDUService extracts the BACnet APDU service choice from a BVLC/NPDU
// framed packet, or 0xff if it can't be located. BVLC header is 4 bytes;
// the NPDU + APDU follow. We look for the confirmed-request PDU type (0x00)
// and return the service choice byte.
func bacnetAPDUService(p []byte) byte {
	// Minimal walk: BVLC(4) + NPDU version(1) + control(1); if no dest/src
	// routing, the APDU starts at offset 6. APDU[0] PDU-type/flags, then
	// invoke-id + (for confirmed) max-segs/resp + service-choice.
	if len(p) < 10 {
		return 0xff
	}
	apdu := p[6:]
	if len(apdu) < 4 || apdu[0]&0xf0 != 0x00 {
		return 0xff
	}
	// confirmed-request: [pdu-type/flags][max-segs/max-resp][invoke-id][service]
	return apdu[3]
}

// ---- stateful per-source tracking ----

// Tracker accumulates per-source observations to estimate scan timing,
// Memory caps so a flood of distinct/spoofed source IPs (or a single source
// touching a /8 or forging tool/script names) can't exhaust memory: the source
// table and every per-source set is bounded.
const (
	maxScanSources        = 65536
	maxScanHostsPerSrc    = 256
	maxScanHandlersPerSrc = 32
	maxScanToolsPerSrc    = 16
	maxScanNSEPerSrc      = 64
	maxScanPortsPerSrc    = 2048
)

// scope, and aggressiveness. Safe for single-goroutine use behind the
// sensor's bus loop (which is serialized).
type Tracker struct {
	window time.Duration
	srcs   map[string]*srcState
	lastGC time.Time
}

type srcState struct {
	first        time.Time
	last         time.Time
	conns        int
	gaps         []time.Duration // inter-connection gaps
	ports        map[int]bool
	portSeq      []int // arrival order of distinct ports (bounded)
	hosts        map[string]bool
	handlers     map[string]bool
	tools        map[string]bool
	versionProbe bool
	vulnScan     bool
	osProbeHint  bool
	connectScans int
	nseScripts   map[string]bool
	emitted      bool
}

// Observation is one connection's worth of signal.
type Observation struct {
	SourceIP string
	DestIP   string // honeynet host the connection targeted (horizontal-spread input)
	DestPort int
	Handler  string
	Time     time.Time
	Verdict  PayloadVerdict
	// OSProbeHint is set by the caller when the event carries an
	// OS-fingerprint-probe signal (e.g. an ICMP timestamp + a TCP
	// connect to a closed-then-open pair — best-effort).
	OSProbeHint bool
}

// Result is what Observe returns when a source crosses the threshold.
type Result struct {
	SourceIP      string
	TimingProfile string // "-T0 paranoid" .. "-T5 insane"
	Aggressive    bool   // looks like -A
	VersionScan   bool   // -sV
	OSScan        bool   // -O
	NSEScripts    []string
	DistinctPorts int
	Conns         int
	// DistinctHosts is how many distinct honeynet hosts the source
	// touched — the breadth axis that distinguishes a horizontal sweep
	// from a single-host vertical scan.
	DistinctHosts int
	// ScanShape classifies the scan's geometry: "vertical" (one host,
	// many ports), "horizontal" (many hosts, few ports), or "block"
	// (many hosts AND many ports — a full subnet × port sweep).
	ScanShape string
	// PortOrder describes how the targeted ports were sequenced:
	// "sequential" (monotonic — a naive scripted scan / nmap -r) or
	// "random" (shuffled — masscan/zmap/nmap default), or "".
	PortOrder string
	// Tool is the best-guess scanning tool, fingerprinted from the
	// payloads seen across the source's connections (e.g. "masscan",
	// "nuclei", "nmap-nse"), or "".
	Tool string
	// Tools lists every distinct tool fingerprint seen (a source may
	// chain a mass sweep with a follow-up vuln scan).
	Tools []string
	// VulnScan is true when the source ran recognizable vulnerability /
	// content-discovery probes (not just version grabs).
	VulnScan bool
	// Stealthy is true for evasive cadence: -T0/-T1 timing, the slow
	// "stay under the IDS threshold" profile.
	Stealthy bool
	// Confidence is a 0..100 score combining cadence, scope, probe
	// variety, and tool fingerprints — how sure we are this source is
	// scanning rather than a handful of benign reconnects.
	Confidence int
}

// NewTracker builds a Tracker. window bounds how long a source's state
// lives without new activity.
func NewTracker(window time.Duration) *Tracker {
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &Tracker{window: window, srcs: map[string]*srcState{}}
}

// MinConnsForVerdict is how many connections a source must make before
// the timing/sequencing heuristic is confident enough to emit.
const MinConnsForVerdict = 6

// Observe records one connection and returns a non-nil Result the first
// time the source crosses the confidence threshold.
func (t *Tracker) Observe(o Observation) *Result {
	if o.SourceIP == "" {
		return nil
	}
	now := o.Time
	if now.IsZero() {
		now = time.Now()
	}
	// Evict idle sources (no activity within the window) so the map
	// doesn't grow unbounded under many distinct/spoofed source IPs.
	// Throttled to once per window to bound the sweep cost.
	if now.Sub(t.lastGC) > t.window {
		for ip, st := range t.srcs {
			if now.Sub(st.last) > t.window {
				delete(t.srcs, ip)
			}
		}
		t.lastGC = now
	}
	st, ok := t.srcs[o.SourceIP]
	if !ok || now.Sub(st.last) > t.window {
		// Hard cap the source table so a flood of distinct/spoofed source IPs
		// can't exhaust memory between the throttled GC sweeps. When full, do an
		// emergency idle sweep; if still full, stop tracking new sources.
		if !ok && len(t.srcs) >= maxScanSources {
			for ip, s := range t.srcs {
				if now.Sub(s.last) > t.window {
					delete(t.srcs, ip)
				}
			}
			if len(t.srcs) >= maxScanSources {
				return nil
			}
		}
		st = &srcState{first: now, ports: map[int]bool{}, hosts: map[string]bool{}, handlers: map[string]bool{}, tools: map[string]bool{}, nseScripts: map[string]bool{}}
		t.srcs[o.SourceIP] = st
	}
	if st.conns > 0 {
		st.gaps = append(st.gaps, now.Sub(st.last))
		if len(st.gaps) > 256 {
			st.gaps = st.gaps[len(st.gaps)-256:]
		}
	}
	st.last = now
	st.conns++
	if o.DestPort > 0 {
		if !st.ports[o.DestPort] && len(st.portSeq) < 512 {
			st.portSeq = append(st.portSeq, o.DestPort)
		}
		if len(st.ports) < maxScanPortsPerSrc {
			st.ports[o.DestPort] = true
		}
	}
	if o.DestIP != "" && len(st.hosts) < maxScanHostsPerSrc {
		st.hosts[o.DestIP] = true
	}
	if o.Handler != "" && len(st.handlers) < maxScanHandlersPerSrc {
		st.handlers[o.Handler] = true
	}
	if o.Verdict.VersionProbe {
		st.versionProbe = true
	}
	if o.Verdict.VulnScan {
		st.vulnScan = true
	}
	if o.Verdict.ConnectScan {
		st.connectScans++
	}
	if o.Verdict.NSEScript != "" && len(st.nseScripts) < maxScanNSEPerSrc {
		st.nseScripts[o.Verdict.NSEScript] = true
	}
	if o.Verdict.Tool != "" && len(st.tools) < maxScanToolsPerSrc {
		st.tools[o.Verdict.Tool] = true
	}
	if o.OSProbeHint {
		st.osProbeHint = true
	}

	if st.emitted || st.conns < MinConnsForVerdict {
		return nil
	}
	st.emitted = true
	return t.verdict(o.SourceIP, st)
}

func (t *Tracker) verdict(ip string, st *srcState) *Result {
	r := &Result{
		SourceIP:      ip,
		TimingProfile: estimateTiming(st.gaps),
		VersionScan:   st.versionProbe,
		VulnScan:      st.vulnScan,
		OSScan:        st.osProbeHint,
		DistinctPorts: len(st.ports),
		DistinctHosts: len(st.hosts),
		Conns:         st.conns,
		ScanShape:     scanShape(len(st.hosts), len(st.ports)),
		PortOrder:     classifyPortOrder(st.portSeq),
	}
	for s := range st.nseScripts {
		r.NSEScripts = append(r.NSEScripts, s)
	}
	sort.Strings(r.NSEScripts)
	for tl := range st.tools {
		r.Tools = append(r.Tools, tl)
	}
	sort.Strings(r.Tools)
	r.Tool = primaryTool(st.tools)
	// -A (aggressive) ≈ version scan + NSE + OS probe + broad port set.
	if st.versionProbe && len(st.nseScripts) > 0 && len(st.ports) >= 4 {
		r.Aggressive = true
	}
	r.Stealthy = strings.HasPrefix(r.TimingProfile, "-T0") || strings.HasPrefix(r.TimingProfile, "-T1")
	r.Confidence = scanConfidence(st)
	return r
}

// scanShape classifies the scan geometry from the breadth on each axis:
// hosts touched vs ports touched. The thresholds are deliberately low —
// by the time a source crosses MinConnsForVerdict, even a few of each is
// a deliberate sweep on that axis.
func scanShape(hosts, ports int) string {
	wideHosts := hosts >= 3
	widePorts := ports >= 4
	switch {
	case wideHosts && widePorts:
		return "block"
	case wideHosts:
		return "horizontal"
	case widePorts:
		return "vertical"
	default:
		return ""
	}
}

// classifyPortOrder reports whether the targeted ports arrived in a
// monotonic ("sequential") order — the hallmark of a naive scripted scan
// or `nmap -r` — versus a shuffled ("random") order, which the default
// nmap / masscan / zmap port randomization produces. Needs >=4 ports.
func classifyPortOrder(seq []int) string {
	if len(seq) < 4 {
		return ""
	}
	steps := len(seq) - 1
	asc, desc := 0, 0
	for i := 1; i < len(seq); i++ {
		switch {
		case seq[i] > seq[i-1]:
			asc++
		case seq[i] < seq[i-1]:
			desc++
		}
	}
	// Near-monotonic in either direction = sequential.
	if asc*10 >= steps*9 || desc*10 >= steps*9 {
		return "sequential"
	}
	return "random"
}

// primaryTool picks the highest-signal tool fingerprint from the set a
// source produced. A vuln scanner / fuzzer outranks a mass version
// sweeper, which outranks a generic nmap-nse marker, so a source that
// chained masscan -> nuclei is reported as "nuclei".
func primaryTool(tools map[string]bool) string {
	if len(tools) == 0 {
		return ""
	}
	rank := func(t string) int {
		switch t {
		case "masscan", "zgrab", "nmap-nse":
			return 1
		default:
			return 2 // active vuln scanners / fuzzers
		}
	}
	best, bestRank := "", -1
	for t := range tools {
		if r := rank(t); r > bestRank || (r == bestRank && t < best) {
			best, bestRank = t, r
		}
	}
	return best
}

// scanConfidence scores 0..100 how confident we are the source is
// scanning rather than making a handful of benign reconnections. It
// combines connection volume, port/host breadth, probe variety, evasive
// cadence, and self-identifying tool fingerprints.
func scanConfidence(st *srcState) int {
	score := 0
	score += min(st.conns*4, 30)      // sustained volume
	score += min(len(st.ports)*3, 24) // vertical breadth
	score += min(len(st.hosts)*4, 20) // horizontal breadth
	score += len(st.nseScripts) * 6   // NSE variety
	if st.versionProbe {
		score += 8
	}
	if st.vulnScan {
		score += 12
	}
	if len(st.tools) > 0 {
		score += 16 // a self-identified scanner is near-certain
	}
	if st.osProbeHint {
		score += 6
	}
	if score > 100 {
		score = 100
	}
	return score
}

// estimateTiming maps the median inter-connection gap to the nmap
// timing-template label. nmap's templates have characteristic
// scan_delay / max_rtt_timeout cadences: -T0 ~5min between probes,
// -T1 ~15s, -T2 ~0.4s, -T3 (default) sub-100ms parallel, -T4/-T5
// near-instant. We bucket the median gap accordingly.
func estimateTiming(gaps []time.Duration) string {
	if len(gaps) == 0 {
		return "unknown"
	}
	med := medianGap(gaps)
	switch {
	case med >= 4*time.Minute:
		return "-T0 paranoid"
	case med >= 10*time.Second:
		return "-T1 sneaky"
	case med >= 300*time.Millisecond:
		return "-T2 polite"
	case med >= 30*time.Millisecond:
		return "-T3 normal"
	case med >= 5*time.Millisecond:
		return "-T4 aggressive"
	default:
		return "-T5 insane"
	}
}

func medianGap(gaps []time.Duration) time.Duration {
	cp := append([]time.Duration(nil), gaps...)
	// insertion sort (small N).
	for i := 1; i < len(cp); i++ {
		for j := i; j > 0 && cp[j-1] > cp[j]; j-- {
			cp[j], cp[j-1] = cp[j-1], cp[j]
		}
	}
	return cp[len(cp)/2]
}
