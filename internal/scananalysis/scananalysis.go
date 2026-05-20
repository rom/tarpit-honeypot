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
	case strings.HasPrefix(s, "GET / HTTP/1.1\r\nHost:") && strings.Contains(s, "Accept:"):
		// Real-ish; not a strong probe signal on its own.
	case s == "\r\n\r\n":
		v.NmapProbe = "NULL"
		v.VersionProbe = true
	case strings.HasPrefix(s, "HELP\r\n"), strings.HasPrefix(s, "Help\r\n"):
		v.NmapProbe = "Help"
		v.VersionProbe = true
	case strings.HasPrefix(s, "\x80") && len(s) >= 4:
		// nmap's RPCCheck / SSLSessionReq-style binary probes.
		v.NmapProbe = "BinaryProbe"
		v.VersionProbe = true
	case strings.HasPrefix(low, "stats\r\n") || strings.HasPrefix(low, "version\r\n"):
		v.NmapProbe = "GenericLines"
		v.VersionProbe = true
	}

	// NSE script signatures — the http-* scripts hit characteristic
	// paths; the discovery scripts send protocol-specific probes.
	switch {
	case strings.Contains(low, "/nmaplowercheck"):
		v.NSEScript = "http-nmap-probe"
	case strings.Contains(low, "/.git/") || strings.Contains(low, "/.svn/"):
		v.NSEScript = "http-vcs-discovery"
	case strings.Contains(low, "/robots.txt"):
		v.NSEScript = "http-robots"
	case strings.Contains(low, "user-agent:") && strings.Contains(low, "nmap"):
		v.NSEScript = "nse-generic"
	case handlerName == "smb" && strings.Contains(low, "smbghost"):
		v.NSEScript = "smb-vuln"
	}
	return v
}

// ---- stateful per-source tracking ----

// Tracker accumulates per-source observations to estimate scan timing,
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
	handlers     map[string]bool
	versionProbe bool
	osProbeHint  bool
	nseScripts   map[string]bool
	emitted      bool
}

// Observation is one connection's worth of signal.
type Observation struct {
	SourceIP string
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
		st = &srcState{first: now, ports: map[int]bool{}, handlers: map[string]bool{}, nseScripts: map[string]bool{}}
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
		st.ports[o.DestPort] = true
	}
	if o.Handler != "" {
		st.handlers[o.Handler] = true
	}
	if o.Verdict.VersionProbe {
		st.versionProbe = true
	}
	if o.Verdict.NSEScript != "" {
		st.nseScripts[o.Verdict.NSEScript] = true
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
		OSScan:        st.osProbeHint,
		DistinctPorts: len(st.ports),
		Conns:         st.conns,
	}
	for s := range st.nseScripts {
		r.NSEScripts = append(r.NSEScripts, s)
	}
	// -A (aggressive) ≈ version scan + NSE + OS probe + broad port set.
	if st.versionProbe && len(st.nseScripts) > 0 && len(st.ports) >= 4 {
		r.Aggressive = true
	}
	return r
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
