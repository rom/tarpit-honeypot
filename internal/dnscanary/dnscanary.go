// Package dnscanary serves a tiny authoritative DNS-like listener used to
// trip-wire canary names. The operator registers an unguessable name like
// "abc123.canary.example.com" — any A/AAAA/TXT/whatever query for that name
// or a subdomain of it fires a critical event with the source IP attached.
//
// We do NOT try to be a real DNS server. We parse just enough of the wire
// format to recover the query name and respond with NXDOMAIN (the safest
// default — attackers don't get a positive resolution back).
package dnscanary

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// Resolver lets the dnscanary forward-resolve honeynet hostnames without
// importing the honeynet package directly (which would create a cycle).
// The sensor passes a closure that wraps Topology.HostByName.
type Resolver func(qname string) (ip string, hostname string, ok bool)

type Server struct {
	bind       string
	sensorName string
	canaries   []entry
	amp        ampConfig
	ampState   *ampState
	resolve    Resolver
	sem        chan struct{} // bounds concurrent in-flight handlers
}

// dnsMaxConcurrent caps in-flight handler goroutines. UDP/53 is
// connectionless and spoofable, so an unbounded `go s.handle(...)` per
// datagram lets a flood spawn goroutines faster than the event bus drains
// — exhausting memory. Excess datagrams are dropped (UDP is lossy anyway).
const dnsMaxConcurrent = 256

type ampConfig struct {
	enabled   bool
	window    time.Duration
	threshold int
	sev       event.Severity
}

type ampState struct {
	mu      sync.Mutex
	sources map[string]*ampSrc
}

// ampMaxSources hard-caps the amplifier per-source table against a
// spoofed-source flood.
const ampMaxSources = 16384

type ampSrc struct {
	since     time.Time
	count     int
	anyCount  int // qtype=ANY (255) — classic amplifier probe
	lastFired time.Time
}

type entry struct {
	id  string
	sev event.Severity
	// suffix match: a canary at "foo.bar.example.com" matches that name and
	// any subdomain (e.g. "x.foo.bar.example.com"). All canary names are
	// lowercased + trailing-dot stripped at load time.
	name string
}

// SetResolver wires up the honeynet hostname resolver. nil disables
// forward-resolution; queries return NXDOMAIN as before.
func (s *Server) SetResolver(r Resolver) {
	s.resolve = r
}

func New(bind string, sensorName string, canaries []config.DNSCanary, amp config.DNSAmplifier) (*Server, error) {
	if bind == "" {
		return nil, fmt.Errorf("dnscanary: bind required")
	}
	s := &Server{bind: bind, sensorName: sensorName, sem: make(chan struct{}, dnsMaxConcurrent)}
	for _, c := range canaries {
		sev, err := event.ParseSeverity(c.Severity)
		if err != nil {
			return nil, fmt.Errorf("dnscanary %s: %w", c.ID, err)
		}
		s.canaries = append(s.canaries, entry{id: c.ID, sev: sev, name: c.Name})
	}
	if amp.Enabled {
		// Defensive default: config defaults should have filled this, but
		// never fail startup on an empty severity.
		sev, err := event.ParseSeverity(amp.Severity)
		if err != nil {
			sev = event.SeverityHigh
		}
		window := amp.Window
		if window <= 0 {
			window = 10 * time.Second
		}
		threshold := amp.Queries
		if threshold <= 0 {
			threshold = 50
		}
		s.amp = ampConfig{enabled: true, window: window, threshold: threshold, sev: sev}
		s.ampState = &ampState{sources: map[string]*ampSrc{}}
	}
	return s, nil
}

func (s *Server) Run(ctx context.Context, bus chan<- *event.Event) error {
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp", s.bind)
	if err != nil {
		return fmt.Errorf("dnscanary: listen %s: %w", s.bind, err)
	}
	slog.Info("dnscanary up", "bind", s.bind, "canaries", len(s.canaries))
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	buf := make([]byte, 1500)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			slog.Warn("dnscanary read", "err", err)
			continue
		}
		msg := append([]byte(nil), buf[:n]...)
		select {
		case s.sem <- struct{}{}:
			go func() {
				defer func() { <-s.sem }()
				s.handle(ctx, pc, raddr, msg, bus)
			}()
		default:
			// Too many handlers in flight (flood) — drop this datagram.
		}
	}
}

func (s *Server) handle(ctx context.Context, pc net.PacketConn, raddr net.Addr, msg []byte, bus chan<- *event.Event) {
	name, qtype, ok := parseQuery(msg)
	if !ok {
		return
	}
	src := hostPortFromAddr(raddr)

	// Abnormal-payload detection: DNS tunneling / exfil shows up as
	// over-long qnames, very long high-entropy single labels (base32/
	// hex-encoded data), or tunneling-favored qtypes (NULL/TXT). Flag
	// them so the operator sees a covert-channel attempt distinctly
	// from a normal lookup.
	anomalies := dnsAnomalies(name, qtype, len(msg))

	// Always emit a low-severity "query received" event so the operator sees
	// the noise floor even when no canary fired.
	sev := event.SeverityLow
	if len(anomalies) > 0 {
		sev = event.SeverityHigh
	}
	baseMeta := map[string]any{
		"qname": name,
		"qtype": qtype,
	}
	if len(anomalies) > 0 {
		baseMeta["anomalies"] = anomalies
	}
	// Resolve honeynet A records up front so the event meta is COMPLETE
	// before dispatch. Events travel by pointer to asynchronous sink
	// workers that JSON-encode (iterate) Meta; mutating Meta after send
	// races that read and can crash the process ("fatal error: concurrent
	// map read and map write").
	var reply []byte
	if qtype == 1 && s.resolve != nil {
		if ip, hostname, ok := s.resolve(name); ok {
			reply = buildA(msg, ip)
			baseMeta["honeynet_resolved"] = hostname
			baseMeta["honeynet_ip"] = ip
		}
	}
	baseEv := &event.Event{
		ID:       event.NewID(),
		Time:     time.Now().UTC(),
		Sensor:   s.sensorName,
		RuleID:   "dnscanary:query",
		Severity: sev,
		Source:   src,
		Proto:    "udp",
		Meta:     baseMeta,
	}
	if len(anomalies) > 0 {
		baseEv.Anomalies = append(baseEv.Anomalies, anomalies...)
	}
	send(ctx, bus, baseEv)

	for _, c := range s.canaries {
		if isSubdomain(name, c.name) {
			ce := &event.Event{
				ID:       event.NewID(),
				Time:     time.Now().UTC(),
				Sensor:   s.sensorName,
				RuleID:   "canary:dns:" + c.id,
				Severity: c.sev,
				Source:   src,
				Proto:    "udp",
				Meta: map[string]any{
					"qname":            name,
					"qtype":            qtype,
					"matched_canary":   c.name,
					"trigger_event_id": baseEv.ID,
				},
			}
			send(ctx, bus, ce)
		}
	}

	if s.amp.enabled {
		if ev := s.checkAmplifier(src.IP, qtype); ev != nil {
			ev.Sensor = s.sensorName
			send(ctx, bus, ev)
		}
	}

	// reply was resolved before dispatch (see above); NXDOMAIN otherwise.
	if reply == nil {
		reply = buildNXDOMAIN(msg)
	}
	if reply != nil {
		_ = pc.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = pc.WriteTo(reply, raddr)
	}
}

// dnsAnomalies inspects a parsed query for DNS-tunneling / exfil /
// abnormal-payload markers. Returns the marker list (empty = normal).
//
//	dns-qname-overlong        total qname > 200 chars (tunnels pack data into the name)
//	dns-label-overlong        a single label >= 50 chars (encoded chunk)
//	dns-high-entropy-label    a label that looks base32/hex-encoded (covert channel)
//	dns-tunneling-qtype       NULL(10)/TXT(16) — the qtypes tunnels prefer for capacity
//	dns-oversize-query        the request message itself is unusually large
func dnsAnomalies(name string, qtype uint16, msgLen int) []string {
	var out []string
	if len(name) > 200 {
		out = append(out, "dns-qname-overlong")
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if len(l) >= 50 {
			out = append(out, "dns-label-overlong")
		}
		if len(l) >= 20 && looksEncodedLabel(l) {
			out = append(out, "dns-high-entropy-label")
			break
		}
	}
	if qtype == 10 || qtype == 16 { // NULL, TXT
		out = append(out, "dns-tunneling-qtype")
	}
	// DNSCrypt clients fetch the resolver certificate via a TXT query for
	// "<version>.dnscrypt-cert.<provider>" before tunnelling DNS over an
	// encrypted channel — a reliable tell that DNSCrypt is in use.
	if strings.Contains(name, "dnscrypt-cert.") {
		out = append(out, "dnscrypt-probe")
	}
	if msgLen > 512 {
		out = append(out, "dns-oversize-query")
	}
	return dedupStrings(out)
}

// looksEncodedLabel heuristically detects a base32/hex-encoded DNS
// label: mostly alphanumeric with a high distinct-character ratio and
// no dictionary-word vowel pattern. Cheap approximation of entropy.
func looksEncodedLabel(l string) bool {
	digits, alnum := 0, 0
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
			alnum++
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			alnum++
		}
	}
	if alnum < len(l) {
		return false // contains separators -> probably not a single encoded chunk
	}
	// Encoded data has a substantial digit fraction; English labels
	// rarely do. >= 20% digits in a 20+ char all-alnum label is a
	// strong tunneling tell.
	return digits*5 >= len(l)
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// parseQuery returns (lowercased name without trailing dot, qtype, ok).
func parseQuery(msg []byte) (string, uint16, bool) {
	if len(msg) < 12 {
		return "", 0, false
	}
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	if qdcount < 1 {
		return "", 0, false
	}
	pos := 12
	var name strings.Builder
	for {
		if pos >= len(msg) {
			return "", 0, false
		}
		l := int(msg[pos])
		pos++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 {
			// pointer — we don't follow them for canary lookups, but the
			// outer name is unusable. Stop.
			return "", 0, false
		}
		if pos+l > len(msg) {
			return "", 0, false
		}
		if name.Len() > 0 {
			name.WriteByte('.')
		}
		name.Write(msg[pos : pos+l])
		pos += l
	}
	if pos+4 > len(msg) {
		return "", 0, false
	}
	qtype := binary.BigEndian.Uint16(msg[pos : pos+2])
	return strings.ToLower(name.String()), qtype, true
}

// buildNXDOMAIN returns the original query echoed back with QR=1 + RCODE=3.
// Returns nil if the input is unparseable; the caller skips replying.
func buildNXDOMAIN(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	out := append([]byte(nil), query...)
	// QR=1, OPCODE preserved, AA=0, TC=0, RD preserved, RA=0, Z=0, RCODE=3.
	rd := out[2] & 0x01
	out[2] = 0x80 | rd
	out[3] = 0x03
	// Zero answer/authority/additional counts.
	binary.BigEndian.PutUint16(out[6:8], 0)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	return out
}

// checkAmplifier returns a non-nil event when the source's recent traffic
// looks like amplifier reconnaissance (high query rate, ANY-type queries).
func (s *Server) checkAmplifier(srcIP string, qtype uint16) *event.Event {
	st := s.ampState
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	// Bound the per-source table: DNS source IPs are spoofable, so a flood
	// of unique sources would otherwise grow this map without limit. Past
	// the cap, sweep expired sources and, if still over, reset.
	if len(st.sources) >= ampMaxSources {
		for ip, c := range st.sources {
			if now.Sub(c.since) > s.amp.window {
				delete(st.sources, ip)
			}
		}
		if len(st.sources) >= ampMaxSources {
			st.sources = map[string]*ampSrc{}
		}
	}
	cur, ok := st.sources[srcIP]
	if !ok || now.Sub(cur.since) > s.amp.window {
		cur = &ampSrc{since: now}
		st.sources[srcIP] = cur
	}
	cur.count++
	// qtype=255 is ANY; qtype=46/48 (RRSIG/DNSKEY) and 16 (TXT) also have
	// high amplification factors. We flag ANY explicitly and use it as a
	// fast-path: even a single ANY query is suspicious.
	isAny := qtype == 255
	if isAny {
		cur.anyCount++
	}
	trigger := isAny || cur.count >= s.amp.threshold
	if !trigger {
		return nil
	}
	if now.Sub(cur.lastFired) < s.amp.window {
		return nil
	}
	cur.lastFired = now
	return &event.Event{
		ID:       event.NewID(),
		Time:     now.UTC(),
		RuleID:   "dnscanary:amplifier_probe",
		Severity: s.amp.sev,
		Source:   event.Endpoint{IP: srcIP},
		Proto:    "udp",
		Meta: map[string]any{
			"queries":          cur.count,
			"any_queries":      cur.anyCount,
			"window_s":         int(s.amp.window.Seconds()),
			"triggered_by_any": isAny,
		},
	}
}

// buildA returns the query echoed back with one A record answer pointing
// at the supplied IPv4 address. TTL is fixed at 60s. Returns nil if the
// IP is not parseable as IPv4 or the query is malformed.
func buildA(query []byte, ipv4 string) []byte {
	addr, err := net.ResolveIPAddr("ip4", ipv4)
	if err != nil || addr.IP.To4() == nil {
		return nil
	}
	if len(query) < 12 {
		return nil
	}
	// Walk the question section to find where it ends so we can append the
	// answer after it.
	pos := 12
	for pos < len(query) {
		l := int(query[pos])
		pos++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 {
			return nil
		}
		pos += l
	}
	pos += 4 // qtype + qclass
	if pos > len(query) {
		return nil
	}
	out := append([]byte{}, query[:pos]...)
	// Flip QR + RA + RCODE=0.
	rd := out[2] & 0x01
	out[2] = 0x80 | rd
	out[3] = 0x80
	binary.BigEndian.PutUint16(out[6:8], 1) // 1 answer
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)

	// Answer: name=ptr to offset 12, type=A, class=IN, ttl=60, rdlen=4, rdata=ip4
	out = append(out, 0xC0, 0x0C)
	out = binary.BigEndian.AppendUint16(out, 1)  // type A
	out = binary.BigEndian.AppendUint16(out, 1)  // class IN
	out = binary.BigEndian.AppendUint32(out, 60) // ttl
	out = binary.BigEndian.AppendUint16(out, 4)  // rdlength
	out = append(out, addr.IP.To4()...)
	return out
}

func isSubdomain(name, suffix string) bool {
	if name == suffix {
		return true
	}
	if strings.HasSuffix(name, "."+suffix) {
		return true
	}
	return false
}

func send(ctx context.Context, bus chan<- *event.Event, ev *event.Event) {
	select {
	case bus <- ev:
	case <-ctx.Done():
	}
}

func hostPortFromAddr(a net.Addr) event.Endpoint {
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
