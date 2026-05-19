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
}

type ampConfig struct {
	enabled  bool
	window   time.Duration
	threshold int
	sev      event.Severity
}

type ampState struct {
	mu      sync.Mutex
	sources map[string]*ampSrc
}

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
	s := &Server{bind: bind, sensorName: sensorName}
	for _, c := range canaries {
		sev, err := event.ParseSeverity(c.Severity)
		if err != nil {
			return nil, fmt.Errorf("dnscanary %s: %w", c.ID, err)
		}
		s.canaries = append(s.canaries, entry{id: c.ID, sev: sev, name: c.Name})
	}
	if amp.Enabled {
		sev, err := event.ParseSeverity(amp.Severity)
		if err != nil {
			return nil, fmt.Errorf("dnscanary amplifier: %w", err)
		}
		s.amp = ampConfig{enabled: true, window: amp.Window, threshold: amp.Queries, sev: sev}
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
		go s.handle(ctx, pc, raddr, append([]byte(nil), buf[:n]...), bus)
	}
}

func (s *Server) handle(ctx context.Context, pc net.PacketConn, raddr net.Addr, msg []byte, bus chan<- *event.Event) {
	name, qtype, ok := parseQuery(msg)
	if !ok {
		return
	}
	src := hostPortFromAddr(raddr)

	// Always emit a low-severity "query received" event so the operator sees
	// the noise floor even when no canary fired.
	baseEv := &event.Event{
		ID:       event.NewID(),
		Time:     time.Now().UTC(),
		Sensor:   s.sensorName,
		RuleID:   "dnscanary:query",
		Severity: event.SeverityLow,
		Source:   src,
		Proto:    "udp",
		Meta: map[string]any{
			"qname": name,
			"qtype": qtype,
		},
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

	// Try honeynet forward resolution for A queries; otherwise NXDOMAIN.
	var reply []byte
	if qtype == 1 && s.resolve != nil {
		if ip, hostname, ok := s.resolve(name); ok {
			reply = buildA(msg, ip)
			baseEv.Meta["honeynet_resolved"] = hostname
			baseEv.Meta["honeynet_ip"] = ip
		}
	}
	if reply == nil {
		reply = buildNXDOMAIN(msg)
	}
	if reply != nil {
		_ = pc.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = pc.WriteTo(reply, raddr)
	}
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
			"queries":     cur.count,
			"any_queries": cur.anyCount,
			"window_s":    int(s.amp.window.Seconds()),
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
