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
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

type Server struct {
	bind       string
	sensorName string
	canaries   []entry
}

type entry struct {
	id  string
	sev event.Severity
	// suffix match: a canary at "foo.bar.example.com" matches that name and
	// any subdomain (e.g. "x.foo.bar.example.com"). All canary names are
	// lowercased + trailing-dot stripped at load time.
	name string
}

func New(bind string, sensorName string, canaries []config.DNSCanary) (*Server, error) {
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

	// Reply with NXDOMAIN so the resolver caches a negative result quickly.
	reply := buildNXDOMAIN(msg)
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
