package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// llmnr implements a poisoning responder for LLMNR (Link-Local
// Multicast Name Resolution, RFC 4795, UDP 5355). Windows clients
// fall back to LLMNR when DNS fails to resolve a single-label name;
// tools like Responder.py exploit this by claiming to be every name
// the client asks for, so the client connects to the attacker host
// and leaks NTLMv2 challenges.
//
// Our honeypot does the inverse: we observe the LLMNR query and
// emit a high-severity event including the queried name + querier
// IP. We also emit a fake A-record answer pointing at ourselves so
// the broken Windows client connects to us next (where our SMB
// listener captures the NTLM exchange).
type llmnr struct{}

func (l *llmnr) Name() string { return "llmnr" }

func (l *llmnr) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	name, qtype, ok := parseLLMNRQuery(payload)
	if !ok {
		return res, nil
	}
	res.Meta["qname"] = name
	res.Meta["qtype"] = qtype
	res.Meta["poisoning_target"] = strings.HasSuffix(name, ".") == false && strings.Count(name, ".") == 0
	// Single-label names are the Responder.py / Inveigh signature —
	// Windows resolved DNS first, got NXDOMAIN, then broadcasted LLMNR
	// asking for "wpad" / "fileshare" / a typo'd hostname. Anyone
	// poisoning a corporate network looks for exactly these queries.

	// Build a fake A-record reply pointing at our local IP. The kernel
	// gives us the local address via pc.LocalAddr() — strip the port.
	ourIP := pc.LocalAddr().String()
	if i := strings.LastIndex(ourIP, ":"); i >= 0 {
		ourIP = ourIP[:i]
	}
	if i := strings.LastIndex(ourIP, "["); i == 0 {
		// IPv6 [::1]
		ourIP = "127.0.0.1"
	}
	if reply := buildLLMNRAnswer(payload, name, qtype, ourIP); reply != nil {
		if _, err := pc.WriteTo(reply, src); err != nil {
			res.Meta["write_err"] = err.Error()
		}
		res.BannerSent = "llmnr A-record reply (poison)"
	}
	_ = cfg
	return res, nil
}

// parseLLMNRQuery reuses the DNS wire format (LLMNR is DNS-shaped).
func parseLLMNRQuery(msg []byte) (string, uint16, bool) {
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

func buildLLMNRAnswer(query []byte, name string, qtype uint16, ipv4 string) []byte {
	addr := net.ParseIP(ipv4)
	if addr == nil || addr.To4() == nil {
		return nil
	}
	if qtype != 1 { // A only — AAAA / others fall through
		return nil
	}
	// Echo the query + flip QR + set 1 answer.
	if len(query) < 12 {
		return nil
	}
	// Walk past the question section.
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
	pos += 4
	if pos > len(query) {
		return nil
	}
	out := append([]byte{}, query[:pos]...)
	rd := out[2] & 0x01
	out[2] = 0x80 | rd
	out[3] = 0
	binary.BigEndian.PutUint16(out[6:8], 1)
	out = append(out, 0xC0, 0x0C)
	out = binary.BigEndian.AppendUint16(out, 1) // A
	out = binary.BigEndian.AppendUint16(out, 1) // IN
	out = binary.BigEndian.AppendUint32(out, 30)
	out = binary.BigEndian.AppendUint16(out, 4)
	out = append(out, addr.To4()...)
	return out
}
