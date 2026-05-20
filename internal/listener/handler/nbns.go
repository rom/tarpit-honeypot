package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// nbns is the NetBIOS Name Service responder (UDP 137). Same role as
// llmnr: Windows clients broadcast NBNS lookups for single-label names
// when DNS fails; attackers running Responder/Inveigh impersonate the
// queried name to harvest NTLM. We log the queried name + replier IP
// at high severity and (optionally) answer with our local IP so the
// follow-up SMB connect lands at our trap.
//
// NetBIOS encodes names with a peculiar "first-level encoding": each
// nibble of the original is mapped to a letter A-P, doubling the
// length. The encoded form is 32 chars (the unencoded 16-byte name
// is padded with spaces / a service byte).
type nbns struct{}

func (n *nbns) Name() string { return "nbns" }

func (n *nbns) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	name, decoded, qtype, ok := parseNBNSQuery(payload)
	if !ok {
		return res, nil
	}
	res.Meta["encoded_name"] = name
	res.Meta["netbios_name"] = decoded
	res.Meta["qtype"] = qtype

	// Construct a positive name-query response pointing at our local IP.
	ourIP := pc.LocalAddr().String()
	if i := strings.LastIndex(ourIP, ":"); i >= 0 {
		ourIP = ourIP[:i]
	}
	if reply := buildNBNSAnswer(payload, ourIP); reply != nil {
		if _, err := pc.WriteTo(reply, src); err != nil {
			res.Meta["write_err"] = err.Error()
		}
		res.BannerSent = "nbns positive name-query response (poison)"
	}
	_ = cfg
	return res, nil
}

// parseNBNSQuery extracts the NetBIOS-encoded label and the decoded
// 16-byte name + service byte.
func parseNBNSQuery(msg []byte) (encoded, decoded string, qtype uint16, ok bool) {
	if len(msg) < 12 {
		return "", "", 0, false
	}
	if msg[12] != 32 { // first label length is always 32 for NetBIOS
		return "", "", 0, false
	}
	if 13+32 > len(msg) {
		return "", "", 0, false
	}
	enc := msg[13 : 13+32]
	encoded = string(enc)
	dec := make([]byte, 16)
	for i := 0; i < 16; i++ {
		hi := enc[i*2] - 'A'
		lo := enc[i*2+1] - 'A'
		if hi > 15 || lo > 15 {
			return "", "", 0, false
		}
		dec[i] = (hi << 4) | lo
	}
	// Strip trailing spaces; the last byte is the NetBIOS suffix.
	suffix := dec[15]
	name := strings.TrimRight(string(dec[:15]), " ")
	decoded = name + "<" + hex2(suffix) + ">"
	pos := 13 + 32
	if pos+1 > len(msg) || msg[pos] != 0 {
		return "", "", 0, false
	}
	pos++ // null terminator
	if pos+4 > len(msg) {
		return "", "", 0, false
	}
	qtype = binary.BigEndian.Uint16(msg[pos : pos+2])
	return encoded, decoded, qtype, true
}

func hex2(b byte) string {
	const h = "0123456789abcdef"
	return string([]byte{h[b>>4], h[b&0x0f]})
}

func buildNBNSAnswer(query []byte, ipv4 string) []byte {
	addr := net.ParseIP(ipv4)
	if addr == nil || addr.To4() == nil {
		return nil
	}
	if len(query) < 12 {
		return nil
	}
	// Echo header + question, flip QR + set 1 answer + RCODE=0.
	pos := 12
	if pos+1 > len(query) {
		return nil
	}
	pos += 1 + int(query[12]) // encoded label
	if pos+1 > len(query) {
		return nil
	}
	pos++    // null terminator
	pos += 4 // qtype + qclass
	if pos > len(query) {
		return nil
	}
	out := append([]byte{}, query[:pos]...)
	out[2] = 0x85 // QR=1, OPCODE=0, AA=1, TC=0, RD=1
	out[3] = 0x80 // RA=1, no error
	binary.BigEndian.PutUint16(out[6:8], 1)
	// Answer: name pointer to offset 12, type=NB(0x20), class=IN, TTL=0,
	// rdlength=6, flags(2)=0x0000, IPv4(4)
	out = append(out, 0xC0, 0x0C)
	out = binary.BigEndian.AppendUint16(out, 0x0020) // NB
	out = binary.BigEndian.AppendUint16(out, 1)      // IN
	out = binary.BigEndian.AppendUint32(out, 30)
	out = binary.BigEndian.AppendUint16(out, 6)
	out = append(out, 0, 0)
	out = append(out, addr.To4()...)
	return out
}
