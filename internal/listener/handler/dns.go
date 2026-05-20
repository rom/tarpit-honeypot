package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// dnsResolver is a UDP DNS handler that ANSWERS queries with fabricated
// records — distinct from the dnscanary listener (which fires on
// pre-registered canary names and otherwise NXDOMAINs). This one makes
// the sensor look like a real, recursive-ish resolver / authoritative
// server: A / AAAA / MX / TXT / NS / CNAME queries get a believable
// fake answer so a scanner enumerating DNS sees a live, populated
// server. Every query is captured + run through the same tunneling /
// abnormal-payload detection the canary listener uses.
//
// The fabricated A address is deterministic per (deployment, qname) so
// the same name always resolves to the same fake IP within a sensor —
// a re-query is consistent, but two deployments differ.
type dnsHandler struct {
	id *identity.Identity
}

func (d *dnsHandler) Name() string { return "dns" }

func (d *dnsHandler) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	q, ok := parseDNSQuery(payload)
	if !ok {
		res.Meta["malformed_dns"] = true
		return res, nil
	}
	res.Meta["qname"] = safe.SanitizeForLog(q.name)
	res.Meta["qtype"] = q.qtype
	res.Meta["qtype_name"] = dnsTypeName(q.qtype)

	// Abnormal-payload / tunneling markers (reuse the same heuristics
	// shape as the canary listener).
	for _, a := range dnsQueryAnomalies(q.name, q.qtype, len(payload)) {
		flagAnomaly(&res, a)
	}

	reply := d.buildAnswer(payload, q)
	if reply != nil {
		if _, err := pc.WriteTo(reply, src); err != nil {
			res.Meta["write_err"] = err.Error()
		} else {
			res.BannerSent = "dns answer (" + dnsTypeName(q.qtype) + ")"
		}
	}
	_ = cfg
	return res, nil
}

type dnsQuery struct {
	name  string
	qtype uint16
	// rawNameEnd is the byte offset just past the question's QNAME+QTYPE+QCLASS.
	questionEnd int
}

// parseDNSQuery extracts the first question from a DNS message.
func parseDNSQuery(msg []byte) (dnsQuery, bool) {
	if len(msg) < 12 {
		return dnsQuery{}, false
	}
	qd := binary.BigEndian.Uint16(msg[4:6])
	if qd < 1 {
		return dnsQuery{}, false
	}
	pos := 12
	var labels []string
	for pos < len(msg) {
		l := int(msg[pos])
		if l == 0 {
			pos++
			break
		}
		if l&0xC0 != 0 { // compression pointer in a question — bail
			return dnsQuery{}, false
		}
		pos++
		chunk, ok := safe.Slice(msg, pos, l)
		if !ok {
			return dnsQuery{}, false
		}
		labels = append(labels, string(chunk))
		pos += l
		if len(labels) > 127 {
			return dnsQuery{}, false
		}
	}
	if pos+4 > len(msg) {
		return dnsQuery{}, false
	}
	qtype := binary.BigEndian.Uint16(msg[pos : pos+2])
	pos += 4 // qtype + qclass
	return dnsQuery{name: strings.ToLower(strings.Join(labels, ".")), qtype: qtype, questionEnd: pos}, true
}

// buildAnswer constructs a DNS response with a fabricated answer for
// the supported qtypes, echoing the question section. Unsupported
// qtypes get NOERROR with zero answers (a believable "no such record").
func (d *dnsHandler) buildAnswer(query []byte, q dnsQuery) []byte {
	if q.questionEnd > len(query) || q.questionEnd < 12 {
		return nil
	}
	// Response header: copy ID, set QR=1, RA=1, RCODE=0.
	resp := make([]byte, q.questionEnd)
	copy(resp, query[:q.questionEnd])
	resp[2] = 0x81                           // QR=1, Opcode=0, AA=0, TC=0, RD=1
	resp[3] = 0x80                           // RA=1, RCODE=0
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT = 1

	var rdata []byte
	var ancount uint16
	switch q.qtype {
	case 1: // A
		ip := d.fakeIPv4(q.name)
		rdata = d.aRecord(1, ip[:])
		ancount = 1
	case 28: // AAAA
		ip := d.fakeIPv6(q.name)
		rdata = d.aRecord(28, ip[:])
		ancount = 1
	case 16: // TXT
		txt := "v=spf1 include:_spf." + topDomain(q.name) + " ~all"
		rdata = d.txtRecord(txt)
		ancount = 1
	case 15: // MX
		rdata = d.mxRecord(10, "mail."+topDomain(q.name))
		ancount = 1
	case 2: // NS
		rdata = d.nsRecord("ns1." + topDomain(q.name))
		ancount = 1
	case 5: // CNAME
		rdata = d.nsRecordType(5, "www."+topDomain(q.name))
		ancount = 1
	default:
		ancount = 0
	}
	binary.BigEndian.PutUint16(resp[6:8], ancount)
	binary.BigEndian.PutUint16(resp[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:12], 0) // ARCOUNT
	if rdata != nil {
		resp = append(resp, rdata...)
	}
	return resp
}

// aRecord builds an answer RR for A/AAAA with a name-compression
// pointer to the question (0xC00C) + the supplied rdata bytes.
func (d *dnsHandler) aRecord(rrtype uint16, ip []byte) []byte {
	out := []byte{0xC0, 0x0C} // pointer to QNAME at offset 12
	out = binary.BigEndian.AppendUint16(out, rrtype)
	out = binary.BigEndian.AppendUint16(out, 1)   // class IN
	out = binary.BigEndian.AppendUint32(out, 300) // TTL 5m
	out = binary.BigEndian.AppendUint16(out, uint16(len(ip)))
	out = append(out, ip...)
	return out
}

func (d *dnsHandler) txtRecord(s string) []byte {
	out := []byte{0xC0, 0x0C}
	out = binary.BigEndian.AppendUint16(out, 16)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint32(out, 300)
	// RDATA: 1-byte length-prefixed string.
	rd := append([]byte{byte(len(s))}, []byte(s)...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rd)))
	out = append(out, rd...)
	return out
}

func (d *dnsHandler) mxRecord(pref uint16, host string) []byte {
	out := []byte{0xC0, 0x0C}
	out = binary.BigEndian.AppendUint16(out, 15)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint32(out, 300)
	rd := binary.BigEndian.AppendUint16(nil, pref)
	rd = append(rd, encodeDNSName(host)...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rd)))
	out = append(out, rd...)
	return out
}

func (d *dnsHandler) nsRecord(host string) []byte { return d.nsRecordType(2, host) }
func (d *dnsHandler) nsRecordType(rrtype uint16, host string) []byte {
	out := []byte{0xC0, 0x0C}
	out = binary.BigEndian.AppendUint16(out, rrtype)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint32(out, 300)
	rd := encodeDNSName(host)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rd)))
	out = append(out, rd...)
	return out
}

// publicFirstOctets is a curated set of first octets that fall in
// globally-routable space — deliberately excluding RFC1918 (10/172/192),
// loopback (127), link-local (169), CGNAT (100), "this network" (0), and
// multicast/reserved (>=224). Picking ip[0] from this set guarantees the
// fabricated A record looks like a real internet host regardless of name.
var publicFirstOctets = []byte{23, 34, 45, 52, 66, 72, 88, 93, 104, 128, 134, 142, 151, 162, 173, 185, 199, 203, 208, 216}

// fakeIPv4 returns a deterministic, plausible-looking public IPv4 for a
// name (stable per deployment). The first octet is chosen from a curated
// public set so the answer never lands in RFC1918 / loopback / link-local
// / CGNAT / multicast space.
func (d *dnsHandler) fakeIPv4(name string) [4]byte {
	var seed uint32
	if d.id != nil {
		seed = d.id.Uint32("dns-a/" + name)
	} else {
		for _, c := range name {
			seed = seed*131 + uint32(c)
		}
	}
	var ip [4]byte
	ip[0] = publicFirstOctets[seed%uint32(len(publicFirstOctets))]
	ip[1] = byte(seed >> 8)
	ip[2] = byte(seed >> 16)
	ip[3] = byte(seed>>24)%254 + 1
	return ip
}

func (d *dnsHandler) fakeIPv6(name string) [16]byte {
	var ip [16]byte
	ip[0] = 0x20
	ip[1] = 0x01 // 2001::/16 global unicast
	b := []byte(name)
	for i := 0; i < len(b) && i < 14; i++ {
		ip[2+i%14] ^= b[i]
	}
	if d.id != nil {
		s := d.id.Bytes("dns-aaaa/"+name, 8)
		copy(ip[8:], s)
	}
	return ip
}

// encodeDNSName encodes "a.b.c" as length-prefixed labels + root null.
func encodeDNSName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0)
	return out
}

func topDomain(name string) string {
	parts := strings.Split(name, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	if name == "" {
		return "example.com"
	}
	return name
}

func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	}
	return ""
}

// dnsQueryAnomalies mirrors the dnscanary tunneling heuristics for the
// resolving handler (kept local to avoid an import cycle).
func dnsQueryAnomalies(name string, qtype uint16, msgLen int) []string {
	var out []string
	if len(name) > 200 {
		out = append(out, "dns-qname-overlong")
	}
	for _, l := range strings.Split(name, ".") {
		if len(l) >= 50 {
			out = append(out, "dns-label-overlong")
		}
		if len(l) >= 20 && dnsLabelLooksEncoded(l) {
			out = append(out, "dns-high-entropy-label")
			break
		}
	}
	if qtype == 10 || qtype == 16 {
		out = append(out, "dns-tunneling-qtype")
	}
	if msgLen > 512 {
		out = append(out, "dns-oversize-query")
	}
	return out
}

func dnsLabelLooksEncoded(l string) bool {
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
	return alnum == len(l) && digits*5 >= len(l)
}
