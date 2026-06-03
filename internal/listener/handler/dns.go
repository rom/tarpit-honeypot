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

// dnsHandler is a UDP DNS handler that answers queries coherently with
// the configured honeynet topology — distinct from the dnscanary
// listener (which fires on pre-registered canary names and otherwise
// NXDOMAINs). When a query matches a virtual host (by FQDN, or by reverse
// address for PTR) it returns that host's real virtual IP, an
// archetype-derived HINFO, and topology-consistent SRV / NS / SOA / MX
// records for the host's domain (so e.g. an AD SRV lookup resolves to the
// virtual Domain Controller). Names outside the topology get a
// deterministic fabricated answer so a scanner enumerating the resolver
// still sees a live, populated server. Every query is captured + run
// through the same tunneling / abnormal-payload detection the canary
// listener uses.
//
// Supported qtypes: A, NS, CNAME, SOA, PTR, HINFO, MX, TXT, AAAA, LOC,
// SRV. Fabricated answers are deterministic per (deployment, name) so a
// re-query is consistent and two deployments differ.
type dnsHandler struct {
	id   *identity.Identity
	topo HoneynetSnapshot
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

	reply := d.buildAnswer(payload, q, cfg)
	if reply != nil {
		if _, err := pc.WriteTo(reply, src); err != nil {
			res.Meta["write_err"] = err.Error()
		} else {
			res.BannerSent = "dns answer (" + dnsTypeName(q.qtype) + ")"
		}
	}
	return res, nil
}

type dnsQuery struct {
	name   string
	qtype  uint16
	qclass uint16 // 1 = IN, 3 = CHAOS (version.bind), …
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
	qclass := binary.BigEndian.Uint16(msg[pos+2 : pos+4])
	pos += 4 // qtype + qclass
	return dnsQuery{name: strings.ToLower(strings.Join(labels, ".")), qtype: qtype, qclass: qclass, questionEnd: pos}, true
}

// buildAnswer constructs a DNS response, preferring topology-coherent
// answers (real virtual host IPs, the domain's DC/NS/mail) and falling
// back to deterministic fabricated records for names outside the
// topology. Unsupported qtypes get NOERROR with zero answers.
func (d *dnsHandler) buildAnswer(query []byte, q dnsQuery, cfg config.Listener) []byte {
	if q.questionEnd > len(query) || q.questionEnd < 12 {
		return nil
	}
	// CHAOS-class (3) version.bind / hostname.bind / authors.bind queries: a
	// decoy server happily reports a (deliberately old, exploitable-looking)
	// version banner. This is the classic `dig @host version.bind chaos txt`.
	if q.qclass == 3 && q.qtype == 16 {
		if v := chaosValue(q.name, cfg.DNS.VersionBind, d); v != "" {
			return dnsChaosTXT(query, q, v)
		}
	}
	// AXFR/IXFR are streamed by the TCP handler when fake_zone is enabled; the
	// UDP path never serves a zone (avoids a huge spoofable reply).
	// Response header: copy ID, set QR=1, RA=1, RCODE=0. AA=1 when the
	// answer comes from our own (authoritative) topology.
	resp := make([]byte, q.questionEnd)
	copy(resp, query[:q.questionEnd])
	resp[2] = 0x81                           // QR=1, Opcode=0, AA=0, TC=0, RD=1
	resp[3] = 0x80                           // RA=1, RCODE=0
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT = 1

	host, _, isHost := d.lookupFQDN(q.name)
	dom := d.domainFor(q.name)
	if isHost || dom != "" {
		resp[2] |= 0x04 // AA: authoritative for our topology
	}

	var rdata []byte
	var ancount uint16
	switch q.qtype {
	case 1: // A
		if isHost {
			if v4 := net.ParseIP(host.IP).To4(); v4 != nil {
				rdata = answerRR(1, v4)
				ancount = 1
			}
		}
		if ancount == 0 {
			ip := d.fakeIPv4(q.name)
			rdata = answerRR(1, ip[:])
			ancount = 1
		}
	case 28: // AAAA
		if isHost {
			if v6 := net.ParseIP(host.IP); v6 != nil && v6.To4() == nil {
				rdata = answerRR(28, v6.To16())
				ancount = 1
			}
			// v4-only virtual host: NODATA for AAAA (realistic).
		} else {
			ip := d.fakeIPv6(q.name)
			rdata = answerRR(28, ip[:])
			ancount = 1
		}
	case 2: // NS
		rdata = answerRR(2, encodeDNSName(d.nsName(dom)))
		ancount = 1
	case 5: // CNAME
		rdata = answerRR(5, encodeDNSName("www."+orDefault(dom)))
		ancount = 1
	case 6: // SOA
		rdata = answerRR(6, d.soaData(orDefault(dom)))
		ancount = 1
	case 12: // PTR
		if name, ok := d.reverseLookup(q.name); ok {
			rdata = answerRR(12, encodeDNSName(name))
			ancount = 1
		}
	case 13: // HINFO
		cpu, os := hinfoFor(host, isHost)
		rdata = answerRR(13, append(charString(cpu), charString(os)...))
		ancount = 1
	case 15: // MX
		rdata = answerRR(15, mxData(10, d.mailName(dom)))
		ancount = 1
	case 16: // TXT
		rdata = answerRR(16, charString("v=spf1 include:_spf."+orDefault(dom)+" ~all"))
		ancount = 1
	case 29: // LOC
		rdata = answerRR(29, locData())
		ancount = 1
	case 33: // SRV
		if target, prio, weight, port, ok := d.resolveSRV(q.name); ok {
			rdata = answerRR(33, srvData(prio, weight, port, target))
			ancount = 1
		}
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

// answerRR builds an RR whose owner is a name-compression pointer to the
// question (0xC00C) — valid because every answer is about q.name.
func answerRR(rrtype uint16, rdata []byte) []byte {
	out := []byte{0xC0, 0x0C}
	out = binary.BigEndian.AppendUint16(out, rrtype)
	out = binary.BigEndian.AppendUint16(out, 1)   // class IN
	out = binary.BigEndian.AppendUint32(out, 300) // TTL 5m
	out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
	return append(out, rdata...)
}

// charString encodes a DNS character-string (1-byte length prefix).
func charString(s string) []byte {
	if len(s) > 255 {
		s = s[:255]
	}
	return append([]byte{byte(len(s))}, []byte(s)...)
}

func mxData(pref uint16, host string) []byte {
	rd := binary.BigEndian.AppendUint16(nil, pref)
	return append(rd, encodeDNSName(host)...)
}

func srvData(prio, weight, port uint16, target string) []byte {
	rd := binary.BigEndian.AppendUint16(nil, prio)
	rd = binary.BigEndian.AppendUint16(rd, weight)
	rd = binary.BigEndian.AppendUint16(rd, port)
	return append(rd, encodeDNSName(target)...)
}

// locData encodes a fixed, plausible LOC record (a generic datacenter
// location): version 0, size/precision defaults, lat/lon ~ 0,0, 10m alt.
func locData() []byte {
	const base = uint32(1) << 31 // 0 degrees offset
	out := []byte{0x00, 0x12, 0x16, 0x13}
	out = binary.BigEndian.AppendUint32(out, base)            // latitude
	out = binary.BigEndian.AppendUint32(out, base)            // longitude
	out = binary.BigEndian.AppendUint32(out, 10000000+10*100) // altitude
	return out
}

func (d *dnsHandler) soaData(dom string) []byte {
	rd := encodeDNSName(d.nsName(dom))
	rd = append(rd, encodeDNSName("hostmaster."+dom)...)
	serial := uint32(2024010101)
	if d.id != nil {
		serial = 2024010100 + d.id.Uint32("dns-soa/"+dom)%99 + 1
	}
	rd = binary.BigEndian.AppendUint32(rd, serial)
	rd = binary.BigEndian.AppendUint32(rd, 3600)   // refresh
	rd = binary.BigEndian.AppendUint32(rd, 600)    // retry
	rd = binary.BigEndian.AppendUint32(rd, 604800) // expire
	rd = binary.BigEndian.AppendUint32(rd, 300)    // minimum
	return rd
}

// ---- topology resolution ----

// lookupFQDN finds the virtual host whose FQDN (hostname[.domain]) equals
// name, returning the host + its network.
func (d *dnsHandler) lookupFQDN(name string) (HoneynetHost, HoneynetNetwork, bool) {
	for _, h := range d.topo.Hosts {
		if h.Hostname == "" {
			continue
		}
		netw := d.networkByID(h.NetID)
		fqdn := h.Hostname
		if netw.Domain != "" {
			fqdn = h.Hostname + "." + netw.Domain
		}
		if strings.EqualFold(name, fqdn) || strings.EqualFold(name, h.Hostname) {
			return h, netw, true
		}
	}
	return HoneynetHost{}, HoneynetNetwork{}, false
}

func (d *dnsHandler) networkByID(id string) HoneynetNetwork {
	for _, n := range d.topo.Networks {
		if n.ID == id {
			return n
		}
	}
	return HoneynetNetwork{}
}

// domainFor returns the configured honeynet domain that is a suffix of
// name (the longest match), or "" if none.
func (d *dnsHandler) domainFor(name string) string {
	best := ""
	for _, n := range d.topo.Networks {
		if n.Domain == "" {
			continue
		}
		if name == n.Domain || strings.HasSuffix(name, "."+n.Domain) {
			if len(n.Domain) > len(best) {
				best = n.Domain
			}
		}
	}
	return best
}

// nsName / mailName pick the network's resolver / a mail host when the
// topology defines one, else a believable default under the domain.
func (d *dnsHandler) nsName(dom string) string {
	if dom != "" {
		for _, n := range d.topo.Networks {
			if n.Domain == dom && n.DNS != "" {
				if h := d.hostByIP(n.DNS); h.Hostname != "" {
					return h.Hostname + "." + dom
				}
			}
		}
	}
	return "ns1." + orDefault(dom)
}

func (d *dnsHandler) mailName(dom string) string {
	if h := d.hostWithHandler(dom, "smtp_recv"); h.Hostname != "" {
		return h.Hostname + "." + dom
	}
	return "mail." + orDefault(dom)
}

// reverseLookup resolves an in-addr.arpa PTR query to a virtual host's
// FQDN when the address matches; else fabricates a believable reverse
// name so the zone looks populated.
func (d *dnsHandler) reverseLookup(name string) (string, bool) {
	ip, ok := reverseToIP(name)
	if !ok {
		return "", false
	}
	if h := d.hostByIP(ip); h.Hostname != "" {
		netw := d.networkByID(h.NetID)
		if netw.Domain != "" {
			return h.Hostname + "." + netw.Domain, true
		}
		return h.Hostname, true
	}
	return "host-" + strings.ReplaceAll(ip, ".", "-") + ".in-addr.arpa", true
}

func (d *dnsHandler) hostByIP(ip string) HoneynetHost {
	for _, h := range d.topo.Hosts {
		if h.IP == ip {
			return h
		}
	}
	return HoneynetHost{}
}

func (d *dnsHandler) hostWithHandler(dom, handler string) HoneynetHost {
	for _, h := range d.topo.Hosts {
		if dom != "" && d.networkByID(h.NetID).Domain != dom {
			continue
		}
		for _, s := range h.Services {
			if s.Handler == handler {
				return h
			}
		}
	}
	return HoneynetHost{}
}

// resolveSRV maps an "_service._proto.<...>.<domain>" query to a virtual
// host offering the corresponding service in that domain. Returns the
// SRV target FQDN + port (priority 0, weight 100).
func (d *dnsHandler) resolveSRV(name string) (target string, prio, weight, port uint16, ok bool) {
	labels := strings.Split(name, ".")
	if len(labels) < 3 || !strings.HasPrefix(labels[0], "_") {
		return "", 0, 0, 0, false
	}
	handler, defPort := srvServiceHandler(labels[0])
	if handler == "" {
		return "", 0, 0, 0, false
	}
	dom := d.domainFor(name)
	for _, h := range d.topo.Hosts {
		netw := d.networkByID(h.NetID)
		if dom != "" && netw.Domain != dom {
			continue
		}
		for _, s := range h.Services {
			if s.Handler == handler {
				fqdn := h.Hostname
				if netw.Domain != "" {
					fqdn = h.Hostname + "." + netw.Domain
				}
				p := uint16(s.Port)
				if p == 0 {
					p = defPort
				}
				return fqdn, 0, 100, p, true
			}
		}
	}
	return "", 0, 0, 0, false
}

// srvServiceHandler maps an SRV service label to the handler that backs
// it (and its default port) so an AD/service SRV lookup resolves to the
// right virtual host.
func srvServiceHandler(label string) (handler string, port uint16) {
	switch label {
	case "_ldap", "_gc":
		return "ldap", 389
	case "_kerberos", "_kerberos-master":
		return "kerberos", 88
	case "_ldaps":
		return "https", 636
	case "_http":
		return "http", 80
	case "_https":
		return "https", 443
	case "_ssh":
		return "ssh", 22
	case "_smtp", "_submission":
		return "smtp_recv", 25
	case "_sip":
		return "sip", 5060
	case "_xmpp-client", "_xmpp-server":
		return "xmpp", 5222
	case "_rdp":
		return "rdp", 3389
	case "_vnc":
		return "vnc", 5900
	case "_mqtt":
		return "mqtt", 1883
	}
	return "", 0
}

// hinfoFor returns the (CPU, OS) HINFO strings for a host (from its OS /
// archetype family) or a generic pair for unknown names.
func hinfoFor(h HoneynetHost, isHost bool) (cpu, os string) {
	if !isHost {
		return "x86_64", "Linux"
	}
	switch strings.ToLower(h.OS) {
	case "windows":
		return "Intel64 Family 6", "Windows Server 2019"
	case "ics", "plc", "ot":
		return "ARM", "VxWorks"
	case "cisco":
		return "MIPS", "Cisco IOS"
	case "bsd", "freebsd", "openbsd":
		return "amd64", "BSD"
	case "", "linux":
		return "x86_64", "Linux"
	}
	return "x86_64", h.OS
}

// reverseToIP turns "20.0.0.10.in-addr.arpa" into "10.0.0.20".
func reverseToIP(name string) (string, bool) {
	const suffix = ".in-addr.arpa"
	n := strings.TrimSuffix(name, ".")
	if !strings.HasSuffix(n, suffix) {
		return "", false
	}
	rev := strings.Split(strings.TrimSuffix(n, suffix), ".")
	if len(rev) != 4 {
		return "", false
	}
	return rev[3] + "." + rev[2] + "." + rev[1] + "." + rev[0], true
}

func orDefault(dom string) string {
	if dom == "" {
		return "example.com"
	}
	return dom
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
	case 13:
		return "HINFO"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 29:
		return "LOC"
	case 33:
		return "SRV"
	case 251:
		return "IXFR"
	case 252:
		return "AXFR"
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
	// ANY (255) is the DNS-amplification primitive — one tiny query asks for
	// every record, and with a spoofable UDP source it reflects amplified at a
	// third party. The DNS handler caps its own answer sizes, but the probe
	// itself is high-signal recon.
	if qtype == 255 {
		out = append(out, "dns-any-amplification")
	}
	// AXFR (252) / IXFR (251): a zone-transfer request tries to dump the
	// whole zone — classic recon against a misconfigured authoritative
	// server (and a strong tell on a workstation/DC archetype). We never
	// serve the zone; we just flag the attempt.
	if qtype == 251 || qtype == 252 {
		out = append(out, "dns-zone-transfer")
	}
	// DNSCrypt certificate lookup ("<v>.dnscrypt-cert.<provider>") — a tell
	// that an encrypted-DNS (DNSCrypt) channel is being set up.
	if strings.Contains(name, "dnscrypt-cert.") {
		out = append(out, "dnscrypt-probe")
	}
	// DGA: address lookups (A/AAAA) for algorithmically-generated domains.
	if qtype == 1 || qtype == 28 {
		for _, l := range strings.Split(name, ".") {
			if dnsLabelLooksDGA(l) {
				out = append(out, "dns-dga-suspected")
				break
			}
		}
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

// dnsLabelLooksDGA mirrors dnscanary.looksDGALabel (kept local to avoid an
// import cycle): a long, vowel-poor / digit-heavy / consonant-run-heavy
// label of the kind a malware DGA generates.
func dnsLabelLooksDGA(l string) bool {
	if len(l) < 12 || len(l) > 63 {
		return false
	}
	vowels, digits, alpha, run, maxRun := 0, 0, 0, 0, 0
	for i := 0; i < len(l); i++ {
		switch c := l[i]; {
		case c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u':
			vowels++
			alpha++
			run = 0
		case c >= 'a' && c <= 'z':
			alpha++
			run++
			if run > maxRun {
				maxRun = run
			}
		case c >= '0' && c <= '9':
			digits++
			run = 0
		default:
			return false
		}
	}
	if alpha == 0 {
		return false
	}
	vowelPoor := vowels*100 < len(l)*26
	digitHeavy := digits*4 >= len(l) && digits*10 <= len(l)*7
	return vowelPoor || maxRun >= 6 || digitHeavy
}

// --- version.bind / hostname.bind (CHAOS) + fake zone-transfer decoys --------

// chaosValue returns the string answer for a CHAOS-class TXT query. configured
// is the operator's version_bind override (used for version.bind/version.server);
// empty falls back to a deliberately old, exploitable-looking BIND banner.
func chaosValue(name, configured string, d *dnsHandler) string {
	switch strings.ToLower(strings.TrimSuffix(name, ".")) {
	case "version.bind", "version.server":
		if configured != "" {
			return configured
		}
		return "9.8.1-P1" // an old BIND with known RCEs — a juicy decoy
	case "hostname.bind", "id.server":
		if d != nil && d.id != nil {
			return d.id.HostName()
		}
		return "ns1"
	case "authors.bind":
		return "decoy"
	}
	return ""
}

// dnsChaosTXT builds a single-answer response carrying a CHAOS-class TXT record
// (class 3) with value — the reply to a version.bind probe.
func dnsChaosTXT(query []byte, q dnsQuery, value string) []byte {
	resp := make([]byte, q.questionEnd)
	copy(resp, query[:q.questionEnd])
	resp[2] = 0x85 // QR=1, AA=1, RD=1
	resp[3] = 0x80 // RA=1, RCODE=0
	binary.BigEndian.PutUint16(resp[4:6], 1)
	binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT=1
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	rr := []byte{0xC0, 0x0C}                   // owner = pointer to question
	rr = binary.BigEndian.AppendUint16(rr, 16) // TYPE TXT
	rr = binary.BigEndian.AppendUint16(rr, 3)  // CLASS CHAOS
	rr = binary.BigEndian.AppendUint32(rr, 0)  // TTL 0
	rd := charString(value)
	rr = binary.BigEndian.AppendUint16(rr, uint16(len(rd)))
	rr = append(rr, rd...)
	return append(resp, rr...)
}

// fullRR encodes a resource record with an explicit (uncompressed) owner name.
func fullRR(name string, rrtype uint16, ttl uint32, rdata []byte) []byte {
	out := encodeDNSName(name)
	out = binary.BigEndian.AppendUint16(out, rrtype)
	out = binary.BigEndian.AppendUint16(out, 1) // class IN
	out = binary.BigEndian.AppendUint32(out, ttl)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
	return append(out, rdata...)
}

// fakeZoneServices are the believable service hostnames leaked in a fabricated
// zone — exactly what an attacker who pulls AXFR hopes to find.
var fakeZoneServices = []string{
	"www", "mail", "mail2", "smtp", "imap", "pop", "autodiscover", "owa",
	"webmail", "vpn", "remote", "citrix", "portal", "intranet", "extranet",
	"jenkins", "gitlab", "git", "jira", "confluence", "vault", "ad", "dc",
	"ldap", "kerberos", "db", "db1", "mysql", "mssql", "oracle", "mongo",
	"redis", "backup", "nas", "ftp", "sftp", "rdp", "ssh", "jump", "bastion",
	"grafana", "kibana", "prometheus", "api", "api-internal", "dev", "staging",
	"test", "uat", "admin", "phpmyadmin", "router", "fw", "switch", "printer",
}

// buildFakeZone fabricates a full, juicy AXFR/IXFR response for the queried
// apex: SOA, NS, MX, A, a wide set of service A records, SRV for AD, TXT
// "secrets", and a closing SOA. Returned as the list of TCP messages to send
// (one message here — all RRs fit comfortably).
func (d *dnsHandler) buildFakeZone(query []byte, q dnsQuery, cfg config.Listener) [][]byte {
	dom := strings.TrimSuffix(q.name, ".")
	if cfg.DNS.ZoneDomain != "" {
		dom = strings.TrimSuffix(cfg.DNS.ZoneDomain, ".")
	}
	if dom == "" {
		dom = "corp.local"
	}
	resp := make([]byte, q.questionEnd)
	copy(resp, query[:q.questionEnd])
	resp[2] = 0x84                           // QR=1, AA=1
	resp[3] = 0x80                           // RA=1
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT

	var body []byte
	var n uint16
	add := func(b []byte) { body = append(body, b...); n++ }

	soa := d.soaData(dom)
	add(fullRR(dom, 6, 3600, soa)) // opening SOA (AXFR convention)
	add(fullRR(dom, 2, 3600, encodeDNSName("ns1."+dom)))
	add(fullRR(dom, 2, 3600, encodeDNSName("ns2."+dom)))
	add(fullRR(dom, 15, 3600, mxData(10, "mail."+dom)))
	add(fullRR(dom, 15, 3600, mxData(20, "mail2."+dom)))
	apex := d.fakeIPv4(dom)
	add(fullRR(dom, 1, 3600, apex[:]))
	// Service A records — the inventory an AXFR puller is hunting for.
	for _, svc := range fakeZoneServices {
		host := svc + "." + dom
		ip := d.fakeIPv4(host)
		add(fullRR(host, 1, 3600, ip[:]))
	}
	// AD service-discovery SRV records (point at the fake DC).
	add(fullRR("_ldap._tcp."+dom, 33, 3600, srvData(0, 100, 389, "dc."+dom)))
	add(fullRR("_kerberos._tcp."+dom, 33, 3600, srvData(0, 100, 88, "dc."+dom)))
	add(fullRR("_kpasswd._udp."+dom, 33, 3600, srvData(0, 100, 464, "dc."+dom)))
	// TXT "secrets" — SPF/DKIM/DMARC plus deliberately tempting fake material.
	txts := []string{
		"v=spf1 include:_spf." + dom + " ~all",
		"v=DMARC1; p=none; rua=mailto:dmarc@" + dom,
		"google-site-verification=" + d.fakeHex("gsv/"+dom, 32),
		"internal-note: legacy admin creds in vault, see infra wiki",
		"backup-key=" + d.fakeHex("bk/"+dom, 24),
	}
	txts = append(txts, cfg.DNS.ExtraTXT...)
	for _, t := range txts {
		add(fullRR(dom, 16, 3600, charString(t)))
	}
	add(fullRR(dom, 6, 3600, soa)) // closing SOA terminates the AXFR

	binary.BigEndian.PutUint16(resp[6:8], n)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	resp = append(resp, body...)
	return [][]byte{resp}
}

// fakeHex returns a deterministic hex string for fabricated TXT material.
func (d *dnsHandler) fakeHex(seed string, n int) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, n)
	var x uint32 = 0x9e3779b9
	if d.id != nil {
		x ^= d.id.Uint32("dns-fake/" + seed)
	}
	for i := range out {
		x = x*1664525 + 1013904223
		out[i] = hexd[x>>28&0x0f]
	}
	return string(out)
}
