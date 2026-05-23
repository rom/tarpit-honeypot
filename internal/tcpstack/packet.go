package tcpstack

import "encoding/binary"

// Segment is a parsed IPv4 + TCP packet. The userspace stack only speaks
// IPv4; IPv6 reconnaissance stays in tunnet's L3 responder. Parsing is
// deliberately lenient: a truncated or insane packet still yields a
// Segment (with the relevant *Short / *OK flags cleared) so the malformed
// classifier can describe exactly what was wrong rather than dropping it.
type Segment struct {
	// IPv4 header.
	SrcIP    [4]byte
	DstIP    [4]byte
	IHL      int // IP header length in bytes (0 = bogus / not extracted)
	TotalLen int // IP total-length field as received
	TTL      byte
	DF       bool   // Don't-Fragment
	MF       bool   // More-Fragments
	FragOff  uint16 // fragment offset (8-byte units)
	IPProto  byte

	// TCP header (valid only when IsTCP && !TCPShort && !BadDataOff).
	IsTCP      bool
	TCPShort   bool // fewer than 20 bytes of TCP header present
	BadDataOff bool // data-offset field lies about the header length
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	DataOff    int // TCP header length in bytes
	Flags      byte
	Window     uint16
	Urgent     uint16
	Options    []byte // raw TCP options
	Payload    []byte // application data

	// Parsed TCP timestamp option (so a SYN-ACK can echo TSecr).
	HasTS bool
	TSVal uint32
	TSEcr uint32

	// Checksum verification results (false = mismatch, used by Classify).
	IPChecksumOK  bool
	TCPChecksumOK bool
}

// ParseV4 extracts an IPv4 (and, when present, TCP) Segment from a raw L3
// packet as read off the TUN. The bool is false only when the buffer is
// not an IPv4 packet at all; everything past that is reported via Segment
// fields so callers can both respond and classify malformed traffic.
func ParseV4(pkt []byte) (*Segment, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil, false
	}
	s := &Segment{}
	s.TotalLen = int(binary.BigEndian.Uint16(pkt[2:4]))
	ff := binary.BigEndian.Uint16(pkt[6:8])
	s.DF = ff&0x4000 != 0
	s.MF = ff&0x2000 != 0
	s.FragOff = ff & 0x1fff
	s.TTL = pkt[8]
	s.IPProto = pkt[9]
	copy(s.SrcIP[:], pkt[12:16])
	copy(s.DstIP[:], pkt[16:20])

	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl > len(pkt) {
		return s, true // bogus header length; addresses only
	}
	s.IHL = ihl
	s.IPChecksumOK = ipChecksum(pkt[:ihl]) == 0

	// Trim any link padding / trailing bytes so the TCP checksum covers
	// exactly the IP payload the sender intended.
	end := len(pkt)
	if s.TotalLen >= ihl && s.TotalLen <= len(pkt) {
		end = s.TotalLen
	}
	if s.IPProto != 6 {
		return s, true
	}
	s.IsTCP = true
	tcp := pkt[ihl:end]
	if len(tcp) < 20 {
		s.TCPShort = true
		return s, true
	}
	s.SrcPort = binary.BigEndian.Uint16(tcp[0:2])
	s.DstPort = binary.BigEndian.Uint16(tcp[2:4])
	s.Seq = binary.BigEndian.Uint32(tcp[4:8])
	s.Ack = binary.BigEndian.Uint32(tcp[8:12])
	s.Flags = tcp[13]
	s.Window = binary.BigEndian.Uint16(tcp[14:16])
	s.Urgent = binary.BigEndian.Uint16(tcp[18:20])

	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || dataOff > len(tcp) {
		s.BadDataOff = true
		return s, true
	}
	s.DataOff = dataOff
	s.Options = tcp[20:dataOff]
	s.Payload = tcp[dataOff:]
	s.TCPChecksumOK = tcpChecksumV4(s.SrcIP[:], s.DstIP[:], tcp) == 0
	s.parseOptions()
	return s, true
}

// parseOptions walks the TCP option list far enough to recover the
// timestamp (the only option we need to echo). Malformed option framing
// just stops the walk — Classify reports the structural problem.
func (s *Segment) parseOptions() {
	o := s.Options
	for i := 0; i < len(o); {
		switch o[i] {
		case optEOL:
			return
		case optNOP:
			i++
		default:
			if i+1 >= len(o) {
				return
			}
			l := int(o[i+1])
			if l < 2 || i+l > len(o) {
				return
			}
			if o[i] == optTimestamp && l == 10 {
				s.HasTS = true
				s.TSVal = binary.BigEndian.Uint32(o[i+2 : i+6])
				s.TSEcr = binary.BigEndian.Uint32(o[i+6 : i+10])
			}
			i += l
		}
	}
}

// PayloadLen is the number of application bytes the segment carries; SYN
// and FIN each consume one sequence number in addition to any payload.
func (s *Segment) PayloadLen() int { return len(s.Payload) }

// out describes one outbound IPv4+TCP segment for buildV4. Options must
// already be padded to a 4-byte boundary (buildOptions guarantees this);
// non-SYN segments pass nil.
type out struct {
	src, dst         [4]byte
	srcPort, dstPort uint16
	seq, ack         uint32
	flags            byte
	window           uint16
	ttl              byte
	df               bool
	options          []byte
	payload          []byte
}

// buildV4 serializes a complete IPv4 + TCP segment (no IP options) with
// both checksums computed. It is the single packet-construction primitive
// the stack uses for SYN-ACK, ACK, data, FIN and RST replies.
func buildV4(o out) []byte {
	tcpHdr := 20 + len(o.options)
	total := 20 + tcpHdr + len(o.payload)
	b := make([]byte, total)

	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	if o.df {
		binary.BigEndian.PutUint16(b[6:8], 0x4000)
	}
	b[8] = o.ttl
	b[9] = 6 // TCP
	copy(b[12:16], o.src[:])
	copy(b[16:20], o.dst[:])
	binary.BigEndian.PutUint16(b[10:12], ipChecksum(b[:20]))

	t := b[20:]
	binary.BigEndian.PutUint16(t[0:2], o.srcPort)
	binary.BigEndian.PutUint16(t[2:4], o.dstPort)
	binary.BigEndian.PutUint32(t[4:8], o.seq)
	binary.BigEndian.PutUint32(t[8:12], o.ack)
	t[12] = byte(tcpHdr/4) << 4
	t[13] = o.flags
	binary.BigEndian.PutUint16(t[14:16], o.window)
	copy(t[20:], o.options)
	copy(t[20+len(o.options):], o.payload)
	binary.BigEndian.PutUint16(t[16:18], tcpChecksumV4(o.src[:], o.dst[:], t))
	return b
}

// ipChecksum is the standard ones-complement header checksum; it returns 0
// over a header that already carries a correct checksum.
func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpChecksumV4 sums the TCP pseudo-header plus the segment; it returns 0
// over a segment whose checksum field is already correct.
func tcpChecksumV4(src, dst, tcp []byte) uint16 {
	var sum uint32
	add := func(s []byte) {
		for i := 0; i+1 < len(s); i += 2 {
			sum += uint32(s[i])<<8 | uint32(s[i+1])
		}
		if len(s)%2 == 1 {
			sum += uint32(s[len(s)-1]) << 8
		}
	}
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	add(pseudo)
	add(tcp)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
