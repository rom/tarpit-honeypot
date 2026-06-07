package handler

// SNMP structural inspection shared by the udp/161 agent (snmp.go) and the
// udp/162 trap receiver (snmptrap.go). It tolerantly walks the BER/ASN.1 of an
// SNMP datagram — v1 (version 0), v2c (1) and v3 (3) — extracting the version,
// community, PDU type, v1 trap fields and varbind OIDs, while flagging the
// malformed / oversized / anomalous structures attackers use to fingerprint a
// trap host or to drive the SNMP-subsystem memory-safety bugs in the Cisco IOS
// / IOS XE RCE class. Detection only: we never feed any of this into a real
// SNMP stack.

// PDU type tags (context-specific constructed).
const (
	pduGetRequest  = 0xA0
	pduGetResponse = 0xA2
	pduSetRequest  = 0xA3
	pduV1Trap      = 0xA4
	pduGetBulk     = 0xA5
	pduInform      = 0xA6
	pduV2Trap      = 0xA7
)

// Structural limits beyond which a value is an exploit/fuzz indicator rather
// than anything a real agent or manager emits. Real OIDs sit well under 32
// arcs; trap varbind lists are a handful, not hundreds.
const (
	snmpMaxOIDArcs     = 32
	snmpMaxOIDBytes    = 128
	snmpMaxVarbinds    = 64
	snmpOversizedBytes = 4096 // a trap/inform larger than this is abnormal
)

type snmpInspection struct {
	Version       int    // 0=v1, 1=v2c, 3=v3, -1=unknown/unparseable
	Community     string // v1/v2c only
	V3User        string // v3 msgUserName
	PDUType       byte   // 0 if not reached
	IsInform      bool
	IsTrap        bool
	EnterpriseOID string // v1 trap enterprise
	GenericTrap   int    // v1 trap generic-trap (-1 if n/a)
	SpecificTrap  int    // v1 trap specific-trap
	VarbindCount  int
	VarbindOIDs   []string
	PDUTagOffset  int      // absolute offset of the PDU type tag (-1 if not found)
	Anomalies     []string // structural anomaly markers (no "snmp-" caller prefix needed)
	CVEs          []string // Cisco SNMP RCE-class CVE ids matched
}

// applySNMPInspect merges a tolerant inspection's structural anomaly markers
// and Cisco IOS / IOS XE SNMP RCE-class CVE attributions into a Result. Shared
// by the udp/161 agent and the udp/162 trap receiver so both surface the same
// malformed / oversized / overflow signals.
func applySNMPInspect(res *Result, in snmpInspection) {
	for _, a := range in.Anomalies {
		flagAnomaly(res, a)
	}
	for _, id := range in.CVEs {
		flagAnomaly(res, "cve:"+id)
	}
	if len(in.CVEs) > 0 {
		flagAnomaly(res, "cisco-snmp-rce-attempt")
	}
}

// berField parses the TLV at b[off:], returning the tag, the ABSOLUTE content
// offset + length, and the next TLV offset. ok=false only on a header that
// can't be read; a declared length that runs past the buffer still returns
// ok=true (with next>len(b)) so the caller can flag it as oversized/truncated.
func berField(b []byte, off int) (tag byte, cOff, cLen, next int, ok bool) {
	if off < 0 || off+2 > len(b) {
		return 0, 0, 0, 0, false
	}
	tag = b[off]
	l := int(b[off+1])
	p := off + 2
	if l&0x80 != 0 {
		nb := l & 0x7f
		if nb == 0 || nb > 4 || p+nb > len(b) {
			return 0, 0, 0, 0, false
		}
		l = 0
		for i := 0; i < nb; i++ {
			l = l<<8 | int(b[p+i])
		}
		p += nb
	}
	if l < 0 {
		return 0, 0, 0, 0, false
	}
	return tag, p, l, p + l, true
}

// decodeOID renders OBJECT IDENTIFIER content bytes as a dotted string and
// returns the arc count. Tolerant of truncation (returns what it decoded).
func decodeOID(b []byte) (string, int) {
	if len(b) == 0 {
		return "", 0
	}
	var arcs []int
	// First byte encodes the first two arcs: 40*x + y.
	first := int(b[0])
	arcs = append(arcs, first/40, first%40)
	var cur int
	for i := 1; i < len(b); i++ {
		cur = cur<<7 | int(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			arcs = append(arcs, cur)
			cur = 0
		}
		if len(arcs) > 4096 { // hard stop on a pathological/fuzzed OID
			break
		}
	}
	out := make([]byte, 0, len(arcs)*3)
	for i, a := range arcs {
		if i > 0 {
			out = append(out, '.')
		}
		out = appendInt(out, a)
	}
	return string(out), len(arcs)
}

func appendInt(b []byte, n int) []byte {
	if n == 0 {
		return append(b, '0')
	}
	if n < 0 {
		b = append(b, '-')
		n = -n
	}
	var tmp [20]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
	}
	return append(b, tmp[i:]...)
}

// inspectSNMP runs the tolerant walk. It never panics on attacker input.
func inspectSNMP(payload []byte) snmpInspection {
	in := snmpInspection{Version: -1, GenericTrap: -1, PDUTagOffset: -1}
	addAnom := func(m string) {
		for _, x := range in.Anomalies {
			if x == m {
				return
			}
		}
		in.Anomalies = append(in.Anomalies, m)
	}

	if len(payload) > snmpOversizedBytes {
		addAnom("snmp-oversized-packet")
	}
	// Outer SEQUENCE.
	tag, cOff, cLen, _, ok := berField(payload, 0)
	if !ok || tag != 0x30 {
		addAnom("snmp-malformed-asn1")
		return in
	}
	if cOff+cLen > len(payload) {
		addAnom("snmp-oversized-pdu") // declared message longer than the datagram
	}
	end := cOff + cLen
	if end > len(payload) {
		end = len(payload)
	}

	// version INTEGER
	off := cOff
	vtag, vOff, vLen, vnext, ok := berField(payload, off)
	if !ok || vtag != 0x02 {
		addAnom("snmp-malformed-asn1")
		return in
	}
	in.Version = beInt(payload, vOff, vLen)
	switch in.Version {
	case 0, 1, 3: // v1, v2c, v3
	default:
		addAnom("snmp-nonstandard-version")
	}
	off = vnext

	if in.Version == 3 {
		// v3 framing differs; pull the user name for capture and stop (the
		// structural overflow checks above already ran on the envelope).
		in.V3User = snmpV3UserName(payload)
		return in
	}

	// community OCTET STRING (v1/v2c)
	ctag, coff, clen, cnext, ok := berField(payload, off)
	if !ok || ctag != 0x04 {
		addAnom("snmp-malformed-asn1")
		return in
	}
	if coff+clen <= len(payload) {
		in.Community = string(payload[coff : coff+clen])
	}
	off = cnext

	// PDU
	ptag, pOff, pLen, _, ok := berField(payload, off)
	if !ok {
		addAnom("snmp-malformed-asn1")
		return in
	}
	in.PDUType = ptag
	in.PDUTagOffset = off
	if pOff+pLen > len(payload) {
		addAnom("snmp-oversized-pdu")
	}
	switch ptag {
	case pduV1Trap:
		in.IsTrap = true
		inspectV1Trap(payload, pOff, minInt(pOff+pLen, len(payload)), &in, addAnom)
	case pduV2Trap:
		in.IsTrap = true
		inspectV2PDU(payload, pOff, minInt(pOff+pLen, len(payload)), &in, addAnom)
	case pduInform:
		in.IsInform = true
		inspectV2PDU(payload, pOff, minInt(pOff+pLen, len(payload)), &in, addAnom)
	case pduGetRequest, pduGetResponse, pduSetRequest, pduGetBulk:
		// A request/response PDU on the trap port is unexpected (scan / exploit
		// probe); still inspect its varbinds for overflow OIDs.
		addAnom("snmp-unexpected-pdu")
		inspectV2PDU(payload, pOff, minInt(pOff+pLen, len(payload)), &in, addAnom)
	default:
		addAnom("snmp-malformed-asn1")
	}

	in.CVEs = ciscoSNMPRCEMatch(in.Anomalies)
	return in
}

// inspectV1Trap walks { enterprise OID, agent-addr, generic, specific,
// timestamp, varbinds } and flags an oversized / off-tree enterprise OID.
func inspectV1Trap(b []byte, off, end int, in *snmpInspection, addAnom func(string)) {
	// enterprise OID
	tag, cOff, cLen, next, ok := berField(b, off)
	if ok && tag == 0x06 && cOff+cLen <= len(b) {
		oid, arcs := decodeOID(b[cOff : cOff+cLen])
		in.EnterpriseOID = oid
		if arcs > snmpMaxOIDArcs || cLen > snmpMaxOIDBytes || !standardOIDPrefix(b[cOff:cOff+cLen]) {
			addAnom("snmp-randomized-enterprise-oid")
		}
		off = next
	} else if !ok {
		addAnom("snmp-malformed-asn1")
		return
	}
	// agent-addr (0x40), generic INTEGER, specific INTEGER, timestamp — skip to
	// the trailing varbind SEQUENCE, reading the two trap integers on the way.
	ints := 0
	for off < end {
		t, o, l, n, ok := berField(b, off)
		if !ok {
			addAnom("snmp-malformed-asn1")
			return
		}
		switch {
		case t == 0x02 && ints == 0:
			in.GenericTrap = beInt(b, o, l)
			ints++
		case t == 0x02 && ints == 1:
			in.SpecificTrap = beInt(b, o, l)
			ints++
		case t == 0x30: // varbind list
			inspectVarbinds(b, o, minInt(o+l, len(b)), in, addAnom)
			return
		}
		off = n
	}
}

// inspectV2PDU walks { request-id, error-status, error-index, varbinds }.
func inspectV2PDU(b []byte, off, end int, in *snmpInspection, addAnom func(string)) {
	for i := 0; off < end; i++ {
		t, o, l, n, ok := berField(b, off)
		if !ok {
			addAnom("snmp-malformed-asn1")
			return
		}
		if t == 0x30 { // the varbind list is the trailing SEQUENCE
			inspectVarbinds(b, o, minInt(o+l, len(b)), in, addAnom)
			return
		}
		off = n
	}
}

// inspectVarbinds counts the varbinds and flags overflow / off-tree OIDs.
func inspectVarbinds(b []byte, off, end int, in *snmpInspection, addAnom func(string)) {
	for off < end {
		t, o, _, n, ok := berField(b, off)
		if !ok {
			addAnom("snmp-malformed-asn1")
			return
		}
		if t != 0x30 { // each varbind is a SEQUENCE { name OID, value }
			off = n
			continue
		}
		in.VarbindCount++
		if in.VarbindCount > snmpMaxVarbinds {
			addAnom("snmp-varbind-flood")
		}
		// First field of the varbind is the name OID.
		ot, oo, ol, _, ok := berField(b, o)
		if ok && ot == 0x06 && oo+ol <= len(b) {
			oid, arcs := decodeOID(b[oo : oo+ol])
			if len(in.VarbindOIDs) < 16 {
				in.VarbindOIDs = append(in.VarbindOIDs, oid)
			}
			if arcs > snmpMaxOIDArcs || ol > snmpMaxOIDBytes {
				addAnom("snmp-oversized-oid")
			}
		}
		off = n
	}
}

// standardOIDPrefix reports whether OID content starts at the iso.org.dod.internet
// (1.3.6.1) subtree — the prefix every legitimate enterprise/MIB OID shares. A
// trap enterprise OID outside it is a fuzz / randomized-OID tell.
func standardOIDPrefix(b []byte) bool {
	// 1.3.6.1 encodes as: 0x2b (=40*1+3), 0x06, 0x01.
	return len(b) >= 3 && b[0] == 0x2b && b[1] == 0x06 && b[2] == 0x01
}

// beInt reads a big-endian (signed) INTEGER of up to 4 bytes; clamps otherwise.
func beInt(b []byte, off, l int) int {
	if off < 0 || l <= 0 || off+l > len(b) || l > 4 {
		return 0
	}
	n := 0
	for i := 0; i < l; i++ {
		n = n<<8 | int(b[off+i])
	}
	return n
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ciscoSNMPRCEMatch attributes the Cisco IOS / IOS XE SNMP memory-safety RCE
// class when the datagram carries a clear overflow primitive (an oversized /
// randomized OID, or a PDU/message whose declared length runs past the packet).
// These are the observable triggers shared by the SNMP-subsystem buffer
// overflows; precise per-CVE selectors are layered on top by the catalog.
func ciscoSNMPRCEMatch(anoms []string) []string {
	overflow := false
	for _, a := range anoms {
		switch a {
		case "snmp-oversized-oid", "snmp-randomized-enterprise-oid", "snmp-oversized-pdu":
			overflow = true
		}
	}
	if !overflow {
		return nil
	}
	// The two SNMP-subsystem buffer-overflow RCEs in Cisco IOS / IOS XE whose
	// trigger is exactly an over-long / malformed OID in a crafted SNMP packet.
	return []string{"CVE-2017-6736", "CVE-2025-20352"}
}
