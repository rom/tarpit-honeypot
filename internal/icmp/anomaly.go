package icmp

import "encoding/binary"

// Anomalies inspects a received ICMPv4 echo request (the ICMP message,
// type byte onward) plus its IPv4-header context for abnormal-payload
// and fragmentation-abuse markers. These are the covert-channel /
// evasion / DoS patterns an ICMP responder should flag rather than
// silently answer:
//
//	icmp-oversize-payload      echo data far larger than any ping tool sends
//	icmp-payload-nonzero-entropy  echo data that isn't the usual sequential
//	                              /charset filler — a tunnel (icmptunnel,
//	                              ptunnel) packs real data here
//	icmp-frag-abuse            IP header says fragmented (MF set or non-zero
//	                              offset) on an ICMP echo — used for IDS evasion
//	                              and teardrop-style DoS
//	icmp-frag-tiny             a fragment with a suspiciously small offset
//	                              step (overlapping-fragment evasion)
//
// ipHeader is the 20+ byte IPv4 header; icmpMsg is the ICMP message.
func Anomalies(ipHeader, icmpMsg []byte) []string {
	var out []string

	// Fragmentation: flags+offset live in IPv4 header bytes 6-7.
	if len(ipHeader) >= 8 {
		flagsFrag := binary.BigEndian.Uint16(ipHeader[6:8])
		mf := flagsFrag&0x2000 != 0        // More Fragments
		offset := (flagsFrag & 0x1FFF) * 8 // fragment offset in bytes
		if mf || offset > 0 {
			out = append(out, "icmp-frag-abuse")
			// A non-first fragment with a tiny offset is the classic
			// overlapping-fragment IDS-evasion shape.
			if offset > 0 && offset < 16 {
				out = append(out, "icmp-frag-tiny")
			}
		}
	}

	// Echo payload starts after the 8-byte ICMP header.
	if len(icmpMsg) > 8 {
		payload := icmpMsg[8:]
		if len(payload) > 1024 {
			out = append(out, "icmp-oversize-payload")
		}
		if len(payload) >= 16 && !looksLikePingFiller(payload) {
			out = append(out, "icmp-payload-nonzero-entropy")
		}
	}
	return out
}

// looksLikePingFiller reports whether an echo payload matches the
// benign filler real ping tools send: Linux ping uses a timestamp
// followed by the sequential bytes 0x10,0x11,0x12...; Windows ping
// uses the repeating "abcdefghijklmnop..." alphabet. Anything else in
// a 16+ byte payload is treated as a possible covert channel.
//
// We test each pattern against the full payload AND against the
// payload with the first 16 bytes skipped (Linux's ping prepends a
// 16-byte timestamp region; Windows does not), accepting a match in
// either framing.
func looksLikePingFiller(p []byte) bool {
	if isPingPattern(p) {
		return true
	}
	if len(p) > 16 && isPingPattern(p[16:]) {
		return true
	}
	return false
}

func isPingPattern(body []byte) bool {
	if len(body) == 0 {
		return true
	}
	// Pattern A: sequential bytes (Linux ping data region).
	sequential := true
	for i := 1; i < len(body); i++ {
		if body[i] != body[i-1]+1 {
			sequential = false
			break
		}
	}
	if sequential {
		return true
	}
	// Pattern B: Windows ping alphabet "abcdefghijklmnopqrstuvwabcde...".
	alpha := true
	for i := 0; i < len(body); i++ {
		if body[i] != byte('a'+(i%23)) {
			alpha = false
			break
		}
	}
	if alpha {
		return true
	}
	// Pattern C: all-identical / all-zero filler (some tools).
	for i := 1; i < len(body); i++ {
		if body[i] != body[0] {
			return false
		}
	}
	return true
}
