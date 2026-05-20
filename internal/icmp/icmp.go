// Package icmp builds ICMPv4 and ICMPv6 messages used by the honeynet
// responder to emulate router hops, segmentation boundaries, and host
// behaviors. Everything here is pure byte-assembly with no sockets, so
// it builds + tests on every platform; the raw-socket delivery lives
// in the (Linux-only) honeynet responder.
//
// Supported ICMPv4 types:
//
//	0  Echo Reply              8  Echo Request
//	3  Destination Unreachable (codes 0/1/3/4/13 + 4 = Frag Needed)
//	5  Redirect
//	11 Time Exceeded           12 Parameter Problem
//	13 Timestamp Request       14 Timestamp Reply
//	17 Address Mask Request    18 Address Mask Reply
//
// Supported ICMPv6 types:
//
//	128 Echo Request           129 Echo Reply
//	133 Router Solicitation    134 Router Advertisement
//	135 Neighbor Solicitation  136 Neighbor Advertisement
//	1   Destination Unreachable 3 Time Exceeded
//	2   Packet Too Big          4 Parameter Problem
package icmp

import "encoding/binary"

// ICMPv4 type constants.
const (
	V4EchoReply       = 0
	V4DestUnreachable = 3
	V4Redirect        = 5
	V4EchoRequest     = 8
	V4TimeExceeded    = 11
	V4ParamProblem    = 12
	V4Timestamp       = 13
	V4TimestampReply  = 14
	V4AddrMask        = 17
	V4AddrMaskReply   = 18
)

// ICMPv4 Destination-Unreachable codes (the subset the user asked for
// plus the must-have Fragmentation Needed).
const (
	CodeNetUnreachable      = 0  // network unreachable
	CodeHostUnreachable     = 1  // host unreachable
	CodePortUnreachable     = 3  // port unreachable
	CodeFragNeeded          = 4  // fragmentation needed and DF set
	CodeCommAdminProhibited = 13 // communication administratively prohibited
)

// ICMPv6 type constants.
const (
	V6DestUnreachable = 1
	V6PacketTooBig    = 2
	V6TimeExceeded    = 3
	V6ParamProblem    = 4
	V6EchoRequest     = 128
	V6EchoReply       = 129
	V6RouterSol       = 133
	V6RouterAdv       = 134
	V6NeighborSol     = 135
	V6NeighborAdv     = 136
)

// checksum is the 16-bit one's-complement Internet checksum.
func checksum(b []byte) uint16 {
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

func putChecksum(msg []byte) {
	msg[2], msg[3] = 0, 0
	cs := checksum(msg)
	msg[2] = byte(cs >> 8)
	msg[3] = byte(cs)
}

// EchoReplyV4 turns an echo-request ICMP body into an echo reply: same
// identifier / sequence / payload, type set to 0, checksum recomputed.
// origICMP must be the full ICMP message (type byte onward).
func EchoReplyV4(origICMP []byte) []byte {
	if len(origICMP) < 8 {
		return nil
	}
	msg := append([]byte(nil), origICMP...)
	msg[0] = V4EchoReply
	msg[1] = 0
	putChecksum(msg)
	return msg
}

// EchoRequestV4 builds an echo request with the given id/seq/payload.
func EchoRequestV4(id, seq uint16, payload []byte) []byte {
	msg := make([]byte, 8+len(payload))
	msg[0] = V4EchoRequest
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	copy(msg[8:], payload)
	putChecksum(msg)
	return msg
}

// errorBodyV4 builds a type-3/5/11/12-shaped ICMPv4 message: 4-byte
// header fields + the unused/MTU/pointer/gateway word + the original
// IP header and first 8 bytes of the offending datagram (per RFC 792).
// The `word` argument is the 4 bytes after type/code/checksum (its
// meaning depends on type: 0 for unreachable/time-exceeded, MTU for
// frag-needed, gateway IP for redirect, pointer<<24 for param problem).
func errorBodyV4(typ, code byte, word uint32, origIPHeaderPlus8 []byte) []byte {
	msg := make([]byte, 8+len(origIPHeaderPlus8))
	msg[0] = typ
	msg[1] = code
	binary.BigEndian.PutUint32(msg[4:8], word)
	copy(msg[8:], origIPHeaderPlus8)
	putChecksum(msg)
	return msg
}

// DestUnreachableV4 builds a Destination Unreachable (type 3) with the
// given code. origIPHeaderPlus8 is the IP header + first 8 bytes of the
// datagram that triggered the error.
func DestUnreachableV4(code byte, origIPHeaderPlus8 []byte) []byte {
	return errorBodyV4(V4DestUnreachable, code, 0, origIPHeaderPlus8)
}

// FragNeededV4 builds the Destination Unreachable / Fragmentation
// Needed (type 3 code 4) used in Path-MTU discovery; nextHopMTU goes in
// the low 16 bits of the unused word per RFC 1191.
func FragNeededV4(nextHopMTU uint16, origIPHeaderPlus8 []byte) []byte {
	return errorBodyV4(V4DestUnreachable, CodeFragNeeded, uint32(nextHopMTU), origIPHeaderPlus8)
}

// TimeExceededV4 builds a Time Exceeded (type 11). code 0 = TTL
// exceeded in transit (the traceroute hop signal); code 1 = fragment
// reassembly time exceeded.
func TimeExceededV4(code byte, origIPHeaderPlus8 []byte) []byte {
	return errorBodyV4(V4TimeExceeded, code, 0, origIPHeaderPlus8)
}

// ParamProblemV4 builds a Parameter Problem (type 12). pointer is the
// octet offset of the bad field in the original header.
func ParamProblemV4(pointer byte, origIPHeaderPlus8 []byte) []byte {
	return errorBodyV4(V4ParamProblem, 0, uint32(pointer)<<24, origIPHeaderPlus8)
}

// RedirectV4 builds a Redirect (type 5). code selects the redirect
// class (0 net, 1 host, 2 ToS+net, 3 ToS+host); gateway is the IP the
// sender should use instead.
func RedirectV4(code byte, gateway [4]byte, origIPHeaderPlus8 []byte) []byte {
	word := binary.BigEndian.Uint32(gateway[:])
	return errorBodyV4(V4Redirect, code, word, origIPHeaderPlus8)
}

// TimestampReplyV4 builds a Timestamp Reply (type 14) answering a
// Timestamp Request. The request carries id/seq + originate timestamp;
// we echo those and fill receive + transmit with the supplied ms-since-
// midnight-UTC value (RFC 792 timestamp format).
func TimestampReplyV4(req []byte, msSinceMidnightUTC uint32) []byte {
	if len(req) < 20 {
		return nil
	}
	msg := make([]byte, 20)
	msg[0] = V4TimestampReply
	copy(msg[4:8], req[4:8])                                   // id + seq
	copy(msg[8:12], req[8:12])                                 // originate timestamp (echoed)
	binary.BigEndian.PutUint32(msg[12:16], msSinceMidnightUTC) // receive
	binary.BigEndian.PutUint32(msg[16:20], msSinceMidnightUTC) // transmit
	putChecksum(msg)
	return msg
}

// AddrMaskReplyV4 builds an Address Mask Reply (type 18) answering an
// Address Mask Request. mask is the advertised subnet mask.
func AddrMaskReplyV4(req []byte, mask [4]byte) []byte {
	if len(req) < 8 {
		return nil
	}
	msg := make([]byte, 12)
	msg[0] = V4AddrMaskReply
	copy(msg[4:8], req[4:8]) // id + seq
	copy(msg[8:12], mask[:])
	putChecksum(msg)
	return msg
}

// ---- ICMPv6 ----
//
// ICMPv6 checksums cover a pseudo-header (src+dst+length+next-header).
// Build* functions here produce the message body with a zero checksum;
// callers that need a valid checksum supply the pseudo-header via
// ChecksumV6.

// EchoReplyV6 turns an ICMPv6 echo request (type 128) into an echo
// reply (type 129). Checksum is left zero — set it with ChecksumV6
// once the pseudo-header addresses are known.
func EchoReplyV6(origICMP []byte) []byte {
	if len(origICMP) < 8 {
		return nil
	}
	msg := append([]byte(nil), origICMP...)
	msg[0] = V6EchoReply
	msg[1] = 0
	msg[2], msg[3] = 0, 0
	return msg
}

// NeighborAdvertV6 builds a Neighbor Advertisement (type 136) answering
// a Neighbor Solicitation for targetIP, advertising targetMAC as the
// link-layer address. flags is the R/S/O bitfield (typically 0x60 =
// Solicited+Override). Checksum left zero for ChecksumV6.
func NeighborAdvertV6(targetIP [16]byte, targetMAC [6]byte, flags byte) []byte {
	// 4 (header) + 4 (flags word) + 16 (target) + 8 (target-LL option).
	msg := make([]byte, 4+4+16+8)
	msg[0] = V6NeighborAdv
	msg[4] = flags
	copy(msg[8:24], targetIP[:])
	// Target Link-Layer Address option: type 2, length 1 (8 bytes).
	msg[24] = 2
	msg[25] = 1
	copy(msg[26:32], targetMAC[:])
	return msg
}

// RouterAdvertV6 builds a minimal Router Advertisement (type 134) with
// the given hop limit, router lifetime, and source link-layer address
// option. Used to make a fake router appear on the segment. Checksum
// left zero for ChecksumV6.
func RouterAdvertV6(hopLimit byte, routerLifetime uint16, srcMAC [6]byte) []byte {
	// 4 (header) + 4 (curhop/flags/lifetime) + 4 (reachable) + 4 (retrans)
	// + 8 (source-LL option).
	msg := make([]byte, 4+4+4+4+8)
	msg[0] = V6RouterAdv
	msg[4] = hopLimit
	binary.BigEndian.PutUint16(msg[6:8], routerLifetime)
	// Source Link-Layer Address option: type 1, length 1.
	off := 16
	msg[off] = 1
	msg[off+1] = 1
	copy(msg[off+2:off+8], srcMAC[:])
	return msg
}

// EchoRequestV6 builds an ICMPv6 echo request (type 128).
func EchoRequestV6(id, seq uint16, payload []byte) []byte {
	msg := make([]byte, 8+len(payload))
	msg[0] = V6EchoRequest
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	copy(msg[8:], payload)
	return msg
}

// ChecksumV6 computes + writes the ICMPv6 checksum into msg[2:4] using
// the IPv6 pseudo-header (src, dst, ICMPv6 length, next-header=58).
func ChecksumV6(msg []byte, src, dst [16]byte) {
	if len(msg) < 4 {
		return
	}
	msg[2], msg[3] = 0, 0
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src[:])
	add(dst[:])
	var lenAndNH [8]byte
	binary.BigEndian.PutUint32(lenAndNH[0:4], uint32(len(msg)))
	lenAndNH[7] = 58 // next header = ICMPv6
	add(lenAndNH[:])
	add(msg)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	cs := ^uint16(sum)
	msg[2] = byte(cs >> 8)
	msg[3] = byte(cs)
}

// Valid reports whether an ICMP message's checksum is correct (ICMPv4
// only; ICMPv6 needs the pseudo-header). Used in tests.
func Valid(msg []byte) bool {
	return len(msg) >= 4 && checksum(msg) == 0
}
