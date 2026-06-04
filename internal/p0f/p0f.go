// Package p0f is a passive TCP/IP OS fingerprinter: it builds a p0f-v3-style
// signature from an observed TCP SYN (initial TTL, IP options length, MSS,
// window size + scale, TCP option layout, quirks) and matches it against a
// signature database to name the source OS / stack. It refines the coarse
// TTL-bucket os_guess the sniffer produces today.
//
// The signature grammar and database format follow p0f v3
// (https://lcamtuf.coredump.cx/p0f3/) closely enough to load real p0f.fp
// `tcp` sections, and a curated subset is embedded so it works with no config.
// Pure Go, no external deps.
package p0f

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// Signature is an observed TCP SYN fingerprint.
type Signature struct {
	Version int      // 4 or 6
	ITTL    int      // bucketed initial TTL (64/128/255)
	OptLen  int      // IP options length (usually 0)
	MSS     int      // TCP MSS option value, 0 if absent
	WSize   int      // TCP window size
	WScale  int      // window scale, -1 if absent
	Layout  []string // TCP option layout: mss, sok, ts, nop, ws, eol+N
	Quirks  []string // df, id+, id-, ...
	PClass  int      // payload class: 0 = no payload
}

// FromSYN builds a Signature from a raw IPv4/IPv6 SYN: the bucketed initial
// TTL, whether DF is set, the IP ID (for the id+ quirk), the IP options
// length, and the raw TCP segment. Returns ok=false if it isn't a parseable
// SYN. payloadLen is the TCP payload byte count (0 for a normal SYN).
func FromSYN(version int, ttl byte, df bool, ipID uint16, ipOptLen int, tcp []byte, payloadLen int) (Signature, bool) {
	if len(tcp) < 20 {
		return Signature{}, false
	}
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || dataOff > len(tcp) {
		return Signature{}, false
	}
	s := Signature{
		Version: version,
		ITTL:    bucketTTL(ttl),
		OptLen:  ipOptLen,
		WSize:   int(binary.BigEndian.Uint16(tcp[14:16])),
		WScale:  -1,
	}
	if payloadLen > 0 {
		s.PClass = 1
	}
	// Quirks we can derive cheaply.
	if df {
		s.Quirks = append(s.Quirks, "df")
		if ipID != 0 {
			s.Quirks = append(s.Quirks, "id+")
		}
	}
	// Parse TCP options for layout + MSS + window scale.
	opts := tcp[20:dataOff]
	for i := 0; i < len(opts); {
		kind := opts[i]
		switch kind {
		case 0: // EOL
			s.Layout = append(s.Layout, "eol+"+strconv.Itoa(len(opts)-i-1))
			i = len(opts)
		case 1: // NOP
			s.Layout = append(s.Layout, "nop")
			i++
		default:
			if i+1 >= len(opts) {
				i = len(opts)
				break
			}
			optLen := int(opts[i+1])
			if optLen < 2 || i+optLen > len(opts) {
				i = len(opts)
				break
			}
			switch kind {
			case 2: // MSS
				if optLen == 4 {
					s.MSS = int(binary.BigEndian.Uint16(opts[i+2 : i+4]))
				}
				s.Layout = append(s.Layout, "mss")
			case 3: // Window scale
				if optLen == 3 {
					s.WScale = int(opts[i+2])
				}
				s.Layout = append(s.Layout, "ws")
			case 4: // SACK permitted
				s.Layout = append(s.Layout, "sok")
			case 8: // Timestamps
				s.Layout = append(s.Layout, "ts")
			default:
				s.Layout = append(s.Layout, "?"+strconv.Itoa(int(kind)))
			}
			i += optLen
		}
	}
	return s, true
}

// bucketTTL maps an observed TTL to the nearest stack-characteristic initial
// value at or above it (the p0f convention).
func bucketTTL(ttl byte) int {
	switch {
	case ttl == 0:
		return 0
	case ttl <= 32:
		return 32
	case ttl <= 64:
		return 64
	case ttl <= 128:
		return 128
	default:
		return 255
	}
}

// String renders the signature in p0f canonical form
// (ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass).
func (s Signature) String() string {
	ws := strconv.Itoa(s.WScale)
	if s.WScale < 0 {
		ws = "*"
	}
	mss := "*"
	if s.MSS > 0 {
		mss = strconv.Itoa(s.MSS)
	}
	pc := "0"
	if s.PClass != 0 {
		pc = "+"
	}
	return strings.Join([]string{
		strconv.Itoa(s.Version), strconv.Itoa(s.ITTL), strconv.Itoa(s.OptLen),
		mss, strconv.Itoa(s.WSize) + "," + ws,
		strings.Join(s.Layout, ","), strings.Join(s.Quirks, ","), pc,
	}, ":")
}
