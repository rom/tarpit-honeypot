package sniffer

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// scanKind classifies a single TCP segment by its flag combination. The
// stealth kinds (NULL/FIN/Xmas) have no legitimate use and are scan
// probes on their own; SYN and ACK are normal in isolation and are only
// reported when one source sprays many distinct ports (volume).
type scanKind int

const (
	scanNone scanKind = iota
	scanNull          // no flags set                — nmap -sN
	scanFIN           // FIN only                     — nmap -sF
	scanXmas          // FIN+PSH+URG                  — nmap -sX
	scanSYN           // SYN without ACK              — nmap -sS (volume)
	scanACK           // ACK without SYN              — nmap -sA (volume)
)

func (k scanKind) ruleID() string {
	switch k {
	case scanNull:
		return "sniffer:tcp_null_scan"
	case scanFIN:
		return "sniffer:tcp_fin_scan"
	case scanXmas:
		return "sniffer:tcp_xmas_scan"
	case scanSYN:
		return "sniffer:tcp_syn_scan"
	case scanACK:
		return "sniffer:tcp_ack_scan"
	}
	return ""
}

func (k scanKind) stealth() bool {
	return k == scanNull || k == scanFIN || k == scanXmas
}

// TCP flag bits.
const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
	flagACK = 0x10
	flagURG = 0x20
)

// fmtTCPFlags renders the set TCP control bits as a stable comma list.
func fmtTCPFlags(f byte) string {
	bits := []struct {
		bit byte
		s   string
	}{
		{flagURG, "URG"}, {flagACK, "ACK"}, {flagPSH, "PSH"},
		{flagRST, "RST"}, {flagSYN, "SYN"}, {flagFIN, "FIN"},
	}
	out := ""
	for _, b := range bits {
		if f&b.bit != 0 {
			if out != "" {
				out += ","
			}
			out += b.s
		}
	}
	if out == "" {
		return "none"
	}
	return out
}

// classifyTCP maps the 6 low TCP control bits to a scanKind. CWR/ECE
// (the two high bits) are ignored so an ECN-capable variant of a scan
// still classifies.
func classifyTCP(flags byte) scanKind {
	switch flags & 0x3f {
	case 0x00:
		return scanNull
	case flagFIN:
		return scanFIN
	case flagFIN | flagPSH | flagURG:
		return scanXmas
	case flagSYN:
		return scanSYN
	case flagACK:
		return scanACK
	}
	return scanNone
}

// ipv4Info is the parsed result of one captured IPv4 frame.
type ipv4Info struct {
	srcIP      string
	proto      byte
	fragmented bool
	payload    []byte // L4 bytes (TCP/UDP/ICMP header onward)
}

// parseIPv4 parses an Ethernet frame carrying IPv4 and returns the L4
// payload plus whether the datagram is fragmented (MF set or non-zero
// offset). Returns ok=false for non-IPv4 / malformed frames.
func parseIPv4(frame []byte) (ipv4Info, bool) {
	var info ipv4Info
	if len(frame) < 14+20 {
		return info, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 { // EtherType IPv4
		return info, false
	}
	ip := frame[14:]
	if ip[0]>>4 != 4 {
		return info, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || ihl > len(ip) {
		return info, false
	}
	flagsFrag := binary.BigEndian.Uint16(ip[6:8])
	info.fragmented = flagsFrag&0x2000 != 0 || flagsFrag&0x1fff != 0
	info.proto = ip[9]
	info.srcIP = net.IP(ip[12:16]).String()
	info.payload = ip[ihl:]
	return info, true
}

// parseTCP pulls the destination port + flag byte out of a TCP segment.
func parseTCP(l4 []byte) (dstPort uint16, flags byte, ok bool) {
	if len(l4) < 14 { // need through the flags byte at offset 13
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(l4[2:4]), l4[13], true
}

// scanTracker aggregates per-source scan probes over a sliding window and
// decides when to emit. Stealth probes fire at a low distinct-port count
// (they are malicious on sight); SYN/ACK fire only at the volume
// threshold so a single normal connection never trips them. One event
// per (source, kind) per window — the same dedup discipline as the ARP
// scan detector.
type scanTracker struct {
	window        time.Duration
	volumeThresh  int
	stealthThresh int

	mu sync.Mutex
	st map[string]map[scanKind]*kindState
}

type kindState struct {
	since     time.Time
	ports     map[uint16]struct{}
	lastFired time.Time
}

func newScanTracker(window time.Duration, volumeThresh, stealthThresh int) *scanTracker {
	if window <= 0 {
		window = 30 * time.Second
	}
	if volumeThresh <= 0 {
		volumeThresh = 16
	}
	if stealthThresh <= 0 {
		stealthThresh = 3
	}
	return &scanTracker{
		window:        window,
		volumeThresh:  volumeThresh,
		stealthThresh: stealthThresh,
		st:            map[string]map[scanKind]*kindState{},
	}
}

// observe records one probe and reports (distinctPorts, fire). fire is
// true exactly once per (source, kind) per window, when the distinct-port
// count first reaches the kind's threshold.
func (t *scanTracker) observe(src string, port uint16, kind scanKind, now time.Time) (int, bool) {
	if kind == scanNone {
		return 0, false
	}
	thresh := t.volumeThresh
	if kind.stealth() {
		thresh = t.stealthThresh
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	byKind := t.st[src]
	if byKind == nil {
		byKind = map[scanKind]*kindState{}
		t.st[src] = byKind
	}
	ks := byKind[kind]
	if ks == nil || now.Sub(ks.since) > t.window {
		ks = &kindState{since: now, ports: map[uint16]struct{}{}}
		byKind[kind] = ks
	}
	ks.ports[port] = struct{}{}
	n := len(ks.ports)
	if n < thresh {
		return n, false
	}
	if !ks.lastFired.IsZero() && now.Sub(ks.lastFired) < t.window {
		return n, false
	}
	ks.lastFired = now
	return n, true
}

// gc drops source state whose only window has expired, keeping the map
// bounded under sustained scanning from many sources.
func (t *scanTracker) gc(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for src, byKind := range t.st {
		for k, ks := range byKind {
			if now.Sub(ks.since) > t.window && now.Sub(ks.lastFired) > t.window {
				delete(byKind, k)
			}
		}
		if len(byKind) == 0 {
			delete(t.st, src)
		}
	}
}

// rateLimiter fires at most once per key per window — used for
// fragmentation alerts, where the signal is "this source sent fragmented
// probes" rather than a per-port count.
type rateLimiter struct {
	window time.Duration
	mu     sync.Mutex
	last   map[string]time.Time
}

func newRateLimiter(window time.Duration) *rateLimiter {
	if window <= 0 {
		window = 30 * time.Second
	}
	return &rateLimiter{window: window, last: map[string]time.Time{}}
}

func (r *rateLimiter) allow(key string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.last[key]; ok && now.Sub(t) < r.window {
		return false
	}
	r.last[key] = now
	return true
}
