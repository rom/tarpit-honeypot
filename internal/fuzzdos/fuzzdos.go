// Package fuzzdos detects and classifies fuzzing and denial-of-service
// activity from the signals a connection-layer honeypot can observe. It
// complements the AF_PACKET sniffer (which classifies wire-level SYN/NULL/
// Xmas floods it never lets establish) by working on the bytes and cadence
// of connections that DO reach a handler. Two halves:
//
//  1. Per-payload classification (stateless): does this request look like
//     a fuzzing payload, and of what kind? ClassifyPayload inspects byte
//     structure — Shannon entropy, printable ratio, long single-byte runs
//     (buffer-overflow "AAAA…"), null floods, format-string specifiers,
//     and gross oversize — and labels the technique. Handlers / the sensor
//     call it per connection; a positive verdict is stamped as a
//     fuzzing-<technique> anomaly so the protocol_violation correlator and
//     downstream SIEM see it too.
//
//  2. Per-source classification (stateful): a Tracker accumulates each
//     source's connection rate, cumulative bytes, per-port concentration,
//     and malformed-payload count, then labels the denial-of-service type
//     (connection-flood / app-flood / volumetric / malformed-flood) and a
//     sustained fuzzing campaign (with its dominant technique). The sensor
//     feeds every listener event in and emits attack:dos / attack:fuzzing
//     when a source crosses a threshold.
//
// Thresholds are deliberately conservative and per-source state ages out
// per window, so a legitimate burst doesn't trip a false flood.
package fuzzdos

import (
	"bytes"
	"fmt"
	"math"
)

// Verdict is the stateless per-payload classification.
type Verdict struct {
	// Fuzzing is true when the payload's structure matches a fuzzing
	// technique rather than a well-formed request.
	Fuzzing bool
	// Technique names the matched fuzzing class: "buffer-overflow",
	// "format-string", "null-flood", "oversize", "high-entropy", or
	// "binary-garbage". Empty when Fuzzing is false.
	Technique string
	// Entropy is the payload's Shannon entropy in bits/byte (0..8).
	Entropy float64
	// Printable is the fraction of bytes that are printable/whitespace ASCII.
	Printable float64
	// Size is len(payload).
	Size int
	// Detail is a short human note about what matched (e.g. the run length).
	Detail string
}

// Classification thresholds. Tuned to flag deliberate fuzzing while
// leaving well-formed (even large) protocol traffic alone.
const (
	minClassifySize = 64    // below this, structure stats are too noisy to judge
	bufOverflowRun  = 512   // a run of one (non-null) byte this long = overflow filler
	nullFloodRatio  = 0.5   // >= half null bytes = null flood
	oversizeText    = 16384 // a text-protocol request larger than this is abusive
	oversizeBinary  = 65536 // a binary-protocol request larger than this is abusive
	highEntropyText = 7.2   // near-random bytes on a text protocol = generation fuzzing
	binaryGarbage   = 0.30  // printable ratio below this on a text protocol = mutation/garbage
	fmtSpecifiers   = 8     // this many %x/%s/%p/%d specifiers = format-string fuzzing
)

// textProtocols are the line/text-oriented handlers where low printable
// ratio or high entropy is itself anomalous (binary protocols look that
// way normally, so we don't entropy-judge them).
var textProtocols = map[string]bool{
	"http": true, "https": true, "ftp": true, "ftp_files": true,
	"smtp": true, "smtp_recv": true, "telnet": true, "pop3": true,
	"imap": true, "sip": true, "irc": true, "finger": true, "whois": true,
	"redis": true, "memcached": true, "lpd": true, "ident": true,
	"xmpp": true, "rtsp": true,
}

// ClassifyPayload inspects the bytes a client sent and returns whether they
// look like a fuzzing payload, and of what kind. An empty payload (a bare
// connect) is never fuzzing — that's the scan analyzer's domain.
func ClassifyPayload(payload []byte, handler string) Verdict {
	v := Verdict{Size: len(payload)}
	if len(payload) == 0 {
		return v
	}
	v.Entropy = shannon(payload)
	v.Printable = printableRatio(payload)
	text := textProtocols[handler]

	// Buffer-overflow filler: a long run of a single non-null byte
	// ("AAAA…", 0x90 NOP sleds, …). Applies to any protocol.
	if bv, run := longestRun(payload); run >= bufOverflowRun && bv != 0 {
		v.Fuzzing, v.Technique = true, "buffer-overflow"
		v.Detail = fmt.Sprintf("run=%d byte=0x%02x", run, bv)
		return v
	}
	// Null flood: a payload that is mostly NUL bytes.
	if v.Size >= minClassifySize {
		if nulls := bytes.Count(payload, []byte{0}); float64(nulls)/float64(v.Size) >= nullFloodRatio {
			v.Fuzzing, v.Technique = true, "null-flood"
			v.Detail = fmt.Sprintf("nulls=%d/%d", nulls, v.Size)
			return v
		}
	}
	// Gross oversize for the protocol class.
	limit := oversizeBinary
	if text {
		limit = oversizeText
	}
	if v.Size > limit {
		v.Fuzzing, v.Technique = true, "oversize"
		v.Detail = fmt.Sprintf("size=%d>%d", v.Size, limit)
		return v
	}
	// The remaining techniques only make sense on text protocols (binary
	// protocols are high-entropy / low-printable by nature).
	if text && v.Size >= minClassifySize {
		if fmtSpecifierCount(payload) >= fmtSpecifiers {
			v.Fuzzing, v.Technique = true, "format-string"
			return v
		}
		if v.Entropy >= highEntropyText {
			v.Fuzzing, v.Technique = true, "high-entropy"
			v.Detail = fmt.Sprintf("entropy=%.2f", v.Entropy)
			return v
		}
		if v.Printable < binaryGarbage {
			v.Fuzzing, v.Technique = true, "binary-garbage"
			v.Detail = fmt.Sprintf("printable=%.2f", v.Printable)
			return v
		}
	}
	return v
}

// shannon returns the Shannon entropy (bits/byte, 0..8) of b.
func shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	var h float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

// printableRatio returns the fraction of b that is printable ASCII or
// common whitespace (tab/CR/LF).
func printableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 1
	}
	p := 0
	for _, c := range b {
		if c == '\t' || c == '\r' || c == '\n' || (c >= 0x20 && c < 0x7f) {
			p++
		}
	}
	return float64(p) / float64(len(b))
}

// longestRun returns the byte value and length of the longest run of a
// single repeated byte in b.
func longestRun(b []byte) (val byte, run int) {
	if len(b) == 0 {
		return 0, 0
	}
	best, cur := 1, 1
	val = b[0]
	for i := 1; i < len(b); i++ {
		if b[i] == b[i-1] {
			cur++
		} else {
			cur = 1
		}
		if cur > best {
			best, val = cur, b[i]
		}
	}
	return val, best
}

// fmtSpecifierCount counts printf-style conversion specifiers (%x %s %p %d
// %n) — a dense cluster is the signature of a format-string fuzz.
func fmtSpecifierCount(b []byte) int {
	n := 0
	for i := 0; i+1 < len(b); i++ {
		if b[i] != '%' {
			continue
		}
		switch b[i+1] {
		case 'x', 'X', 's', 'p', 'd', 'n':
			n++
		}
	}
	return n
}
