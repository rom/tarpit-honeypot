// Package safe provides bounds-checked input decoders and output
// sanitizers used across the sensor. The honeypot is on the receiving
// end of every kind of malformed / hostile / attacker-supplied data,
// so the policy is:
//
//   - When parsing untrusted bytes, every offset / length is bounds-
//     checked before use. No slice expressions like b[off:off+n]
//     without a preceding `if off+n > len(b)` guard. The helpers in
//     this file fail closed (return ok=false) rather than panicking
//     or allocating big.
//
//   - When emitting attacker-controlled strings to a log, a syslog
//     channel, an email body, an HTTP webhook, a Slack message, or
//     the SQLite store, the strings are passed through one of the
//     SanitizeFor* helpers first so control characters / escape
//     sequences / ANSI sequences / log-injection newlines can't
//     impersonate trusted log lines or trigger terminal exploits.
//
// The "Bounded*" helpers cap allocations at MaxStringBytes so a
// crafted 4-GB length-field can't be turned into a 4-GB make([]byte,
// n). The cap is exported so handlers can adjust it for known wider
// fields if necessary, but the default suits the longest legitimate
// field across every handler we ship.
package safe

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxStringBytes is the universal cap on a single attacker-supplied
// string field. Honeypot handlers should never accept arbitrarily-
// large strings — the longest legitimate input in our protocol set is
// a kerberos PA-DATA payload at ~16 KiB. Anything bigger is a fuzzer
// or a buffer-overflow attempt and gets rejected.
const MaxStringBytes = 32 * 1024

// MaxLogLength is the cap on a single field as it appears in a log
// line or alert body. Log readers (humans and SIEMs) get truncated
// strings instead of multi-megabyte attacker payloads.
const MaxLogLength = 4 * 1024

// Slice returns b[off:off+n] iff the slice is fully in-range; on out-
// of-range it returns (nil, false). Use this instead of bare slice
// expressions when off / n come from attacker bytes.
func Slice(b []byte, off, n int) ([]byte, bool) {
	if n < 0 || off < 0 {
		return nil, false
	}
	if off > len(b) {
		return nil, false
	}
	end := off + n
	if end < off { // overflow
		return nil, false
	}
	if end > len(b) {
		return nil, false
	}
	return b[off:end], true
}

// BoundedString returns the next n bytes of b at offset off as a string,
// rejecting out-of-range and over-cap inputs. The returned bool is true
// only when the read succeeded fully.
func BoundedString(b []byte, off, n int) (string, bool) {
	if n > MaxStringBytes {
		return "", false
	}
	s, ok := Slice(b, off, n)
	if !ok {
		return "", false
	}
	return string(s), true
}

// AllocBytes allocates an n-byte buffer iff n is within MaxStringBytes
// and non-negative. Returns (nil, false) otherwise. Use this in place
// of `make([]byte, n)` when n comes from attacker-controlled length
// fields.
func AllocBytes(n int) ([]byte, bool) {
	if n < 0 || n > MaxStringBytes {
		return nil, false
	}
	return make([]byte, n), true
}

// ASCIIPrintable filters s to printable ASCII (0x20..0x7E plus tab) and
// truncates to MaxLogLength runes. Non-printable bytes become '.'.
// This is the format we put in log "captured banner" fields so a binary
// payload can't smuggle ANSI escapes or newlines into the log file.
func ASCIIPrintable(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > MaxLogLength {
		s = s[:MaxLogLength] + "...[truncated]"
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\t':
			b.WriteByte(' ')
		case c >= 0x20 && c <= 0x7E:
			b.WriteByte(c)
		default:
			b.WriteByte('.')
		}
	}
	return b.String()
}

// SanitizeForLog escapes control characters and newlines so an attacker
// can't inject fake log lines or terminal control sequences into the
// log. NUL becomes \x00, newline becomes \n, CR becomes \r, escape
// becomes \x1b, etc. Other non-printable bytes become \xHH. Truncates
// at MaxLogLength.
//
// Pass *any* attacker-supplied string through this before emitting it
// into a log line, a CEF/LEEF field, an email subject/body, an HTTP
// webhook payload, an SMS body, or an SQLite text column.
func SanitizeForLog(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > MaxLogLength {
		s = s[:MaxLogLength] + "...[truncated]"
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case 0x1b:
			b.WriteString(`\e`)
		case 0x00:
			b.WriteString(`\0`)
		default:
			if c < 0x20 || c == 0x7F {
				fmt.Fprintf(&b, `\x%02x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

// SanitizeUTF8ForLog keeps printable Unicode but strips control runes,
// bidi-override marks, and zero-width characters. Use this when the
// caller wants the actual characters preserved (e.g. UTF-8 hostnames
// in DNS / LDAP), not byte-by-byte hex escapes.
func SanitizeUTF8ForLog(s string) string {
	if !utf8.ValidString(s) {
		// Fall back to byte-level sanitizer — invalid UTF-8 isn't
		// safe to render as Unicode.
		return SanitizeForLog(s)
	}
	if len(s) > MaxLogLength {
		// Truncate on a rune boundary.
		s = truncateUTF8(s, MaxLogLength) + "...[truncated]"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case unicode.IsControl(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		case r >= 0x2066 && r <= 0x2069, // bidi isolates
			r >= 0x202a && r <= 0x202e, // bidi overrides / embeds
			r >= 0x200b && r <= 0x200f, // zero-width
			r == 0xfeff:                // BOM / zero-width no-break
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	// Walk back to a rune boundary.
	for max > 0 && (s[max]&0xc0) == 0x80 {
		max--
	}
	return s[:max]
}

// SanitizeHeader strips CR, LF, and NUL so an attacker-supplied string
// can't inject extra HTTP headers via Server: <value> or
// Authorization: <value>. The output is suitable as a single HTTP
// header value.
func SanitizeHeader(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > 1024 {
		s = s[:1024]
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\r' || c == '\n' || c == 0 {
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// SanitizeEmailSubject removes line terminators and bell/escape codes
// so a stolen credential or scanner-supplied banner can't break the
// outbound alert email's MIME structure.
func SanitizeEmailSubject(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7F {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// SanitizeMetaStrings walks an event-meta map in place and replaces
// every string-typed value with its SanitizeForLog form. Nested maps
// and slices of strings get the same treatment. Used by the listener
// dispatch to ensure every captured field — request_line, banner,
// captured credentials, SNI, JA3-raw, SNMP community, anything the
// handler put in res.Meta — is escape-safe before it reaches a
// formatter / sink / log line, regardless of which output format
// the operator picked.
//
// This is the central enforcement point so we don't have to remember
// to call SanitizeForLog on every individual handler's meta write.
func SanitizeMetaStrings(meta map[string]any) {
	for k, v := range meta {
		meta[k] = sanitizeAny(v)
	}
}

func sanitizeAny(v any) any {
	switch t := v.(type) {
	case string:
		return SanitizeForLog(t)
	case []string:
		out := make([]string, len(t))
		for i, s := range t {
			out[i] = SanitizeForLog(s)
		}
		return out
	case []byte:
		// Render binary as hex string of the first slice; preserves
		// the data for forensic value without log-injection risk.
		return SanitizeForLog(string(t))
	case map[string]any:
		SanitizeMetaStrings(t)
		return t
	case []map[string]any:
		for _, m := range t {
			SanitizeMetaStrings(m)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = sanitizeAny(e)
		}
		return t
	}
	return v
}

// HexDump renders b as 16-byte-per-line hex with an ASCII gutter,
// capped at maxBytes. Used by handlers to attach a safe rendering of
// a malformed packet to its event meta without exposing the raw
// bytes to log-injection.
func HexDump(b []byte, maxBytes int) string {
	if maxBytes <= 0 || maxBytes > 1024 {
		maxBytes = 1024
	}
	n := len(b)
	if n > maxBytes {
		n = maxBytes
	}
	var out strings.Builder
	out.Grow(n * 4)
	for i := 0; i < n; i += 16 {
		fmt.Fprintf(&out, "%04x: ", i)
		end := i + 16
		if end > n {
			end = n
		}
		for j := i; j < end; j++ {
			fmt.Fprintf(&out, "%02x ", b[j])
		}
		for j := end; j < i+16; j++ {
			out.WriteString("   ")
		}
		out.WriteString(" |")
		for j := i; j < end; j++ {
			c := b[j]
			if c < 0x20 || c > 0x7E {
				out.WriteByte('.')
			} else {
				out.WriteByte(c)
			}
		}
		out.WriteString("|\n")
	}
	if len(b) > maxBytes {
		fmt.Fprintf(&out, "...[%d more bytes]\n", len(b)-maxBytes)
	}
	return out.String()
}
