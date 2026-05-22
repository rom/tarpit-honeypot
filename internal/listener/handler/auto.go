package handler

import (
	"bytes"
	"context"
	"net"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// auto is a generic catch-all for protocols the sensor doesn't explicitly
// model. It records whatever the client sends, guesses the protocol from the
// leading bytes, and flags it as unknown — so a probe on an unmodelled port
// still produces an attributable event instead of a dropped connection. If
// the operator sets a banner it's sent as a server-first nudge to draw out a
// client that waits for a greeting. It never reflects client input (so it
// can't be abused as an amplifier).
type auto struct{}

func (a *auto) Name() string { return "auto" }

func (a *auto) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 2048
	}

	n := readProbe(conn, capN)
	if len(n) == 0 && cfg.Banner != "" {
		// The client is waiting for a server-first banner — send the
		// operator's nudge (a fixed string, never client input) and retry.
		_, _ = conn.Write([]byte(cfg.Banner))
		res.BannerSent = cfg.Banner
		n = readProbe(conn, capN)
	}
	if len(n) == 0 {
		res.Meta["no_data"] = true
		return res, nil
	}
	res.Payload = n
	res.Meta["protocol_guess"] = guessProtocol(n)
	res.Meta["bytes"] = len(n)
	flagAnomaly(&res, "unknown-protocol")
	return res, nil
}

// readProbe reads up to capN bytes of the client's opening message within the
// connection's existing deadline. A scanner usually writes one probe; we do a
// couple of short reads to coalesce a fragmented one, then stop.
func readProbe(conn net.Conn, capN int) []byte {
	buf := make([]byte, capN)
	total := 0
	for total < capN {
		_ = conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
		m, err := conn.Read(buf[total:])
		total += m
		if err != nil || m == 0 {
			break
		}
		if m < len(buf[total-m:]) {
			break // got a short read — probably the whole probe
		}
	}
	if total == 0 {
		return nil
	}
	return append([]byte(nil), buf[:total]...)
}

// guessProtocol classifies an opening message by its leading bytes.
func guessProtocol(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	switch {
	case len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04:
		return "tls"
	case bytes.HasPrefix(b, []byte("SSH-")):
		return "ssh"
	case looksHTTP(b):
		return "http"
	case b[0] == 0x05:
		return "socks5"
	case b[0] == 0x04 && len(b) >= 2 && (b[1] == 0x01 || b[1] == 0x02):
		return "socks4"
	case b[0] == 0x00 && len(b) >= 4:
		return "binary-len-prefixed" // many RPC/DB framings start with a length
	case mostlyPrintable(b):
		return "text"
	default:
		return "binary"
	}
}

// looksHTTP reports whether b starts with an HTTP request line.
func looksHTTP(b []byte) bool {
	if i := bytes.IndexByte(b, ' '); i > 0 && i <= 16 {
		if isKnownHTTPMethod(string(b[:i])) {
			return true
		}
	}
	return bytes.Contains(b, []byte(" HTTP/"))
}

// mostlyPrintable reports whether at least 90% of b is printable ASCII /
// whitespace (so a text protocol is distinguished from a binary one).
func mostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\t' || c == '\r' || c == '\n' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return printable*10 >= len(b)*9
}
