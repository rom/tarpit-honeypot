package handler

import (
	"bytes"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// lpd emulates the Line Printer Daemon (TCP 515, RFC 1179) that printers,
// MFPs and print servers expose. The protocol is a one-byte command code
// followed by a queue name (and, for "receive job", a control file whose
// H/P/J/C/L fields historically flowed into shell pipelines on real
// servers — the LPD command-injection / format-string class).
//
// We acknowledge the command (so a client/tool keeps going and reveals its
// control file), capture the queue + control metadata, and flag printer
// abuse: shell-metacharacter injection in any field, overlong fields
// (buffer-overflow probes), and path traversal in the queue/filename.
// Nothing is queued or executed.
type lpd struct{}

func (l *lpd) Name() string { return "lpd" }

// lpdMaxField is the largest field we treat as legitimate; longer is a
// classic overflow probe against real LPD implementations.
const lpdMaxField = 256

func (l *lpd) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	readCap := cfg.ReadBytes
	if readCap <= 0 || readCap > 65535 {
		readCap = 8192
	}
	buf := make([]byte, readCap)
	n, _ := conn.Read(buf)
	if n <= 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}
	in := buf[:n]
	res.Payload = append([]byte(nil), in...)

	cmd := in[0]
	res.Meta["lpd_command"] = lpdCmdName(cmd)
	flagAnomaly(&res, "printer-lpd-command")

	// Operand: the rest of the first line (queue name, optionally + agent).
	// rest is anything after that newline — a control file batched into the
	// same packet (some tools don't wait for the ack).
	body := in[1:]
	operand := body
	var rest []byte
	if i := bytes.IndexByte(body, '\n'); i >= 0 {
		operand = body[:i]
		rest = body[i+1:]
	}
	res.Meta["lpd_operand"] = string(operand) // sanitized centrally
	l.scanField(string(operand), &res)

	// Receive-job (0x02): ack so a client/tool keeps going, then scan the
	// control/data files — that's where the injectable H/P/J/C/L fields
	// live. Handle both batched (rest) and wait-for-ack (second read) flows.
	if cmd == 0x02 {
		_, _ = conn.Write([]byte{0x00}) // positive acknowledgement
		if len(rest) > 0 {
			l.scanControlFile(string(rest), &res)
		} else {
			withTimeout(conn, cfg.ReadTimeout)
			if n2, _ := conn.Read(buf); n2 > 0 {
				ctrl := buf[:n2]
				if len(res.Payload) < pjlMaxBytes {
					res.Payload = append(res.Payload, ctrl...)
				}
				l.scanControlFile(string(ctrl), &res)
				_, _ = conn.Write([]byte{0x00})
			}
		}
	}
	res.BannerSent = "lpd ack"
	return res, nil
}

// scanField flags injection / overflow / traversal in a single operand
// (queue name, agent, or a control-file value).
func (l *lpd) scanField(s string, res *Result) {
	if len(s) > lpdMaxField {
		flagAnomaly(res, "printer-lpd-overflow")
	}
	if lpdHasShellMeta(s) {
		flagAnomaly(res, "printer-lpd-injection")
	}
	low := strings.ToLower(s)
	if strings.Contains(low, "../") || strings.Contains(low, "..\\") {
		flagAnomaly(res, "printer-path-traversal")
	}
}

// scanControlFile inspects RFC-1179 control-file lines. Each line is a
// single-letter command followed by a value; the host (H), user (P),
// job-name (J), class (C) and banner (L) values are the historically
// shell-injectable ones.
func (l *lpd) scanControlFile(text string, res *Result) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		switch line[0] {
		case 'H', 'P', 'J', 'C', 'L', 'N', 'f', 'l', 'o', 'p', 'r', 'U', 'S':
			l.scanField(line[1:], res)
		}
	}
}

func lpdHasShellMeta(s string) bool {
	return strings.ContainsAny(s, "`;|&<>$(){}\n\r") || strings.Contains(s, "$(")
}

func lpdCmdName(c byte) string {
	switch c {
	case 0x01:
		return "print-waiting-jobs"
	case 0x02:
		return "receive-job"
	case 0x03:
		return "queue-state-short"
	case 0x04:
		return "queue-state-long"
	case 0x05:
		return "remove-jobs"
	}
	return "unknown"
}
