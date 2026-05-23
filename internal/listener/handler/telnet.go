package handler

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/safe"
	"github.com/rom/tarpit-honeypot/internal/sessionrec"
	"github.com/rom/tarpit-honeypot/internal/shell"
)

type telnet struct {
	jit  *jitter.Jitterer
	arch *archetype.Profile
	rec  *sessionrec.Store
}

func (t *telnet) Name() string { return "telnet" }

// IAC option negotiation: WILL ECHO, WILL SGA. Then a fake login prompt.
// Read a bounded amount, then close. Captures the username (and password if
// the client is fast enough to send it before the read cap).
var telnetIAC = []byte{
	0xff, 0xfb, 0x01, // IAC WILL ECHO
	0xff, 0xfb, 0x03, // IAC WILL SUPPRESS-GO-AHEAD
	0xff, 0xfd, 0x18, // IAC DO TERMINAL-TYPE
}

func (t *telnet) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	t.jit.Sleep(ctx)
	banner := cfg.Banner
	if banner == "" {
		switch {
		case t.arch != nil && t.arch.LoginPrompt() != "" && t.arch.TelnetBanner() != "":
			// Moxa / SCALANCE — the device shows a model/firmware
			// banner first, then a custom login prompt; archetype
			// stores both, telnetBanner usually ends with the
			// custom prompt already.
			banner = t.arch.TelnetBanner()
		case t.arch != nil && t.arch.TelnetBanner() != "":
			banner = t.arch.TelnetBanner()
		default:
			banner = "\r\nUbuntu 20.04.6 LTS\r\n\r\nlogin: "
		}
	}
	res := Result{Meta: map[string]any{}}
	if _, err := conn.Write(telnetIAC); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	if _, err := conn.Write([]byte(banner)); err != nil {
		if res.Meta == nil {
			res.Meta = map[string]any{}
		}
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = banner

	br := bufio.NewReader(conn)
	// Read the username line. ReadBytes acts as a soft cap; honeypot
	// telnet logs typically see < 64 byte usernames.
	cap := cfg.ReadBytes
	if cap <= 0 {
		cap = 256
	}
	// A real telnet client interleaves IAC option negotiation with the
	// login bytes; readTelnetLine consumes those (and answers them) so the
	// captured username/password aren't polluted with 0xff option bytes —
	// a honeypot that logs raw IAC garbage is an easy tell.
	user, _ := readTelnetLine(br, conn, cap, &res)
	user = strings.TrimRight(user, "\r\n")
	// Standard /bin/login prompt sequence.
	_, _ = conn.Write([]byte("Password: "))
	pass, _ := readTelnetLine(br, conn, cap, &res)
	pass = strings.TrimRight(pass, "\r\n")

	res.Meta["user_attempt"] = safe.SanitizeForLog(user)
	res.Meta["pass_attempt"] = safe.SanitizeForLog(pass)
	res.Payload = []byte(user + "\n" + pass)
	flagDefaultCred(&res, user, pass)
	if hasNonPrintable(user) || hasNonPrintable(pass) {
		flagAnomaly(&res, "telnet-credential-non-printable")
	}

	// First attempt always "fails" — most scanners give up after one,
	// the few that retry get a second login prompt and a second
	// failure. Real /bin/login behavior.
	_, _ = conn.Write([]byte("\r\nLogin incorrect\r\n"))

	// CLI shell engagement: post-fake-login we accept the second
	// attempt and drop into the archetype's shell. This is where the
	// post-login TTP capture happens — every command the attacker
	// types lands in res.Meta["shell_commands"] and any anomaly
	// markers (reverse shell, persistence, recon) bubble up into
	// res.Meta["anomalies"] which the listener promotes to a
	// first-class event field.
	if t.arch != nil && t.arch.CLIPrompt() != "" {
		// Second login banner.
		if t.arch.LoginPrompt() != "" {
			_, _ = conn.Write([]byte(t.arch.LoginPrompt()))
		} else {
			_, _ = conn.Write([]byte("\r\nlogin: "))
		}
		_, _ = readBoundedLineFromReader(br, cap)
		_, _ = conn.Write([]byte("Password: "))
		_, _ = readBoundedLineFromReader(br, cap)
		// "Welcome" line — the kind every distro / device shows.
		_, _ = conn.Write([]byte("\r\nLast login: Mon May 19 13:01:22 from 10.0.0.5\r\n"))

		// Drive the shell loop until exit / timeout / EOF, recording the
		// session as an asciinema cast when enabled.
		var inR io.Reader = br
		var outW io.Writer = conn
		if t.rec != nil {
			if rc, name, err := t.rec.Begin(hostFromAddr(conn.RemoteAddr())); err == nil {
				defer rc.Close()
				inR, outW = rc.Reader(br), rc.Writer(conn)
				res.Meta["session_cast"] = name
			}
		}
		captured := shell.Run(ctx, inR, outW, t.arch)
		if len(captured.Commands) > 0 {
			res.Meta["shell_commands"] = captured.Commands
		}
		for _, a := range captured.Anomalies {
			flagAnomaly(&res, a)
		}
	}
	return res, nil
}

// Telnet protocol bytes (RFC 854 / 1091).
const (
	telIAC      = 0xff
	telSE       = 0xf0
	telSB       = 0xfa
	telWILL     = 0xfb
	telWONT     = 0xfc
	telDO       = 0xfd
	telDONT     = 0xfe
	telOptEcho  = 0x01
	telOptSGA   = 0x03
	telOptTType = 0x18 // TERMINAL-TYPE
)

// readTelnetLine reads one line, transparently consuming and answering IAC
// option negotiation so it never lands in the captured credential. It also
// harvests the client's TERMINAL-TYPE subnegotiation into res.Meta.
func readTelnetLine(br *bufio.Reader, conn net.Conn, max int, res *Result) (string, error) {
	if max <= 0 || max > 4096 {
		max = 4096
	}
	out := make([]byte, 0, 64)
	for len(out) < max {
		b, err := br.ReadByte()
		if err != nil {
			return string(out), err
		}
		if b != telIAC {
			if b == '\n' {
				break
			}
			out = append(out, b)
			continue
		}
		cmd, err := br.ReadByte()
		if err != nil {
			return string(out), err
		}
		switch cmd {
		case telWILL, telWONT, telDO, telDONT:
			opt, err := br.ReadByte()
			if err != nil {
				return string(out), err
			}
			telnetNegotiate(conn, cmd, opt)
		case telSB:
			sub := readTelnetSubneg(br)
			// TERMINAL-TYPE IS (option 0x18, sub-cmd 0x00) carries the
			// client's emulation string (xterm, VT100, PuTTY, …).
			if len(sub) >= 2 && sub[0] == telOptTType && sub[1] == 0x00 && res != nil {
				res.Meta["terminal_type"] = safe.SanitizeForLog(string(sub[2:]))
			}
		case telIAC:
			out = append(out, telIAC) // escaped literal 0xff
		default:
			// 2-byte command (NOP / GA / AYT / …) — nothing to consume.
		}
	}
	return string(out), nil
}

// telnetNegotiate sends a minimal, consistent reply to a client option
// negotiation so the session looks real: we honour ECHO + SGA (already
// announced WILL), ask for TERMINAL-TYPE, and refuse everything else.
func telnetNegotiate(conn net.Conn, cmd, opt byte) {
	switch cmd {
	case telDO:
		if opt == telOptEcho || opt == telOptSGA {
			return // already WILL — no reply needed
		}
		_, _ = conn.Write([]byte{telIAC, telWONT, opt})
	case telWILL:
		if opt == telOptTType {
			// We sent DO TERMINAL-TYPE; ask the client to send its type.
			_, _ = conn.Write([]byte{telIAC, telSB, telOptTType, 0x01, telIAC, telSE})
			return
		}
		_, _ = conn.Write([]byte{telIAC, telDONT, opt})
	}
	// WONT / DONT need no reply.
}

// readTelnetSubneg reads an IAC SB … IAC SE subnegotiation body (excluding
// the trailing IAC SE), bounded so a peer can't stream forever.
func readTelnetSubneg(br *bufio.Reader) []byte {
	out := make([]byte, 0, 32)
	for len(out) < 256 {
		b, err := br.ReadByte()
		if err != nil {
			return out
		}
		if b == telIAC {
			n, err := br.ReadByte()
			if err != nil {
				return out
			}
			if n == telSE {
				return out
			}
			if n == telIAC {
				out = append(out, telIAC) // escaped 0xff inside subneg
				continue
			}
			// Unexpected command inside SB — stop.
			return out
		}
		out = append(out, b)
	}
	return out
}

// readBoundedLineFromReader is the telnet-handler-local bounded read
// helper. We don't use bufio.Reader.ReadString('\n') because that has
// no built-in length cap; an attacker could hold the connection open
// and dribble bytes forever. The function caps at max bytes.
func readBoundedLineFromReader(br *bufio.Reader, max int) (string, error) {
	if max <= 0 || max > 4096 {
		max = 4096
	}
	out := make([]byte, 0, 64)
	for len(out) < max {
		b, err := br.ReadByte()
		if err != nil {
			return string(out), err
		}
		out = append(out, b)
		if b == '\n' {
			break
		}
	}
	return string(out), nil
}
