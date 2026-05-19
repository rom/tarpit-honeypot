package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/safe"
	"github.com/rom/tarpit-honeypot/internal/shell"
)

type telnet struct {
	jit  *jitter.Jitterer
	arch *archetype.Profile
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
	res := Result{}
	if _, err := conn.Write(telnetIAC); err != nil {
		res.Meta = map[string]any{"write_err": err.Error()}
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
	user, _ := readBoundedLineFromReader(br, cap)
	user = strings.TrimRight(user, "\r\n")
	// Standard /bin/login prompt sequence.
	_, _ = conn.Write([]byte("Password: "))
	pass, _ := readBoundedLineFromReader(br, cap)
	pass = strings.TrimRight(pass, "\r\n")

	res.Meta = map[string]any{
		"user_attempt": safe.SanitizeForLog(user),
		"pass_attempt": safe.SanitizeForLog(pass),
	}
	res.Payload = []byte(user + "\n" + pass)

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

		// Drive the shell loop until exit / timeout / EOF.
		captured := shell.Run(ctx, br, conn, t.arch)
		if len(captured.Commands) > 0 {
			res.Meta["shell_commands"] = captured.Commands
		}
		for _, a := range captured.Anomalies {
			flagAnomaly(&res, a)
		}
	}
	return res, nil
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
