package handler

import (
	"bufio"
	"context"
	"net"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/jitter"
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
		if t.arch != nil && t.arch.TelnetBanner() != "" {
			banner = t.arch.TelnetBanner()
		} else {
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
	cap := cfg.ReadBytes
	if cap <= 0 {
		cap = 256
	}
	buf := make([]byte, 0, cap)
	for len(buf) < cap {
		b, err := br.ReadByte()
		if err != nil {
			break
		}
		buf = append(buf, b)
		if b == '\n' {
			break
		}
	}
	if len(buf) > 0 {
		res.Payload = buf
	}
	return res, nil
}
