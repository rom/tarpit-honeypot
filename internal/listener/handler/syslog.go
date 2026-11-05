package handler

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// syslogTCP is a TCP-only syslog receiver. Per RFC 6587 there are two
// framings: octet-counting (`<len> <payload>`) and non-transparent
// (newline-terminated). We accept both. Captures the first few messages
// so credential-leaking syslog feeds (yes, those exist) get logged.
type syslogTCP struct{}

func (s *syslogTCP) Name() string { return "syslog_tcp" }

func (s *syslogTCP) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	var msgs []string
	for i := 0; i < 16; i++ {
		// Peek first byte to detect octet-counting framing.
		b, err := br.Peek(1)
		if err != nil {
			break
		}
		if b[0] >= '0' && b[0] <= '9' {
			// octet-counting: read digits, space, then that many bytes
			lenStr := ""
			for {
				c, err := br.ReadByte()
				if err != nil {
					break
				}
				if c == ' ' {
					break
				}
				lenStr += string(c)
			}
			n := 0
			fmt.Sscanf(lenStr, "%d", &n)
			if n <= 0 || n > 8192 {
				break
			}
			buf := make([]byte, n)
			if _, err := br.Read(buf); err != nil {
				break
			}
			msgs = append(msgs, string(buf))
		} else {
			line, err := readLineCapped(br, maxLineBytes)
			if err != nil && line == "" {
				break
			}
			msgs = append(msgs, strings.TrimRight(line, "\r\n"))
		}
	}
	if len(msgs) > 0 {
		res.Meta["messages"] = msgs
		res.Meta["message_count"] = len(msgs)
		res.Payload = []byte(strings.Join(msgs, "\n"))
	}
	res.BannerSent = "syslog_tcp accept (no reply)"
	return res, nil
}

// syslogUDP is the UDP equivalent. RFC 5424 / RFC 3164 messages arrive
// one per datagram. Per-packet — no state.
type syslogUDP struct{}

func (s *syslogUDP) Name() string { return "syslog_udp" }

func (s *syslogUDP) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...)}
	msg := strings.TrimRight(string(payload), "\r\n")
	res.Meta = map[string]any{
		"message": msg,
	}
	// Try to extract <PRI> per RFC 3164.
	if strings.HasPrefix(msg, "<") {
		if end := strings.IndexByte(msg, '>'); end > 0 && end < 6 {
			pri := 0
			fmt.Sscanf(msg[1:end], "%d", &pri)
			res.Meta["pri"] = pri
			res.Meta["facility"] = pri >> 3
			res.Meta["sev"] = pri & 0x07
			res.Meta["body"] = msg[end+1:]
		}
	}
	_ = cfg
	_ = src
	_ = pc
	return res, nil
}
