package handler

import (
	"bufio"
	"context"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type ssh struct{}

func (s *ssh) Name() string { return "ssh" }

// SSH identification string per RFC 4253 §4.2. We send a believable banner,
// read the client's identification line, then send a fake "Protocol mismatch"
// and close — no key exchange. Enough to log who tried.
func (s *ssh) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	banner := cfg.Banner
	if banner == "" {
		banner = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n"
	}
	res := Result{BannerSent: banner}
	if _, err := conn.Write([]byte(banner)); err != nil {
		res.Meta = map[string]any{"write_err": err.Error()}
		return res, nil
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err == nil && line != "" {
		res.Payload = []byte(line)
		res.Meta = map[string]any{"client_id": line}
	} else if err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
	}
	_, _ = conn.Write([]byte("Protocol mismatch.\r\n"))
	return res, nil
}
