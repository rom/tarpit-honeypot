package handler

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/jitter"
)

type ftp struct {
	jit *jitter.Jitterer
}

func (f *ftp) Name() string { return "ftp" }

// Minimal FTP login flow: 220 banner -> read USER -> 331 -> read PASS ->
// 530 incorrect, close. Captures username and password attempts.
func (f *ftp) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	f.jit.Sleep(ctx)
	banner := cfg.Banner
	if banner == "" {
		banner = "220 (vsFTPd 3.0.3)\r\n"
	}
	res := Result{BannerSent: banner}
	if _, err := conn.Write([]byte(banner)); err != nil {
		res.Meta = map[string]any{"write_err": err.Error()}
		return res, nil
	}
	br := bufio.NewReader(conn)

	user, _ := readFTPLine(br, cfg.ReadBytes)
	_, _ = conn.Write([]byte("331 Please specify the password.\r\n"))
	pass, _ := readFTPLine(br, cfg.ReadBytes)
	_, _ = conn.Write([]byte("530 Login incorrect.\r\n"))

	res.Meta = map[string]any{
		"user_line": strings.TrimSpace(user),
		"pass_line": strings.TrimSpace(pass),
	}
	res.Payload = []byte(user + "\n" + pass)
	return res, nil
}

func readFTPLine(br *bufio.Reader, cap int) (string, error) {
	if cap <= 0 {
		cap = 256
	}
	var buf bytes.Buffer
	for buf.Len() < cap {
		b, err := br.ReadByte()
		if err != nil {
			return buf.String(), err
		}
		buf.WriteByte(b)
		if b == '\n' {
			break
		}
	}
	return buf.String(), nil
}
