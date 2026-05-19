package handler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type winrm struct{}

func (w *winrm) Name() string { return "winrm" }

// WinRM (port 5985 HTTP, 5986 HTTPS). It's HTTP at the transport layer
// — a real WinRM endpoint accepts a POST /wsman with a SOAP envelope and
// challenges with WWW-Authenticate: Negotiate or Basic. Most scanners
// look for the IIS-style 401 + WWW-Authenticate response.
//
// We capture the Authorization header (which often contains Basic creds
// for legacy / lab deployments) and reply with a credible IIS 401.
func (w *winrm) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	br := bufio.NewReader(conn)
	cap := cfg.ReadBytes
	if cap <= 0 {
		cap = 8192
	}
	var buf bytes.Buffer
	for buf.Len() < cap {
		b, err := br.ReadByte()
		if err != nil {
			res.Meta["read_err"] = err.Error()
			break
		}
		buf.WriteByte(b)
		if bytes.HasSuffix(buf.Bytes(), []byte("\r\n\r\n")) {
			break
		}
	}
	res.Payload = buf.Bytes()

	for i, line := range strings.Split(buf.String(), "\r\n") {
		if i == 0 {
			res.Meta["request_line"] = line
		} else if strings.HasPrefix(strings.ToLower(line), "authorization:") {
			auth := strings.TrimSpace(line[len("authorization:"):])
			res.Meta["authorization"] = auth
			if strings.HasPrefix(strings.ToLower(auth), "basic ") {
				dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[6:]))
				if err == nil {
					if i := bytes.IndexByte(dec, ':'); i >= 0 {
						res.Meta["basic_user"] = string(dec[:i])
						res.Meta["basic_pass"] = string(dec[i+1:])
					}
				}
			}
		} else if strings.HasPrefix(strings.ToLower(line), "user-agent:") {
			res.Meta["user_agent"] = strings.TrimSpace(line[len("user-agent:"):])
		}
	}

	resp := "HTTP/1.1 401 Unauthorized\r\n" +
		"Server: Microsoft-HTTPAPI/2.0\r\n" +
		"WWW-Authenticate: Negotiate\r\n" +
		"WWW-Authenticate: Basic realm=\"WSMAN\"\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "winrm 401 Negotiate+Basic"
	return res, nil
}
