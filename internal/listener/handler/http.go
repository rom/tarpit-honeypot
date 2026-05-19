package handler

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type httpH struct {
	urlCanaries []config.URLCanary
}

func (h *httpH) Name() string { return "http" }

// Plausible nginx-ish 401 response that captures the request line + headers.
// We read until \r\n\r\n (end of headers) or the read cap, whichever is first.
// Any request whose path exactly matches a configured URL canary is recorded
// in res.CanaryHits — the listener turns those into separate critical events.
func (h *httpH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	return serveHTTP(conn, cfg, h.urlCanaries)
}

func serveHTTP(conn net.Conn, cfg config.Listener, canaries []config.URLCanary) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}

	br := bufio.NewReader(conn)
	cap := cfg.ReadBytes
	if cap <= 0 {
		cap = 4096
	}
	var buf bytes.Buffer
	for buf.Len() < cap {
		b, err := br.ReadByte()
		if err != nil {
			res.Meta = map[string]any{"read_err": err.Error()}
			break
		}
		buf.WriteByte(b)
		if bytes.HasSuffix(buf.Bytes(), []byte("\r\n\r\n")) {
			break
		}
	}
	res.Payload = buf.Bytes()

	firstLine := ""
	host := ""
	for i, line := range strings.Split(string(buf.Bytes()), "\r\n") {
		if i == 0 {
			firstLine = line
		} else if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(line[5:])
		}
	}
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	res.Meta["request_line"] = firstLine
	res.Meta["host"] = host

	// URL canary match: parse the path out of the request line.
	if path := extractPath(firstLine); path != "" {
		for _, c := range canaries {
			if c.Path == path {
				res.CanaryHits = append(res.CanaryHits, c.ID)
			}
		}
	}

	banner := cfg.Banner
	if banner == "" {
		banner = "HTTP/1.1 401 Unauthorized\r\n" +
			"Server: nginx/1.18.0\r\n" +
			"WWW-Authenticate: Basic realm=\"admin\"\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n\r\n"
	}
	if _, err := conn.Write([]byte(banner)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = banner
	return res, nil
}

// extractPath returns the path portion of an HTTP request line like
// "GET /admin?x=1 HTTP/1.1". The query string is stripped because canary
// matching should be path-only.
func extractPath(reqLine string) string {
	parts := strings.SplitN(reqLine, " ", 3)
	if len(parts) < 2 {
		return ""
	}
	p := parts[1]
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return p
}
