package handler

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
)

type httpH struct {
	urlCanaries []config.URLCanary
	id          *identity.Identity
	jit         *jitter.Jitterer
	arch        *archetype.Profile
}

func (h *httpH) Name() string { return "http" }

// Plausible nginx-ish 401 response that captures the request line + headers.
// We read until \r\n\r\n (end of headers) or the read cap, whichever is first.
// Any request whose path exactly matches a configured URL canary is recorded
// in res.CanaryHits — the listener turns those into separate critical events.
// The Server: header is randomized per-deployment to defeat banner clustering,
// and JA4H is computed over the request line + headers.
func (h *httpH) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	h.jit.Sleep(ctx)
	return serveHTTP(conn, cfg, h.urlCanaries, h.id, h.arch)
}

func serveHTTP(conn net.Conn, cfg config.Listener, canaries []config.URLCanary, id *identity.Identity, arch *archetype.Profile) (Result, error) {
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

	// JA4H fingerprint over method+version+header order/values.
	if raw, hash := fingerprint.JA4H(buf.Bytes()); hash != "" {
		res.Meta["ja4h"] = hash
		res.Meta["ja4h_raw"] = raw
	}

	// URL canary match: parse the path out of the request line.
	if path := extractPath(firstLine); path != "" {
		for _, c := range canaries {
			if c.Path == path {
				res.CanaryHits = append(res.CanaryHits, c.ID)
			}
		}
	}

	server := "nginx/1.18.0"
	switch {
	case arch != nil && arch.HTTPServer() != "":
		server = arch.HTTPServer()
	case id != nil:
		server = id.HTTPServerHeader()
	}
	banner := cfg.Banner
	if banner == "" {
		// Archetypes with a web UI body (Moxa, Siemens, etc.) serve
		// 200 OK with a believable index page. Distro archetypes
		// without a configured body fall back to the canonical
		// nginx-shaped 401.
		if arch != nil && arch.HTTPBodyHTML() != "" {
			body := arch.HTTPBodyHTML()
			banner = "HTTP/1.1 200 OK\r\n" +
				"Server: " + server + "\r\n" +
				"Content-Type: text/html; charset=utf-8\r\n" +
				"Content-Length: " + itoa(len(body)) + "\r\n" +
				"Connection: close\r\n\r\n" +
				body
		} else {
			banner = "HTTP/1.1 401 Unauthorized\r\n" +
				"Server: " + server + "\r\n" +
				"WWW-Authenticate: Basic realm=\"admin\"\r\n" +
				"Content-Length: 0\r\n" +
				"Connection: close\r\n\r\n"
		}
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
