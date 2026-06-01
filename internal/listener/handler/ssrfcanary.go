package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// ssrfCanary is an out-of-band callback collector. The URL/DNS canaries fire
// when an attacker visits a trap *inbound*; this handler is the inverse — it is
// the server you plant a token URL into (an SSRF-able parameter, a webhook
// field, a PDF/XML external entity, a fake "click to verify" link) so that when
// a victim system is coerced into fetching it, the *callback* is recorded here.
//
// Every hit is flagged ssrf-callback. We capture the token from the path, and
// the headers that betray the calling system: User-Agent (often a server SDK —
// python-requests, Go-http-client, libwww, java, curl — not a browser),
// X-Forwarded-For / Via / Forwarded (the proxy chain), and any cloud-SDK or
// metadata-proxy signature. A request whose UA looks like server-side
// automation rather than a human browser is additionally flagged
// ssrf-server-side-fetch — the high-signal "a machine fetched my token" case.
//
// We always answer 200 with a 1x1 GIF so the coerced fetch "succeeds" and the
// attacker's exploit chain proceeds (yielding more callbacks) instead of
// erroring out and tipping them off.
type ssrfCanary struct{}

func (s *ssrfCanary) Name() string { return "ssrf_canary" }

// onePixelGIF is a minimal valid 1x1 transparent GIF.
var onePixelGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
	0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
}

func (s *ssrfCanary) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 8192
	}
	head, _ := readHTTPHead(br, capN)
	res.Payload = head

	var path, ua, xff, via, fwd, host string
	for i, line := range strings.Split(string(head), "\r\n") {
		if i == 0 {
			res.Meta["request_line"] = line
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				path = parts[1]
			}
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "user-agent:"):
			ua = strings.TrimSpace(line[11:])
		case strings.HasPrefix(lower, "x-forwarded-for:"):
			xff = strings.TrimSpace(line[16:])
		case strings.HasPrefix(lower, "via:"):
			via = strings.TrimSpace(line[4:])
		case strings.HasPrefix(lower, "forwarded:"):
			fwd = strings.TrimSpace(line[10:])
		case strings.HasPrefix(lower, "host:"):
			host = strings.TrimSpace(line[5:])
		}
	}
	res.Meta["path"] = path
	if host != "" {
		res.Meta["host"] = host
	}
	if ua != "" {
		res.Meta["user_agent"] = ua
	}
	if xff != "" {
		res.Meta["x_forwarded_for"] = xff
	}
	if via != "" {
		res.Meta["via"] = via
	}
	if fwd != "" {
		res.Meta["forwarded"] = fwd
	}

	// The token is the last non-empty path segment (strip query string).
	if tok := ssrfToken(path); tok != "" {
		res.Meta["ssrf_token"] = tok
	}

	// Every callback to this server is, by definition, an out-of-band hit.
	flagAnomaly(&res, "ssrf-callback")
	if looksServerSideFetcher(ua) {
		flagAnomaly(&res, "ssrf-server-side-fetch")
		res.Meta["fetcher_kind"] = "server-side-automation"
	}

	body := onePixelGIF
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: image/gif\r\n" +
		"Cache-Control: no-store\r\n" +
		"Content-Length: " + intToStr(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write(append([]byte(resp), body...)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "ssrf_canary 200"
	return res, nil
}

// ssrfToken returns the last path segment with any query string stripped.
func ssrfToken(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	path = strings.Trim(path, "/")
	if path == "" {
		return ""
	}
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// looksServerSideFetcher reports whether a User-Agent looks like server-side
// automation (an HTTP client library or fetcher) rather than a human browser —
// the strong tell that a machine, not a person, retrieved the token.
func looksServerSideFetcher(ua string) bool {
	if ua == "" {
		return true // no UA at all is itself a non-browser tell
	}
	low := strings.ToLower(ua)
	// A real browser UA contains "mozilla/"; its absence plus a known client
	// library name is the signal.
	libs := []string{
		"python-requests", "python-urllib", "urllib", "go-http-client",
		"libwww-perl", "java/", "okhttp", "curl/", "wget/", "axios/",
		"node-fetch", "guzzlehttp", "ruby", "httpclient", "lwp::",
		"powershell", "winhttp", "libcurl", "aiohttp", "httpx",
	}
	for _, l := range libs {
		if strings.Contains(low, l) {
			return true
		}
	}
	return !strings.Contains(low, "mozilla/")
}
