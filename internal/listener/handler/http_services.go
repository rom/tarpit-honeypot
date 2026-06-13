package handler

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// Shared HTTP-request parsing for the small JSON/REST service handlers
// (couchdb, influxdb, docker_registry) that fingerprint by a protocol-specific
// response the generic http handler wouldn't produce.

// svcHTTPReqLine parses the request line + Authorization / User-Agent headers
// from an HTTP head, returning method, path (query stripped), the raw query,
// and the two captured header values.
func svcHTTPReqLine(head []byte) (method, path, query, authz, ua string) {
	for i, line := range strings.Split(string(head), "\r\n") {
		if i == 0 {
			if f := strings.Fields(line); len(f) >= 2 {
				method, path = strings.ToUpper(f[0]), f[1]
			}
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "authorization:"):
			authz = strings.TrimSpace(line[14:])
		case strings.HasPrefix(lower, "user-agent:"):
			ua = strings.TrimSpace(line[11:])
		}
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, query = path[:i], path[i+1:]
	}
	return
}

// svcHTTPBody reads the request body indicated by Content-Length (bounded).
func svcHTTPBody(br *bufio.Reader, head []byte, cap int) []byte {
	n := 0
	for _, line := range strings.Split(string(head), "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			n, _ = strconv.Atoi(strings.TrimSpace(line[15:]))
			break
		}
	}
	if n <= 0 {
		return nil
	}
	if n > cap {
		n = cap
	}
	body := make([]byte, n)
	got, _ := io.ReadFull(br, body)
	return body[:got]
}

// svcHTTPResp frames an HTTP/1.1 response with the given extra header block
// (may be empty), content type, and body.
func svcHTTPResp(status, extraHeaders, ctype, body string) string {
	return "HTTP/1.1 " + status + "\r\n" + extraHeaders +
		"Content-Type: " + ctype + "\r\n" +
		"Content-Length: " + intToStr(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
}
