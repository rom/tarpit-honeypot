package handler

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// dockerapi mimics the Docker Engine HTTP API (unauthenticated, on
// TCP 2375 / TLS 2376). Cryptominers and cloud-pivoting tools sweep
// for it constantly — finding an open daemon means full container
// runtime + host filesystem mount in a single API call.
//
// We respond like a real daemon to /_ping, /version, and /info, and
// 200 OK with an empty array to /containers/json. Anything that tries
// to POST (start a container, create one, exec into it) gets 401.
// The Authorization / X-Registry-Auth headers are captured.
type dockerapi struct{}

func (d *dockerapi) Name() string { return "dockerapi" }

func (d *dockerapi) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
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
			break
		}
		buf.WriteByte(b)
		if bytes.HasSuffix(buf.Bytes(), []byte("\r\n\r\n")) {
			break
		}
	}
	res.Payload = buf.Bytes()

	method, path := "", ""
	for i, line := range strings.Split(string(buf.Bytes()), "\r\n") {
		if i == 0 {
			res.Meta["request_line"] = line
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				method, path = strings.ToUpper(parts[0]), parts[1]
			}
		} else {
			lower := strings.ToLower(line)
			switch {
			case strings.HasPrefix(lower, "authorization:"):
				res.Meta["authorization"] = strings.TrimSpace(line[14:])
			case strings.HasPrefix(lower, "x-registry-auth:"):
				res.Meta["x_registry_auth"] = strings.TrimSpace(line[16:])
			case strings.HasPrefix(lower, "user-agent:"):
				res.Meta["user_agent"] = strings.TrimSpace(line[11:])
			}
		}
	}
	res.Meta["method"] = method
	res.Meta["path"] = path

	// Route by path prefix (Docker API is versioned: /v1.41/foo etc.).
	stripped := path
	if i := strings.Index(stripped, "/"); i >= 0 {
		// `/v1.41/info` -> `/info`
		if strings.HasPrefix(stripped, "/v") {
			if next := strings.Index(stripped[1:], "/"); next > 0 {
				stripped = stripped[1+next:]
			}
		}
	}

	var body, contentType string
	status := "200 OK"
	switch {
	case method == "GET" && (stripped == "/_ping" || strings.HasSuffix(path, "/_ping")):
		body = "OK"
		contentType = "text/plain"
	case method == "GET" && strings.HasSuffix(stripped, "/version"):
		body = `{"Version":"24.0.7","ApiVersion":"1.43","Os":"linux","Arch":"amd64"}`
		contentType = "application/json"
	case method == "GET" && strings.HasSuffix(stripped, "/info"):
		body = `{"Containers":3,"Running":1,"Images":12,"ServerVersion":"24.0.7","OperatingSystem":"Ubuntu 22.04.3 LTS"}`
		contentType = "application/json"
	case method == "GET" && strings.HasPrefix(stripped, "/containers"):
		body = `[]`
		contentType = "application/json"
	case method == "POST" || method == "DELETE" || method == "PUT":
		status = "401 Unauthorized"
		body = `{"message":"unauthorized: must provide credentials"}`
		contentType = "application/json"
	default:
		status = "404 Not Found"
		body = `{"message":"page not found"}`
		contentType = "application/json"
	}
	resp := "HTTP/1.1 " + status + "\r\n" +
		"Server: Docker/24.0.7 (linux)\r\n" +
		"Api-Version: 1.43\r\n" +
		"Ostype: linux\r\n" +
		"Content-Type: " + contentType + "\r\n" +
		"Content-Length: " + intToStr(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" +
		body
	if _, err := conn.Write([]byte(resp)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "dockerapi " + status
	return res, nil
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	out := []byte{}
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	if neg {
		out = append([]byte{'-'}, out...)
	}
	return string(out)
}
