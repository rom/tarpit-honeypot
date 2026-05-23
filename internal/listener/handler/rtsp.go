package handler

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// rtsp implements just enough RTSP (RFC 2326, TCP port 554) to fool an
// IP-camera scanner. Common scan flow:
//
//	OPTIONS rtsp://host/cam SDP RTSP/1.0
//	CSeq: 1
//
// We reply 401 with a Digest challenge so the scanner records the
// host as an authenticating RTSP server and (often) sends credentials
// next. The Authorization header gets captured in event meta.
type rtsp struct{}

func (r *rtsp) Name() string { return "rtsp" }

func (r *rtsp) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	cap := cfg.ReadBytes
	if cap <= 0 {
		cap = 4096
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
	method, cseq, auth := "", "", ""
	for i, line := range strings.Split(string(buf.Bytes()), "\r\n") {
		if i == 0 {
			res.Meta["request_line"] = line
			parts := strings.Fields(line)
			if len(parts) > 0 {
				method = strings.ToUpper(parts[0])
			}
		} else {
			lower := strings.ToLower(line)
			switch {
			case strings.HasPrefix(lower, "cseq:"):
				cseq = strings.TrimSpace(line[5:])
			case strings.HasPrefix(lower, "authorization:"):
				auth = strings.TrimSpace(line[14:])
				res.Meta["authorization"] = auth
			case strings.HasPrefix(lower, "user-agent:"):
				res.Meta["user_agent"] = strings.TrimSpace(line[11:])
			}
		}
	}
	res.Meta["method"] = method
	// Every reflected value is attacker-controlled; SanitizeHeader strips
	// CR/LF/NUL so a crafted CSeq can't smuggle extra headers (TCP-only, but
	// a downstream proxy/cache could still be confused).
	scseq := safe.SanitizeHeader(cseq)
	const server = "Server: Hipcam RealServer/V1.0\r\n"
	var resp string
	switch method {
	case "OPTIONS":
		// A real RTSP server answers OPTIONS unauthenticated, advertising the
		// methods it supports — what a camera scanner reads first.
		resp = "RTSP/1.0 200 OK\r\n" +
			"CSeq: " + scseq + "\r\n" +
			"Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER, SET_PARAMETER\r\n" +
			server + "\r\n"
		res.BannerSent = "rtsp 200 OPTIONS"
	case "GET_PARAMETER", "SET_PARAMETER":
		resp = "RTSP/1.0 200 OK\r\nCSeq: " + scseq + "\r\n" + server + "Content-Length: 0\r\n\r\n"
		res.BannerSent = "rtsp 200 " + method
	default:
		// DESCRIBE / SETUP / PLAY / … require auth on a real camera: reply
		// 401 with a Digest challenge so the scanner sends credentials next
		// (captured from the Authorization header on the follow-up).
		resp = "RTSP/1.0 401 Unauthorized\r\n" +
			"CSeq: " + scseq + "\r\n" +
			"WWW-Authenticate: Digest realm=\"camera\", nonce=\"deadbeefcafebabe\", algorithm=\"MD5\", stale=\"FALSE\"\r\n" +
			"WWW-Authenticate: Basic realm=\"camera\"\r\n" +
			server + "Content-Length: 0\r\n\r\n"
		res.BannerSent = "rtsp 401 Digest"
		if auth != "" {
			// A captured Authorization header on a DESCRIBE/SETUP is a
			// credential-submission attempt worth flagging.
			flagAnomaly(&res, "rtsp-auth-attempt")
		}
	}
	if _, err := conn.Write([]byte(resp)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	return res, nil
}
