package handler

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// rtsp implements just enough RTSP (RFC 2326, TCP port 554) to fool an
// IP-camera scanner. Common scan flow:
//
//   OPTIONS rtsp://host/cam SDP RTSP/1.0
//   CSeq: 1
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
	resp := "RTSP/1.0 401 Unauthorized\r\n" +
		"CSeq: " + cseq + "\r\n" +
		"WWW-Authenticate: Digest realm=\"camera\", nonce=\"deadbeefcafebabe\", algorithm=\"MD5\", stale=\"FALSE\"\r\n" +
		"Server: HikvisionDS-2CD2T46G2-2I/V5.7.3\r\n" +
		"Content-Length: 0\r\n\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "rtsp 401 Digest"
	return res, nil
}
