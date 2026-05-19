package handler

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// sip is a UDP SIP receiver (port 5060). SIP is text-based — request
// lines look like `OPTIONS sip:1000@1.2.3.4 SIP/2.0`. Common scanner
// behavior: send OPTIONS, REGISTER, or INVITE to enumerate extensions.
// We capture the method + From + To + User-Agent and reply with
// 200 OK so the scanner's enumeration loop is misled.
type sipUDP struct{}

func (s *sipUDP) Name() string { return "sip" }

func (s *sipUDP) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	lines := strings.Split(string(payload), "\r\n")
	if len(lines) < 1 {
		return res, nil
	}
	reqLine := lines[0]
	parts := strings.Fields(reqLine)
	if len(parts) < 3 {
		res.Meta["non_sip"] = true
		return res, nil
	}
	method := strings.ToUpper(parts[0])
	res.Meta["method"] = method
	res.Meta["request_line"] = reqLine
	via := ""
	for _, line := range lines[1:] {
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "from:"):
			res.Meta["from"] = strings.TrimSpace(line[5:])
		case strings.HasPrefix(lower, "to:"):
			res.Meta["to"] = strings.TrimSpace(line[3:])
		case strings.HasPrefix(lower, "call-id:"):
			res.Meta["call_id"] = strings.TrimSpace(line[8:])
		case strings.HasPrefix(lower, "user-agent:"):
			res.Meta["user_agent"] = strings.TrimSpace(line[11:])
		case strings.HasPrefix(lower, "authorization:"):
			res.Meta["authorization"] = strings.TrimSpace(line[14:])
		case strings.HasPrefix(lower, "via:"):
			via = strings.TrimSpace(line[4:])
			res.Meta["via"] = via
		case strings.HasPrefix(lower, "cseq:"):
			res.Meta["cseq"] = strings.TrimSpace(line[5:])
		}
	}
	// Reply 200 OK echoing Via/From/To/Call-ID/CSeq.
	reply := fmt.Sprintf("SIP/2.0 200 OK\r\n"+
		"Via: %s\r\n"+
		"From: %s\r\n"+
		"To: %s;tag=as%x\r\n"+
		"Call-ID: %s\r\n"+
		"CSeq: %s\r\n"+
		"Server: Asterisk/16.16.2\r\n"+
		"Content-Length: 0\r\n\r\n",
		via,
		valueOr(res.Meta, "from", ""),
		valueOr(res.Meta, "to", ""),
		len(payload),
		valueOr(res.Meta, "call_id", ""),
		valueOr(res.Meta, "cseq", ""),
	)
	if _, err := pc.WriteTo([]byte(reply), src); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "sip 200 OK"
	_ = cfg
	return res, nil
}

func valueOr(m map[string]any, k, def string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}
