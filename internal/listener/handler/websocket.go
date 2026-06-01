package handler

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// websocketH emulates a WebSocket endpoint. Modern apps expose WS for admin
// consoles, live dashboards, chat, and IoT control; scanners and exploit kits
// probe `/ws`, `/socket.io/`, `/cable`, etc. We complete the RFC 6455 opening
// handshake (computing the Sec-WebSocket-Accept response so a real client
// believes it connected), then read one or more client frames, unmask and
// capture the payload, and flag obviously hostile first messages (auth
// material, command-shaped JSON). After capturing we close with a normal
// close frame. No application logic is implemented — it is a capture surface.
type websocketH struct{}

func (h *websocketH) Name() string { return "websocket" }

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func (h *websocketH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 8192
	}
	head, _ := readHTTPHead(br, capN)
	res.Payload = head

	var key, path, proto, origin, userAgent string
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
		case strings.HasPrefix(lower, "sec-websocket-key:"):
			key = strings.TrimSpace(line[18:])
		case strings.HasPrefix(lower, "sec-websocket-protocol:"):
			proto = strings.TrimSpace(line[23:])
		case strings.HasPrefix(lower, "origin:"):
			origin = strings.TrimSpace(line[7:])
		case strings.HasPrefix(lower, "user-agent:"):
			userAgent = strings.TrimSpace(line[11:])
		}
	}
	res.Meta["path"] = path
	if origin != "" {
		res.Meta["origin"] = origin
	}
	if userAgent != "" {
		res.Meta["user_agent"] = userAgent
	}
	if proto != "" {
		res.Meta["ws_subprotocol"] = proto
	}

	// Not a WebSocket upgrade — answer like a plain server so a probe still
	// gets a believable reply, and record that it wasn't an upgrade.
	if key == "" {
		body := "Upgrade Required"
		resp := "HTTP/1.1 426 Upgrade Required\r\n" +
			"Content-Type: text/plain\r\n" +
			"Content-Length: " + intToStr(len(body)) + "\r\n" +
			"Connection: close\r\n\r\n" + body
		_, _ = conn.Write([]byte(resp))
		res.Meta["ws_upgrade"] = false
		res.BannerSent = "websocket 426"
		return res, nil
	}

	// Complete the handshake.
	accept := wsAcceptKey(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n"
	if proto != "" {
		// Echo the first offered subprotocol, as a real server commonly does.
		first := strings.TrimSpace(strings.Split(proto, ",")[0])
		resp += "Sec-WebSocket-Protocol: " + first + "\r\n"
	}
	resp += "\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.Meta["ws_upgrade"] = true
	res.BannerSent = "websocket 101"

	// Read up to a couple of client frames and capture their payloads.
	var msgs []string
	for i := 0; i < 4; i++ {
		payload, opcode, ok := readWSFrame(br, capN)
		if !ok {
			break
		}
		if opcode == 0x8 { // close
			break
		}
		if len(payload) > 0 {
			msgs = append(msgs, string(payload))
			classifyWSMessage(string(payload), &res)
		}
	}
	if len(msgs) > 0 {
		res.Meta["ws_messages"] = msgs
	}

	// Polite close frame (status 1000).
	_, _ = conn.Write([]byte{0x88, 0x02, 0x03, 0xe8})
	return res, nil
}

// wsAcceptKey computes the Sec-WebSocket-Accept value for a client key.
func wsAcceptKey(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// readWSFrame reads one (possibly masked) client frame, returning its unmasked
// payload and opcode. Bounded by cap. Only handles <=64KiB single frames,
// which is all a capture surface needs.
func readWSFrame(br *bufio.Reader, capN int) (payload []byte, opcode byte, ok bool) {
	b0, err := br.ReadByte()
	if err != nil {
		return nil, 0, false
	}
	opcode = b0 & 0x0f
	b1, err := br.ReadByte()
	if err != nil {
		return nil, 0, false
	}
	masked := b1&0x80 != 0
	ln := int(b1 & 0x7f)
	switch ln {
	case 126:
		hi, e1 := br.ReadByte()
		lo, e2 := br.ReadByte()
		if e1 != nil || e2 != nil {
			return nil, 0, false
		}
		ln = int(hi)<<8 | int(lo)
	case 127:
		// 8-byte length; we only honor the low 4 bytes and cap it.
		var n int
		for i := 0; i < 8; i++ {
			bb, e := br.ReadByte()
			if e != nil {
				return nil, 0, false
			}
			n = n<<8 | int(bb)
		}
		ln = n
	}
	if ln < 0 || ln > capN {
		ln = capN
	}
	var maskKey [4]byte
	if masked {
		for i := 0; i < 4; i++ {
			mk, e := br.ReadByte()
			if e != nil {
				return nil, 0, false
			}
			maskKey[i] = mk
		}
	}
	buf := make([]byte, ln)
	for i := 0; i < ln; i++ {
		bb, e := br.ReadByte()
		if e != nil {
			buf = buf[:i]
			break
		}
		if masked {
			bb ^= maskKey[i%4]
		}
		buf[i] = bb
	}
	return buf, opcode, true
}

// classifyWSMessage flags hostile-looking first messages: embedded
// credentials or command-shaped control payloads.
func classifyWSMessage(msg string, res *Result) {
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "password") || strings.Contains(low, "\"token\"") ||
		strings.Contains(low, "authorization") || strings.Contains(low, "apikey") ||
		strings.Contains(low, "api_key"):
		flagAnomaly(res, "ws-credential-material")
	}
	if strings.Contains(low, "cmd") || strings.Contains(low, "exec") ||
		strings.Contains(low, "/bin/") || strings.Contains(low, "system(") {
		flagAnomaly(res, "ws-command-payload")
	}
}
