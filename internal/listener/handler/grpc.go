package handler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// grpcH emulates a gRPC server enough to look alive to a scanner and capture
// the service/method an attacker tries to call. gRPC rides on HTTP/2, so a
// real client opens with the HTTP/2 connection preface
// ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") followed by a SETTINGS frame, then a
// HEADERS frame carrying ":path: /package.Service/Method".
//
// Implementing a full HTTP/2 + HPACK stack is overkill for a honeypot, so we:
//   - recognize the preface (the unmistakable gRPC/h2c tell),
//   - reply with our own SETTINGS frame + SETTINGS ACK (a real server's first
//     bytes), so the client proceeds and sends its request,
//   - read the following frames and capture the HEADERS block bytes and any
//     printable ASCII run that looks like a gRPC path (/svc/method),
//   - flag reflection / server-listing probes (grpc.reflection, ServerReflectionInfo).
//
// We do not decode HPACK (it is dynamic-table stateful); instead we scan the
// HEADERS payload for the literal path, which gRPC clients commonly send as a
// literal-without-indexing field. Good enough to attribute the probe.
type grpcH struct{}

func (h *grpcH) Name() string { return "grpc" }

var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

func (h *grpcH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 16384
	}

	// Read the connection preface (24 bytes).
	preface := make([]byte, len(http2Preface))
	n, _ := io.ReadFull(br, preface)
	preface = preface[:n]
	res.Payload = append([]byte{}, preface...)
	if !bytes.Equal(preface, http2Preface) {
		// Not an HTTP/2 client. Capture what we got and bail with a GOAWAY-ish
		// silence; many h2c probes still register the attempt.
		res.Meta["grpc_preface"] = false
		res.BannerSent = "grpc no-preface"
		return res, nil
	}
	res.Meta["grpc_preface"] = true

	// Send our SETTINGS frame (empty) then a SETTINGS ACK — a believable
	// server opening. Frame header: length(3) type(1) flags(1) streamID(4).
	settings := h2Frame(0x4, 0x0, 0, nil)    // SETTINGS, empty
	settingsAck := h2Frame(0x4, 0x1, 0, nil) // SETTINGS, ACK flag
	if _, err := conn.Write(append(settings, settingsAck...)); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}

	// Read subsequent frames; capture HEADERS payloads and look for the path.
	var totalRead int
	var paths []string
	for totalRead < capN {
		ftype, payload, ok := readH2Frame(br, capN-totalRead)
		if !ok {
			break
		}
		totalRead += len(payload) + 9
		if ftype == 0x1 { // HEADERS
			if p := scanGRPCPath(payload); p != "" {
				paths = append(paths, p)
			}
		}
		if ftype == 0x0 && len(payload) > 5 {
			// DATA frame: the length-prefixed gRPC message body. Capture a
			// bounded copy for the SIEM.
			res.Meta["grpc_data_len"] = len(payload)
		}
	}
	if len(paths) > 0 {
		res.Meta["grpc_methods"] = paths
		for _, p := range paths {
			low := bytes.ToLower([]byte(p))
			if bytes.Contains(low, []byte("reflection")) ||
				bytes.Contains(low, []byte("serverreflectioninfo")) {
				flagAnomaly(&res, "grpc-reflection-probe")
			}
		}
	}

	// Close politely with a GOAWAY (lastStreamID 0, NO_ERROR).
	goaway := h2Frame(0x7, 0x0, 0, []byte{0, 0, 0, 0, 0, 0, 0, 0})
	_, _ = conn.Write(goaway)
	res.BannerSent = "grpc h2"
	return res, nil
}

// h2Frame builds an HTTP/2 frame: 24-bit length, 8-bit type, 8-bit flags,
// 31-bit stream id, then payload.
func h2Frame(ftype, flags byte, streamID uint32, payload []byte) []byte {
	out := make([]byte, 9+len(payload))
	out[0] = byte(len(payload) >> 16)
	out[1] = byte(len(payload) >> 8)
	out[2] = byte(len(payload))
	out[3] = ftype
	out[4] = flags
	binary.BigEndian.PutUint32(out[5:9], streamID&0x7fffffff)
	copy(out[9:], payload)
	return out
}

// readH2Frame reads one frame header + payload (payload bounded by cap).
func readH2Frame(br *bufio.Reader, capN int) (ftype byte, payload []byte, ok bool) {
	hdr := make([]byte, 9)
	if n, _ := io.ReadFull(br, hdr); n < 9 {
		return 0, nil, false
	}
	length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	ftype = hdr[3]
	if length < 0 {
		return 0, nil, false
	}
	if length > capN {
		length = capN
	}
	payload = make([]byte, length)
	n, _ := io.ReadFull(br, payload)
	return ftype, payload[:n], true
}

// scanGRPCPath extracts a printable "/package.Service/Method" run from a HEADERS
// payload without decoding HPACK. gRPC paths are sent as literal header values,
// so the ASCII substring is present even in the compressed block.
func scanGRPCPath(headers []byte) string {
	best := ""
	cur := make([]byte, 0, 64)
	flush := func() {
		s := string(cur)
		if len(s) > len(best) && len(s) >= 3 && s[0] == '/' &&
			strings.Count(s, "/") >= 2 {
			best = s
		}
		cur = cur[:0]
	}
	for _, b := range headers {
		// path-legal printable bytes
		if b == '/' || b == '.' || b == '_' || b == '-' ||
			(b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') {
			cur = append(cur, b)
			if len(cur) > 200 {
				flush()
			}
		} else {
			flush()
		}
	}
	flush()
	return best
}
