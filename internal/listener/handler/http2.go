package handler

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// HTTP/2 (h2c, prior-knowledge) capture with real HPACK decoding and
// multiplexed-stream reconstruction. The HTTP/1.x handler branches here when a
// connection opens with the h2c preface. Unlike the gRPC handler (which scans
// the compressed HEADERS bytes for a literal path), this decodes HPACK against
// a connection-scoped dynamic table and reassembles each stream's HEADERS +
// CONTINUATION + DATA frames into a full request — so we capture the real
// :method / :path / :authority and every header an attacker sends across
// multiplexed streams, plus HTTP/2-specific abuse (Rapid Reset, CONTINUATION
// flood). We answer SETTINGS + a minimal 200 per stream so clients proceed,
// then GOAWAY. Capture only.

// HTTP/2 frame types (RFC 9113 §6).
const (
	h2FrameData         = 0x0
	h2FrameHeaders      = 0x1
	h2FrameRSTStream    = 0x3
	h2FrameSettings     = 0x4
	h2FramePing         = 0x6
	h2FrameGoaway       = 0x7
	h2FrameContinuation = 0x9
	// Flags.
	h2FlagEndStream  = 0x1
	h2FlagAck        = 0x1 // SETTINGS / PING ACK (same bit as END_STREAM, different frames)
	h2FlagEndHeaders = 0x4
	h2FlagPadded     = 0x8
	h2FlagPriority   = 0x20
	// Abuse thresholds.
	h2MaxFrames      = 512
	h2RapidResetN    = 20 // RST_STREAM count -> CVE-2023-44487
	h2ContFloodN     = 40 // CONTINUATION count -> CVE-2024-27316
	h2MaxHeaderBlock = 1 << 20
)

// h2Stream accumulates one HTTP/2 stream's reconstructed request.
type h2Stream struct {
	headerBlock []byte // accumulated HEADERS + CONTINUATION fragments
	fields      []hpack.HeaderField
	bodyLen     int
	endHeaders  bool
	endStream   bool
	reset       bool
	recorded    bool
}

// captureHTTP2 drives the HTTP/2 connection after the preface has been
// consumed, recording reconstructed requests into res.Meta.
func captureHTTP2(conn net.Conn, br *bufio.Reader, cfg config.Listener, res *Result) {
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	res.Meta["http_version"] = "2.0"
	res.Meta["http2"] = true

	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 1 << 16
	}

	// Server preface: SETTINGS then SETTINGS ACK — a real server's opening.
	_, _ = conn.Write(append(h2Frame(h2FrameSettings, 0, 0, nil),
		h2Frame(h2FrameSettings, h2FlagAck, 0, nil)...))

	dec := hpack.NewDecoder(4096, nil)
	streams := map[uint32]*h2Stream{}
	var requests []map[string]any
	rstCount, contCount, dataFrames := 0, 0, 0

	total := 0
	for frames := 0; frames < h2MaxFrames && total < capN; frames++ {
		if cfg.ReadTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
		}
		ftype, flags, sid, payload, ok := readH2FrameFull(br, capN)
		if !ok {
			break
		}
		total += 9 + len(payload)

		switch ftype {
		case h2FrameHeaders:
			st := h2GetStream(streams, sid)
			block := h2StripHeadersPadding(payload, flags)
			st.appendBlock(block)
			if flags&h2FlagEndStream != 0 {
				st.endStream = true
			}
			if flags&h2FlagEndHeaders != 0 {
				st.decode(dec)
			}
		case h2FrameContinuation:
			contCount++
			if st := streams[sid]; st != nil && !st.endHeaders {
				st.appendBlock(payload)
				if flags&h2FlagEndHeaders != 0 {
					st.decode(dec)
				}
			}
		case h2FrameData:
			dataFrames++
			st := h2GetStream(streams, sid)
			st.bodyLen += len(payload)
			if flags&h2FlagEndStream != 0 {
				st.endStream = true
			}
		case h2FrameRSTStream:
			rstCount++
			if st := streams[sid]; st != nil {
				st.reset = true
			}
		case h2FrameSettings:
			if flags&h2FlagAck == 0 { // a settings (not ACK) — ack it
				_, _ = conn.Write(h2Frame(h2FrameSettings, h2FlagAck, 0, nil))
			}
		case h2FramePing:
			if flags&h2FlagAck == 0 && len(payload) == 8 { // PING -> PONG
				_, _ = conn.Write(h2Frame(h2FramePing, h2FlagAck, 0, payload))
			}
		case h2FrameGoaway:
			frames = h2MaxFrames // client is closing
		}

		// Emit + respond to any stream that just completed.
		for id, st := range streams {
			if st.recorded || !st.endHeaders || (!st.endStream && !st.reset) {
				continue
			}
			st.recorded = true
			if req := st.request(id); req != nil {
				requests = append(requests, req)
				if !st.reset {
					h2RespondOK(conn, id)
				}
			}
		}
	}

	res.Meta["http2_stream_count"] = len(streams)
	if dataFrames > 0 {
		res.Meta["http2_data_frames"] = dataFrames
	}
	if len(requests) > 0 {
		res.Meta["http2_requests"] = requests
		h2PromoteFirstRequest(res, requests[0])
	}
	if rstCount >= h2RapidResetN {
		res.Meta["http2_rst_count"] = rstCount
		flagAnomaly(res, "http2-rapid-reset") // CVE-2023-44487
	}
	if contCount >= h2ContFloodN {
		res.Meta["http2_continuation_count"] = contCount
		flagAnomaly(res, "http2-continuation-flood") // CVE-2024-27316
	}

	_, _ = conn.Write(h2Frame(h2FrameGoaway, 0, 0, []byte{0, 0, 0, 0, 0, 0, 0, 0}))
	res.BannerSent = "http2 (h2c) capture"
}

func (st *h2Stream) appendBlock(b []byte) {
	if len(st.headerBlock)+len(b) > h2MaxHeaderBlock {
		return
	}
	st.headerBlock = append(st.headerBlock, b...)
}

// decode HPACK-decodes the accumulated header block against the connection's
// dynamic table (shared across streams, per RFC 7541).
func (st *h2Stream) decode(dec *hpack.Decoder) {
	st.endHeaders = true
	if len(st.headerBlock) == 0 {
		return
	}
	fields, err := dec.DecodeFull(st.headerBlock)
	if err == nil {
		st.fields = fields
	}
	st.headerBlock = nil
}

// request builds the captured request map for a completed stream, or nil if it
// carried no usable headers.
func (st *h2Stream) request(id uint32) map[string]any {
	if len(st.fields) == 0 {
		return nil
	}
	var method, path, authority, scheme, ua string
	headers := map[string]string{}
	for _, f := range st.fields {
		switch f.Name {
		case ":method":
			method = f.Value
		case ":path":
			path = f.Value
		case ":authority":
			authority = f.Value
		case ":scheme":
			scheme = f.Value
		default:
			if len(headers) < 64 {
				headers[f.Name] = f.Value
			}
			if strings.EqualFold(f.Name, "user-agent") {
				ua = f.Value
			}
		}
	}
	req := map[string]any{
		"stream_id":    id,
		"method":       method,
		"path":         path,
		"authority":    authority,
		"scheme":       scheme,
		"header_count": len(st.fields),
		"body_len":     st.bodyLen,
	}
	if len(headers) > 0 {
		req["headers"] = headers
	}
	if ua != "" {
		req["user_agent"] = ua
	}
	if st.reset {
		req["reset"] = true
	}
	return req
}

// h2PromoteFirstRequest copies the first reconstructed request's fields up to
// the flat meta keys the rest of the pipeline (UI, profiles, tool fp) reads.
func h2PromoteFirstRequest(res *Result, req map[string]any) {
	method, _ := req["method"].(string)
	path, _ := req["path"].(string)
	authority, _ := req["authority"].(string)
	ua, _ := req["user_agent"].(string)
	if method != "" || path != "" {
		res.Meta["request_line"] = strings.TrimSpace(method+" "+path) + " HTTP/2.0"
		res.Meta["http_method"] = method
		res.Meta["http_uri"] = path
	}
	if authority != "" {
		res.Meta["host"] = authority
	}
	if ua != "" {
		res.Meta["user_agent"] = ua
	}
	verdict := toolfp.IdentifyHTTP(toolfp.HTTPSignals{Method: method, Path: path, UserAgent: ua})
	if len(verdict.Tools) > 0 {
		res.Meta["tools"] = verdict.Tools
		flagAnomaly(res, "tool:"+verdict.Tools[0])
		if verdict.Confidence > 0 {
			res.Meta["tool_confidence"] = verdict.Confidence
		}
	}
}

// h2GetStream returns (creating if needed) the stream state for id.
func h2GetStream(m map[uint32]*h2Stream, id uint32) *h2Stream {
	st := m[id]
	if st == nil {
		st = &h2Stream{}
		m[id] = st
	}
	return st
}

// h2StripHeadersPadding removes the optional pad-length byte / padding and the
// 5-byte priority field from a HEADERS payload, returning the header-block
// fragment.
func h2StripHeadersPadding(payload []byte, flags byte) []byte {
	b := payload
	padLen := 0
	if flags&h2FlagPadded != 0 && len(b) > 0 {
		padLen = int(b[0])
		b = b[1:]
	}
	if flags&h2FlagPriority != 0 && len(b) >= 5 {
		b = b[5:] // stream dependency (4) + weight (1)
	}
	if padLen > 0 && padLen <= len(b) {
		b = b[:len(b)-padLen]
	}
	return b
}

// readH2FrameFull reads a full HTTP/2 frame (header + payload), returning its
// type, flags, stream id, and payload. Payload length is bounded by capN.
func readH2FrameFull(br *bufio.Reader, capN int) (ftype, flags byte, sid uint32, payload []byte, ok bool) {
	hdr := make([]byte, 9)
	if n, _ := io.ReadFull(br, hdr); n < 9 {
		return 0, 0, 0, nil, false
	}
	length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	ftype = hdr[3]
	flags = hdr[4]
	sid = binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff
	if length < 0 {
		return 0, 0, 0, nil, false
	}
	if length > capN {
		length = capN
	}
	payload = make([]byte, length)
	n, _ := io.ReadFull(br, payload)
	return ftype, flags, sid, payload[:n], true
}

// h2RespondOK sends a minimal HTTP/2 response on stream id: a HEADERS frame
// (:status 200, content-length 2) + a DATA frame ("ok") with END_STREAM, so a
// real client sees a completed exchange.
func h2RespondOK(conn net.Conn, id uint32) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "text/plain"})
	_ = enc.WriteField(hpack.HeaderField{Name: "content-length", Value: "2"})
	headers := h2Frame(h2FrameHeaders, h2FlagEndHeaders, id, buf.Bytes())
	data := h2Frame(h2FrameData, h2FlagEndStream, id, []byte("ok"))
	_, _ = conn.Write(append(headers, data...))
}
