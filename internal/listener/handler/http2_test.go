package handler

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// h2EncodeHeaders HPACK-encodes a list of (name,value) header pairs.
func h2EncodeHeaders(pairs ...[2]string) []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, p := range pairs {
		_ = enc.WriteField(hpack.HeaderField{Name: p[0], Value: p[1]})
	}
	return buf.Bytes()
}

// runHTTP2 drives the http handler with an h2c preface plus the given frames,
// draining server output, and returns the captured Result.
func runHTTP2(t *testing.T, frames []byte) Result {
	t.Helper()
	srv, cli := net.Pipe()
	resCh := make(chan Result, 1)
	go func() {
		r, _ := serveHTTP(srv, config.Listener{ReadTimeout: 2 * time.Second, ReadBytes: 1 << 16}, nil, nil, nil, false)
		resCh <- r
	}()
	go func() { _, _ = io.Copy(io.Discard, cli) }() // drain server SETTINGS/responses

	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := cli.Write(http2Preface); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	if _, err := cli.Write(frames); err != nil {
		t.Fatalf("write frames: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	_ = cli.Close()
	select {
	case r := <-resCh:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not return")
		return Result{}
	}
}

func TestHTTP2CaptureSingleStream(t *testing.T) {
	hdrs := h2EncodeHeaders(
		[2]string{":method", "GET"},
		[2]string{":path", "/admin/../../etc/passwd"},
		[2]string{":scheme", "http"},
		[2]string{":authority", "victim.example"},
		[2]string{"user-agent", "sqlmap/1.7.2"},
	)
	frames := append(h2Frame(h2FrameSettings, 0, 0, nil),
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, hdrs)...)

	res := runHTTP2(t, frames)
	if res.Meta["http2"] != true {
		t.Fatalf("http2 flag not set: %v", res.Meta)
	}
	reqs, ok := res.Meta["http2_requests"].([]map[string]any)
	if !ok || len(reqs) != 1 {
		t.Fatalf("http2_requests = %v", res.Meta["http2_requests"])
	}
	if reqs[0]["method"] != "GET" || reqs[0]["path"] != "/admin/../../etc/passwd" {
		t.Errorf("decoded request wrong: %v", reqs[0])
	}
	if res.Meta["http_uri"] != "/admin/../../etc/passwd" {
		t.Errorf("http_uri not promoted: %v", res.Meta["http_uri"])
	}
	if res.Meta["host"] != "victim.example" {
		t.Errorf("host not promoted: %v", res.Meta["host"])
	}
	// HPACK-decoded UA should drive tool fingerprinting.
	if tools, _ := res.Meta["tools"].([]string); len(tools) == 0 {
		t.Errorf("expected a tool match from sqlmap UA; meta=%v", res.Meta["tools"])
	}
}

func TestHTTP2MultiplexedStreams(t *testing.T) {
	// Two interleaved streams (1 and 3), each a separate request. HPACK state
	// is shared across them via the connection decoder.
	s1 := h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1,
		h2EncodeHeaders([2]string{":method", "GET"}, [2]string{":path", "/one"}))
	s3 := h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 3,
		h2EncodeHeaders([2]string{":method", "POST"}, [2]string{":path", "/two"}))
	res := runHTTP2(t, append(append(h2Frame(h2FrameSettings, 0, 0, nil), s1...), s3...))

	reqs, _ := res.Meta["http2_requests"].([]map[string]any)
	if len(reqs) != 2 {
		t.Fatalf("expected 2 reconstructed streams, got %d: %v", len(reqs), reqs)
	}
	paths := map[string]bool{}
	for _, r := range reqs {
		paths[r["path"].(string)] = true
	}
	if !paths["/one"] || !paths["/two"] {
		t.Errorf("multiplexed paths missing: %v", paths)
	}
}

func TestHTTP2ContinuationSplitHeaders(t *testing.T) {
	// Split one header block across HEADERS (no END_HEADERS) + CONTINUATION.
	full := h2EncodeHeaders(
		[2]string{":method", "GET"},
		[2]string{":path", "/split"},
		[2]string{"x-custom", "value"},
	)
	half := len(full) / 2
	h := h2Frame(h2FrameHeaders, h2FlagEndStream, 1, full[:half])       // no END_HEADERS
	c := h2Frame(h2FrameContinuation, h2FlagEndHeaders, 1, full[half:]) // END_HEADERS
	res := runHTTP2(t, append(append(h2Frame(h2FrameSettings, 0, 0, nil), h...), c...))

	reqs, _ := res.Meta["http2_requests"].([]map[string]any)
	if len(reqs) != 1 || reqs[0]["path"] != "/split" {
		t.Fatalf("continuation-split header not reassembled: %v", reqs)
	}
}

func TestHTTP2RapidResetDetected(t *testing.T) {
	var frames []byte
	frames = append(frames, h2Frame(h2FrameSettings, 0, 0, nil)...)
	for i := uint32(0); i < 30; i++ {
		sid := 1 + i*2
		frames = append(frames, h2Frame(h2FrameHeaders, h2FlagEndHeaders, sid,
			h2EncodeHeaders([2]string{":method", "GET"}, [2]string{":path", "/x"}))...)
		frames = append(frames, h2Frame(h2FrameRSTStream, 0, sid, []byte{0, 0, 0, 8})...)
	}
	res := runHTTP2(t, frames)
	if !hasAnom(res, "http2-rapid-reset") {
		t.Errorf("rapid reset not flagged; rst=%v", res.Meta["http2_rst_count"])
	}
}

func TestHTTP2StripsPaddingAndPriority(t *testing.T) {
	hb := h2EncodeHeaders([2]string{":method", "GET"}, [2]string{":path", "/padded"})
	// Build a padded + priority HEADERS payload manually.
	payload := []byte{4}                      // pad length = 4
	payload = append(payload, 0, 0, 0, 0, 15) // priority: dep(4) + weight(1)
	payload = append(payload, hb...)
	payload = append(payload, 0, 0, 0, 0) // 4 padding bytes
	frame := h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream|h2FlagPadded|h2FlagPriority, 1, payload)
	res := runHTTP2(t, append(h2Frame(h2FrameSettings, 0, 0, nil), frame...))
	reqs, _ := res.Meta["http2_requests"].([]map[string]any)
	if len(reqs) != 1 || reqs[0]["path"] != "/padded" {
		t.Fatalf("padded/priority HEADERS not parsed: %v", reqs)
	}
}
