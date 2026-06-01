package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestWebSocketHandshakeAccept(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "websocket", ReadTimeout: time.Second}
	resCh := make(chan Result, 1)
	go func() {
		res, _ := (&websocketH{}).Handle(context.Background(), server, cfg)
		resCh <- res
	}()
	// dGhlIHNhbXBsZSBub25jZQ== is the RFC 6455 example key; its accept value
	// is the well-known s3pPLMBiTxaQ9kYGzzhZRbK+xOo=.
	req := "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	_, _ = client.Write([]byte(req))
	buf := make([]byte, 512)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	resp := string(buf[:n])
	client.Close()
	<-resCh
	if !strings.HasPrefix(resp, "HTTP/1.1 101") {
		t.Fatalf("expected 101 Switching Protocols, got %q", resp[:min2(40, len(resp))])
	}
	if !strings.Contains(resp, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") {
		t.Errorf("wrong/absent accept key in:\n%s", resp)
	}
}

func TestWebSocketAcceptKeyKnownVector(t *testing.T) {
	if got := wsAcceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Errorf("wsAcceptKey = %q, want s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", got)
	}
}

func TestWebSocketCapturesMaskedMessage(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "websocket", ReadTimeout: time.Second}
	resCh := make(chan Result, 1)
	go func() {
		res, _ := (&websocketH{}).Handle(context.Background(), server, cfg)
		resCh <- res
	}()
	req := "GET /cable HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	_, _ = client.Write([]byte(req))
	// Read the 101 response so the handler proceeds to frame reading.
	buf := make([]byte, 512)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = client.Read(buf)

	// Send a masked text frame containing credential-shaped JSON.
	msg := []byte(`{"password":"hunter2","cmd":"id"}`)
	frame := []byte{0x81, byte(0x80 | len(msg)), 0x01, 0x02, 0x03, 0x04}
	for i, b := range msg {
		frame = append(frame, b^[]byte{0x01, 0x02, 0x03, 0x04}[i%4])
	}
	_, _ = client.Write(frame)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = client.Read(buf) // close frame
	client.Close()
	res := <-resCh

	msgs, _ := res.Meta["ws_messages"].([]string)
	if len(msgs) == 0 || !strings.Contains(msgs[0], "hunter2") {
		t.Fatalf("masked message not captured: %v", res.Meta["ws_messages"])
	}
	if !hasAnomaly(res, "ws-credential-material") {
		t.Errorf("credential material not flagged: %v", anomaliesOf(res))
	}
	if !hasAnomaly(res, "ws-command-payload") {
		t.Errorf("command payload not flagged: %v", anomaliesOf(res))
	}
}

func TestWebSocketNonUpgrade(t *testing.T) {
	resp, res := roundTrip(t, &websocketH{}, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 426") {
		t.Errorf("expected 426 for non-upgrade, got %q", resp[:min2(30, len(resp))])
	}
	if res.Meta["ws_upgrade"] != false {
		t.Errorf("ws_upgrade should be false")
	}
}

func TestGRPCPrefaceAndMethodCapture(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "grpc", ReadTimeout: time.Second}
	resCh := make(chan Result, 1)
	go func() {
		res, _ := (&grpcH{}).Handle(context.Background(), server, cfg)
		resCh <- res
	}()
	// Send the HTTP/2 preface + a SETTINGS frame + a HEADERS frame whose
	// payload contains a literal gRPC path.
	out := append([]byte{}, http2Preface...)
	out = append(out, h2Frame(0x4, 0x0, 0, nil)...) // client SETTINGS
	path := []byte("/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo")
	out = append(out, h2Frame(0x1, 0x4, 1, path)...) // HEADERS (END_HEADERS)
	_, _ = client.Write(out)

	buf := make([]byte, 256)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	client.Close()
	res := <-resCh

	if n < 9 {
		t.Fatalf("expected server SETTINGS frame, got %d bytes", n)
	}
	if res.Meta["grpc_preface"] != true {
		t.Fatalf("preface not recognized: %v", res.Meta)
	}
	methods, _ := res.Meta["grpc_methods"].([]string)
	found := false
	for _, m := range methods {
		if strings.Contains(m, "ServerReflection") {
			found = true
		}
	}
	if !found {
		t.Errorf("gRPC method path not captured: %v", methods)
	}
	if !hasAnomaly(res, "grpc-reflection-probe") {
		t.Errorf("reflection probe not flagged: %v", anomaliesOf(res))
	}
}

func TestGRPCNonPreface(t *testing.T) {
	_, res := roundTrip(t, &grpcH{}, "GET / HTTP/1.1\r\n\r\n")
	if res.Meta["grpc_preface"] != false {
		t.Errorf("non-h2 client should report grpc_preface=false, got %v", res.Meta["grpc_preface"])
	}
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}
