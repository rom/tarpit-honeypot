package handler

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// smallSvcCfg gives the small-service handlers a positive read/write
// deadline; withTimeout(conn, 0) would set the deadline to "now" and
// every read/write would fail immediately.
func smallSvcCfg() config.Listener {
	return config.Listener{ReadTimeout: 2 * time.Second}
}

func TestEchoTCPBoundedEcho(t *testing.T) {
	client, server := loopbackPair(t)
	if _, err := client.Write([]byte("ABCDE")); err != nil {
		t.Fatal(err)
	}
	res, err := (&echoTCP{}).Handle(context.Background(), server, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["echoed_bytes"] != 5 {
		t.Errorf("echoed_bytes = %v; want 5", res.Meta["echoed_bytes"])
	}
	if !bytes.Equal(res.Payload, []byte("ABCDE")) {
		t.Errorf("captured payload = %q; want ABCDE", res.Payload)
	}
	buf := make([]byte, 16)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "ABCDE" {
		t.Errorf("client read %q; want ABCDE", got)
	}
}

func TestDiscardTCPNoReply(t *testing.T) {
	client, server := loopbackPair(t)
	if _, err := client.Write([]byte("drop me")); err != nil {
		t.Fatal(err)
	}
	res, err := (&discardTCP{}).Handle(context.Background(), server, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["discarded_bytes"] != 7 {
		t.Errorf("discarded_bytes = %v; want 7", res.Meta["discarded_bytes"])
	}
	if res.BannerSent != "" {
		t.Errorf("discard must not send a banner; got %q", res.BannerSent)
	}
	// Confirm the server never wrote anything back.
	_ = client.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 8)
	if n, err := client.Read(buf); err == nil {
		t.Errorf("discard replied with %d bytes; want none", n)
	}
}

func TestDaytimeTCP(t *testing.T) {
	client, server := loopbackPair(t)
	res, err := (&daytimeTCP{}).Handle(context.Background(), server, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	got := string(buf[:n])
	if got != res.BannerSent {
		t.Errorf("wire %q != BannerSent %q", got, res.BannerSent)
	}
	if !bytes.HasSuffix(buf[:n], []byte("\r\n")) {
		t.Errorf("daytime reply not CRLF-terminated: %q", got)
	}
}

func TestQOTDTCP(t *testing.T) {
	client, server := loopbackPair(t)
	if _, err := (&qotdTCP{}).Handle(context.Background(), server, smallSvcCfg()); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 256)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != qotdText {
		t.Errorf("qotd reply = %q; want the canned quote", got)
	}
}

func TestChargenTCPBounded(t *testing.T) {
	client, server := loopbackPair(t)
	if _, err := (&chargenTCP{}).Handle(context.Background(), server, smallSvcCfg()); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	// One bounded line: 72 chars + CRLF. Never the unbounded stream.
	if n != 74 {
		t.Errorf("chargen wrote %d bytes; want exactly 74 (bounded)", n)
	}
	// A second read must find no further data (the stream stopped).
	_ = client.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if n2, err := client.Read(buf); err == nil {
		t.Errorf("chargen kept streaming: %d more bytes (must be bounded)", n2)
	}
}

func TestTimeTCP(t *testing.T) {
	client, server := loopbackPair(t)
	res, err := (&timeTCP{}).Handle(context.Background(), server, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Payload) != 4 {
		t.Fatalf("rfc868 payload = %d bytes; want 4", len(res.Payload))
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 8)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Errorf("time reply = %d bytes; want 4", n)
	}
}

// ---- UDP: must never amplify ----

func TestEchoUDPNoAmplification(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000}
	in := []byte("0123456789")
	res, err := (&echoUDP{}).Handle(context.Background(), in, src, pc, config.Listener{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 reply; got %d", len(pc.written))
	}
	if len(pc.written[0]) > len(in) {
		t.Errorf("echo amplified: reply %d > request %d", len(pc.written[0]), len(in))
	}
	if res.Meta["echoed_bytes"] != len(in) {
		t.Errorf("echoed_bytes = %v; want %d", res.Meta["echoed_bytes"], len(in))
	}
}

func TestEchoUDPCapsLargeRequest(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000}
	in := bytes.Repeat([]byte("A"), 2000)
	if _, err := (&echoUDP{}).Handle(context.Background(), in, src, pc, config.Listener{}); err != nil {
		t.Fatal(err)
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 reply; got %d", len(pc.written))
	}
	if len(pc.written[0]) > 1024 {
		t.Errorf("echo reply not capped: %d bytes", len(pc.written[0]))
	}
}

func TestChargenUDPBoundedAndFlagged(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000}
	res, err := (&chargenUDP{}).Handle(context.Background(), []byte("x"), src, pc, config.Listener{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected exactly 1 bounded reply; got %d", len(pc.written))
	}
	if len(pc.written[0]) != 74 {
		t.Errorf("chargen UDP reply = %d bytes; want 74 (bounded)", len(pc.written[0]))
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	found := false
	for _, a := range anoms {
		if a == "udp-amplifier-probe" {
			found = true
		}
	}
	if !found {
		t.Errorf("chargen UDP probe not flagged as udp-amplifier-probe: %v", anoms)
	}
}

func TestDiscardUDPNoReply(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000}
	if _, err := (&discardUDP{}).Handle(context.Background(), []byte("drop"), src, pc, config.Listener{}); err != nil {
		t.Fatal(err)
	}
	if len(pc.written) != 0 {
		t.Errorf("discard UDP replied with %d datagrams; want 0", len(pc.written))
	}
}

func TestTimeUDPSingleReply(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000}
	if _, err := (&timeUDP{}).Handle(context.Background(), []byte("t"), src, pc, config.Listener{}); err != nil {
		t.Fatal(err)
	}
	if len(pc.written) != 1 || len(pc.written[0]) != 4 {
		t.Errorf("time UDP reply: %d datagrams, want 1 of 4 bytes", len(pc.written))
	}
}
