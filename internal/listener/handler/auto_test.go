package handler

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestGuessProtocol(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte("GET / HTTP/1.1\r\n"), "http"},
		{[]byte("POST /x HTTP/1.0"), "http"},
		{[]byte("SSH-2.0-OpenSSH_9.2"), "ssh"},
		{[]byte{0x16, 0x03, 0x01, 0x00, 0x05}, "tls"},
		{[]byte{0x05, 0x01, 0x00}, "socks5"},
		{[]byte("hello world this is text"), "text"},
		{[]byte{0xff, 0xfe, 0x01, 0x99, 0x88}, "binary"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := guessProtocol(c.in); got != c.want {
			t.Errorf("guessProtocol(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestAutoTCPCapturesAndGuesses(t *testing.T) {
	res := runConn(t, &auto{}, "FOO bar baz\r\n")
	if res.Meta["protocol_guess"] != "text" {
		t.Errorf("protocol_guess = %v; want text", res.Meta["protocol_guess"])
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "unknown-protocol") {
		t.Errorf("unknown-protocol not flagged: %v", anoms)
	}
	if string(res.Payload) != "FOO bar baz\r\n" {
		t.Errorf("payload not captured: %q", res.Payload)
	}
}

func TestAutoUDPCapturesNeverReplies(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000}
	res, _ := (&autoUDP{}).Handle(context.Background(), []byte("SSH-2.0-x"), src, pc, config.Listener{})
	if res.Meta["protocol_guess"] != "ssh" {
		t.Errorf("protocol_guess = %v; want ssh", res.Meta["protocol_guess"])
	}
	if len(pc.written) != 0 {
		t.Errorf("UDP catch-all must never reply (reflection risk); wrote %d", len(pc.written))
	}
}

func TestAutoTCPBannerNudge(t *testing.T) {
	// With a configured banner and a client that speaks only after the
	// greeting, the banner is sent and the follow-up probe captured.
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: time.Second, Banner: "220 ready\r\n"}
	var res Result
	done := make(chan struct{})
	go func() { defer close(done); res, _ = (&auto{}).Handle(context.Background(), server, cfg) }()
	go func() {
		buf := make([]byte, 64)
		n, _ := client.Read(buf) // wait for the banner nudge
		if n > 0 {
			_, _ = client.Write([]byte("USER bob\r\n"))
		}
		_ = client.Close()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("auto handler did not return")
	}
	if res.BannerSent != "220 ready\r\n" {
		t.Errorf("banner nudge not sent: %q", res.BannerSent)
	}
}
