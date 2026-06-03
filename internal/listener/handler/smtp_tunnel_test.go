package handler

// Confirms that the plaintext SMTP payload transferred INSIDE the TLS tunnel
// (post-STARTTLS on 25/587, or implicit TLS on 465) is captured into
// res.Payload — not just the command verbs, but the DATA message body too.

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestSMTPTunnelPayloadCaptured(t *testing.T) {
	h := newSMTPRecv(Deps{DataDir: t.TempDir()})
	client, server := pipePair(t)
	cfg := config.Listener{ID: "smtp-1", ReadTimeout: 5 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := h.Handle(context.Background(), server, cfg); resC <- r }()

	br := bufio.NewReader(client)
	mustLine(t, br, "220")
	_, _ = client.Write([]byte("EHLO probe\r\n"))
	_ = readSMTPEHLO(t, br)
	_, _ = client.Write([]byte("STARTTLS\r\n"))
	mustLine(t, br, "220")
	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, tc) }()

	// Send a full message over the encrypted channel.
	secret := "X-Exfil: SECRET-TUNNEL-BODY-7788"
	_, _ = tc.Write([]byte("EHLO probe\r\nMAIL FROM:<a@evil.test>\r\nRCPT TO:<v@corp.test>\r\n" +
		"DATA\r\nSubject: hi\r\n" + secret + "\r\n.\r\nQUIT\r\n"))
	r := <-resC

	if r.Meta["tls"] != true {
		t.Fatalf("TLS upgrade not recorded: %v", r.Meta)
	}
	payload := string(r.Payload)
	// The decrypted command verbs AND the message body must be in the payload.
	for _, want := range []string{"MAIL FROM:<a@evil.test>", "DATA", secret} {
		if !strings.Contains(payload, want) {
			t.Errorf("in-tunnel payload missing %q; payload=%q", want, payload)
		}
	}
}
