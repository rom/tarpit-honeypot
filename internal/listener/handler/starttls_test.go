package handler

// Tests for in-protocol STARTTLS: SMTP (25), IMAP (143) and POP3 (110) advertise
// STARTTLS/STLS, upgrade the live connection to TLS, and keep capturing
// credentials over the encrypted channel.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestSMTPStartTLS(t *testing.T) {
	h := newSMTPRecv(Deps{DataDir: t.TempDir()})
	client, server := pipePair(t)
	cfg := config.Listener{ID: "smtp-1", ReadTimeout: 5 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := h.Handle(context.Background(), server, cfg); resC <- r }()

	br := bufio.NewReader(client)
	mustLine(t, br, "220") // greeting
	_, _ = client.Write([]byte("EHLO probe\r\n"))
	ehlo := readSMTPEHLO(t, br)
	if !strings.Contains(ehlo, "STARTTLS") {
		t.Fatalf("EHLO did not advertise STARTTLS:\n%s", ehlo)
	}
	_, _ = client.Write([]byte("STARTTLS\r\n"))
	if r := mustLine(t, br, "220"); !strings.Contains(r, "220") {
		t.Fatalf("STARTTLS reply = %q; want 220", r)
	}
	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, tc) }()
	authPlain := base64.StdEncoding.EncodeToString([]byte("\x00root\x00root"))
	_, _ = tc.Write([]byte("EHLO probe\r\nAUTH PLAIN " + authPlain + "\r\nQUIT\r\n"))
	r := <-resC
	if r.Meta["starttls"] != true || r.Meta["tls"] != true {
		t.Errorf("SMTP did not record the TLS upgrade: %v", r.Meta)
	}
	if r.Meta["auth_user"] != "root" || r.Meta["auth_pass"] != "root" {
		t.Errorf("SMTP did not capture creds over TLS: %v / %v", r.Meta["auth_user"], r.Meta["auth_pass"])
	}
	if !containsStr(metaAnoms(r), "default-credential-attempt") {
		t.Errorf("SMTP default credential over TLS not flagged: %v", metaAnoms(r))
	}
}

func TestIMAPStartTLSUpgrade(t *testing.T) {
	h := newIMAP(Deps{DataDir: t.TempDir()})
	client, server := pipePair(t)
	cfg := config.Listener{ID: "imap-1", ReadTimeout: 5 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := h.Handle(context.Background(), server, cfg); resC <- r }()

	br := bufio.NewReader(client)
	greet := mustLine(t, br, "* OK")
	if !strings.Contains(greet, "STARTTLS") {
		t.Fatalf("IMAP greeting did not advertise STARTTLS: %q", greet)
	}
	_, _ = client.Write([]byte("a1 STARTTLS\r\n"))
	if r := mustLine(t, br, "a1 OK"); !strings.Contains(r, "OK") {
		t.Fatalf("STARTTLS reply = %q; want OK", r)
	}
	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, tc) }()
	_, _ = tc.Write([]byte("a2 LOGIN root root\r\na3 LOGOUT\r\n"))
	r := <-resC
	if r.Meta["starttls"] != true || r.Meta["tls"] != true {
		t.Errorf("IMAP did not record the TLS upgrade: %v", r.Meta)
	}
	if r.Meta["auth_user"] != "root" {
		t.Errorf("IMAP did not capture user over TLS: %v", r.Meta["auth_user"])
	}
	if !containsStr(metaAnoms(r), "default-credential-attempt") {
		t.Errorf("IMAP default credential over TLS not flagged: %v", metaAnoms(r))
	}
}

func TestPOP3StartTLSUpgrade(t *testing.T) {
	h := newPOP3(Deps{DataDir: t.TempDir()})
	client, server := pipePair(t)
	cfg := config.Listener{ID: "pop3-1", ReadTimeout: 5 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := h.Handle(context.Background(), server, cfg); resC <- r }()

	br := bufio.NewReader(client)
	mustLine(t, br, "+OK") // greeting
	_, _ = client.Write([]byte("CAPA\r\n"))
	capa := readUntilPOP3Dot(t, br)
	if !strings.Contains(capa, "STLS") {
		t.Fatalf("CAPA did not advertise STLS:\n%s", capa)
	}
	_, _ = client.Write([]byte("STLS\r\n"))
	if r := mustLine(t, br, "+OK"); !strings.Contains(r, "+OK") {
		t.Fatalf("STLS reply = %q; want +OK", r)
	}
	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, tc) }()
	_, _ = tc.Write([]byte("USER root\r\nPASS root\r\nQUIT\r\n"))
	r := <-resC
	if r.Meta["starttls"] != true || r.Meta["tls"] != true {
		t.Errorf("POP3 did not record the TLS upgrade: %v", r.Meta)
	}
	if r.Meta["auth_user"] != "root" || r.Meta["auth_pass"] != "root" {
		t.Errorf("POP3 did not capture creds over TLS: %v / %v", r.Meta["auth_user"], r.Meta["auth_pass"])
	}
	if !containsStr(metaAnoms(r), "default-credential-attempt") {
		t.Errorf("POP3 default credential over TLS not flagged: %v", metaAnoms(r))
	}
}

// TestImplicitTLSNoStartTLS confirms the implicit-TLS variant (imaps) does not
// re-advertise STARTTLS inside the already-encrypted channel.
func TestImplicitTLSNoStartTLS(t *testing.T) {
	h, err := newTLSWrap("imap", "imaps", Deps{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	client, server := pipePair(t)
	cfg := config.Listener{ID: "imaps-1", ReadTimeout: 5 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := h.Handle(context.Background(), server, cfg); resC <- r }()

	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	br := bufio.NewReader(tc)
	greet, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.Copy(io.Discard, tc) }()
	_, _ = tc.Write([]byte("a1 LOGOUT\r\n"))
	<-resC
	if strings.Contains(greet, "STARTTLS") {
		t.Errorf("imaps re-advertised STARTTLS inside TLS: %q", greet)
	}
}

// --- line helpers ----------------------------------------------------------

func mustLine(t *testing.T, br *bufio.Reader, wantPrefix string) string {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read line (want %q): %v", wantPrefix, err)
	}
	if !strings.HasPrefix(line, wantPrefix) {
		t.Fatalf("line = %q; want prefix %q", line, wantPrefix)
	}
	return line
}

func readSMTPEHLO(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	var b strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read EHLO line: %v", err)
		}
		b.WriteString(line)
		// last line of a multiline reply uses "250 " (space) after the code.
		if strings.HasPrefix(line, "250 ") {
			return b.String()
		}
	}
}

func readUntilPOP3Dot(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	var b strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CAPA line: %v", err)
		}
		if line == ".\r\n" || line == ".\n" {
			return b.String()
		}
		b.WriteString(line)
	}
}
