package handler

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/jitter"
)

// Explicit FTPS: AUTH TLS upgrades the control channel; FEAT advertises it; and
// USER/PASS are captured over the encrypted channel.
func TestFTPExplicitFTPS(t *testing.T) {
	h := &ftp{jit: jitter.New(0, 0), arch: &archetype.Profile{}, tlsMgr: maybeCertMgr(Deps{DataDir: t.TempDir()})}
	if h.tlsMgr == nil {
		t.Fatal("cert manager not built")
	}
	client, server := pipePair(t)
	cfg := config.Listener{ID: "ftp-1", ReadTimeout: 5 * time.Second, ReadBytes: 4096}
	resC := make(chan Result, 1)
	go func() { r, _ := h.Handle(context.Background(), server, cfg); resC <- r }()

	br := bufio.NewReader(client)
	mustLine(t, br, "220") // banner

	// FEAT must advertise AUTH TLS / SSL + PBSZ + PROT.
	_, _ = client.Write([]byte("FEAT\r\n"))
	feat := readUntilFTP(t, br, "211 ")
	for _, want := range []string{"AUTH TLS", "AUTH SSL", "PBSZ", "PROT"} {
		if !strings.Contains(feat, want) {
			t.Fatalf("FEAT did not advertise %q:\n%s", want, feat)
		}
	}

	// AUTH TLS -> 234, then handshake.
	_, _ = client.Write([]byte("AUTH TLS\r\n"))
	mustLine(t, br, "234")
	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, tc) }()

	// Over TLS: PBSZ/PROT then login with a default credential.
	_, _ = tc.Write([]byte("PBSZ 0\r\nPROT P\r\nUSER admin\r\nPASS admin\r\nQUIT\r\n"))
	r := <-resC

	if r.Meta["tls"] != true || r.Meta["ftps"] != true || r.Meta["ftps_auth"] != "TLS" {
		t.Errorf("FTPS upgrade not recorded: %v", r.Meta)
	}
	if strings.TrimSpace(toStr(r.Meta["user_line"])) != "admin" || strings.TrimSpace(toStr(r.Meta["pass_line"])) != "admin" {
		t.Errorf("creds not captured over TLS: user=%v pass=%v", r.Meta["user_line"], r.Meta["pass_line"])
	}
	if !containsStr(metaAnoms(r), "default-credential-attempt") {
		t.Errorf("default credential over FTPS not flagged: %v", metaAnoms(r))
	}
}

// Without a cert manager, AUTH TLS is refused (plaintext-only server).
func TestFTPNoTLSRefusesAuth(t *testing.T) {
	h := &ftp{jit: jitter.New(0, 0), arch: &archetype.Profile{}} // tlsMgr nil
	client, server := pipePair(t)
	cfg := config.Listener{ID: "ftp-2", ReadTimeout: 5 * time.Second, ReadBytes: 4096}
	resC := make(chan Result, 1)
	go func() { r, _ := h.Handle(context.Background(), server, cfg); resC <- r }()

	br := bufio.NewReader(client)
	mustLine(t, br, "220")
	_, _ = client.Write([]byte("AUTH TLS\r\n"))
	if line := mustLine(t, br, "502"); !strings.HasPrefix(line, "502") {
		t.Errorf("AUTH without TLS should be 502, got %q", line)
	}
	go func() { _, _ = io.Copy(io.Discard, br) }() // drain the 221 so Handle returns
	_, _ = client.Write([]byte("QUIT\r\n"))
	<-resC
}

func toStr(v any) string { s, _ := v.(string); return s }

func readUntilFTP(t *testing.T, br *bufio.Reader, endPrefix string) string {
	t.Helper()
	var b strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read FTP reply: %v", err)
		}
		b.WriteString(line)
		if strings.HasPrefix(line, endPrefix) {
			return b.String()
		}
	}
}
