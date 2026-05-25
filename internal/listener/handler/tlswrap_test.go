package handler

// Tests for the TLS-realism batch: the implicit-TLS wrapper (imaps/pop3s/mqtts/
// …) and the PostgreSQL SSLRequest upgrade. Each drives a real crypto/tls
// client over the in-memory pipe so the handshake is genuinely exercised.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestTLSWrapServerFirst(t *testing.T) {
	for _, tc := range []struct {
		inner, name, greet string
	}{
		{"imap", "imaps", "* OK"},
		{"pop3", "pop3s", "+OK"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := newTLSWrap(tc.inner, tc.name, Deps{DataDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			if h.Name() != tc.name {
				t.Errorf("Name() = %q; want %q", h.Name(), tc.name)
			}
			client, server := pipePair(t)
			cfg := config.Listener{ID: tc.name + "-1", ReadTimeout: 5 * time.Second}
			resC := make(chan Result, 1)
			go func() { r, _ := h.Handle(context.Background(), server, cfg); resC <- r }()

			tc2 := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
			br := bufio.NewReader(tc2)
			greet, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("read greeting over TLS: %v", err)
			}
			_ = tc2.Close()
			r := <-resC
			if !strings.Contains(greet, tc.greet) {
				t.Errorf("%s greeting over TLS = %q; want %q", tc.name, greet, tc.greet)
			}
			if r.Meta["tls"] != true {
				t.Errorf("%s did not mark tls in meta: %v", tc.name, r.Meta)
			}
			if _, ok := r.Meta["tls_version"]; !ok {
				t.Errorf("%s missing tls_version", tc.name)
			}
			if _, ok := r.Meta["ja3"]; !ok {
				t.Errorf("%s missing ja3 (ClientHello fingerprint)", tc.name)
			}
		})
	}
}

func TestTLSWrapMQTTS(t *testing.T) {
	h, err := newTLSWrap("mqtt", "mqtts", Deps{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	client, server := pipePair(t)
	cfg := config.Listener{ID: "mqtts-1", ReadTimeout: 5 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := h.Handle(context.Background(), server, cfg); resC <- r }()

	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil { // client-first protocol: drive the handshake first
		t.Fatalf("tls handshake: %v", err)
	}
	_, _ = tc.Write(mqttConnectWithCreds("iot", "iot"))
	ack := make([]byte, 4)
	if _, err := io.ReadFull(tc, ack); err != nil {
		t.Fatalf("read CONNACK over TLS: %v", err)
	}
	_ = tc.Close()
	r := <-resC
	if ack[0] != 0x20 {
		t.Errorf("CONNACK first byte = %#x; want 0x20", ack[0])
	}
	if r.Meta["tls"] != true || r.Meta["username"] != "iot" {
		t.Errorf("mqtts meta wrong: %v", r.Meta)
	}
}

func TestPostgresSSLUpgrade(t *testing.T) {
	p := newPostgres(Deps{DataDir: t.TempDir()})
	if p.tlsMgr == nil {
		t.Fatal("newPostgres should have a cert manager with a data dir")
	}
	client, server := pipePair(t)
	cfg := config.Listener{ID: "pg-1", ReadTimeout: 5 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := p.Handle(context.Background(), server, cfg); resC <- r }()

	// SSLRequest: length=8, code 0x04D2162F.
	_, _ = client.Write([]byte{0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F})
	sb := make([]byte, 1)
	if _, err := io.ReadFull(client, sb); err != nil || sb[0] != 'S' {
		t.Fatalf("SSLRequest reply = %q (err %v); want 'S'", sb, err)
	}
	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	// Drain the server continuously: a TLS 1.3 server writes a session ticket
	// right after the handshake, which over an unbuffered pipe blocks until the
	// client reads it (a real socket buffers it). This also consumes the 'R'
	// auth request + the FATAL response.
	go func() { _, _ = io.Copy(io.Discard, tc) }()
	// StartupMessage then the cleartext password the server will ask for.
	_, _ = tc.Write(pgStartup("dbadmin"))
	_, _ = tc.Write(pgPassword("s3cr3t"))
	r := <-resC
	// No tc.Close() here: the handler has already returned, so its side is no
	// longer reading and a TLS close_notify write would block on the unbuffered
	// pipe; pipePair's cleanup closes the raw ends and unblocks the drainer.
	if r.Meta["tls"] != true {
		t.Errorf("postgres did not upgrade to TLS: %v", r.Meta)
	}
	if r.Meta["password"] != "s3cr3t" {
		t.Errorf("postgres did not capture password over TLS: %v", r.Meta["password"])
	}
}

func TestTLSHandlerNamesRegistered(t *testing.T) {
	names := map[string]bool{}
	for _, n := range config.TCPHandlerNames() {
		names[n] = true
	}
	deps := Deps{DataDir: t.TempDir()}
	for _, n := range []string{"smtps", "imaps", "pop3s", "ldaps", "mqtts", "ftps"} {
		if !names[n] {
			t.Errorf("config does not accept tcp handler %q", n)
		}
		h, err := Get(n, deps)
		if err != nil {
			t.Errorf("Get(%q): %v", n, err)
			continue
		}
		if h.Name() != n {
			t.Errorf("Get(%q).Name() = %q", n, h.Name())
		}
	}
}

// --- postgres message builders ---------------------------------------------

func pgStartup(user string) []byte {
	body := []byte{0x00, 0x03, 0x00, 0x00} // protocol 3.0
	body = append(body, []byte("user\x00"+user+"\x00\x00")...)
	msg := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(msg, uint32(4+len(body)))
	copy(msg[4:], body)
	return msg
}

func pgPassword(pw string) []byte {
	body := append([]byte(pw), 0)
	msg := make([]byte, 5+len(body))
	msg[0] = 'p'
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(body)))
	copy(msg[5:], body)
	return msg
}
