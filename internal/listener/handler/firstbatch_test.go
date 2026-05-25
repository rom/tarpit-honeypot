package handler

// Tests for the "first batch" hardening + detection-completeness changes:
// capped line reads, the honest IMAP STARTTLS refusal, and credential / auth
// capture for MQTT, WinRM (Basic), VNC, and Kerberos.

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestReadLineCapped(t *testing.T) {
	// a normal line is returned intact, including the newline.
	br := bufio.NewReader(strings.NewReader("hello\r\nworld"))
	got, err := readLineCapped(br, maxLineBytes)
	if err != nil || got != "hello\r\n" {
		t.Fatalf("readLineCapped normal = %q, err=%v; want \"hello\\r\\n\"", got, err)
	}
	// a newline-less flood is bounded to the cap and returns promptly without
	// an error (the allocation can't grow without bound).
	big := strings.Repeat("A", 1<<20)
	got2, err2 := readLineCapped(bufio.NewReader(strings.NewReader(big)), maxLineBytes)
	if err2 != nil {
		t.Fatalf("capped read errored: %v", err2)
	}
	if len(got2) != maxLineBytes {
		t.Errorf("flood not capped: got %d bytes, want %d", len(got2), maxLineBytes)
	}
}

func TestIMAPStartTLSRefused(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&imap{}).Handle(context.Background(), server, cfg); resC <- r }()

	br := bufio.NewReader(client)
	if _, err := br.ReadString('\n'); err != nil { // greeting
		t.Fatal(err)
	}
	_, _ = client.Write([]byte("a1 STARTTLS\r\n"))
	resp, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	<-resC
	if strings.Contains(resp, "OK Begin TLS") {
		t.Errorf("IMAP still lies about STARTTLS: %q", resp)
	}
	if !strings.Contains(resp, "NO") || !strings.Contains(resp, "STARTTLS not available") {
		t.Errorf("IMAP STARTTLS should be an honest refusal; got %q", resp)
	}
}

func TestMQTTCapturesCredentials(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&mqtt{}).Handle(context.Background(), server, cfg); resC <- r }()

	_, _ = client.Write(mqttConnectWithCreds("root", "root"))
	ack := make([]byte, 4)
	if _, err := io.ReadFull(client, ack); err != nil { // CONNACK
		t.Fatal(err)
	}
	_ = client.Close()
	r := <-resC
	if r.Meta["username"] != "root" || r.Meta["password"] != "root" {
		t.Errorf("MQTT did not capture creds: user=%v pass=%v", r.Meta["username"], r.Meta["password"])
	}
	anoms := metaAnoms(r)
	if !containsStr(anoms, "mqtt-credential-attempt") {
		t.Errorf("MQTT credential attempt not flagged: %v", anoms)
	}
	if !containsStr(anoms, "default-credential-attempt") {
		t.Errorf("MQTT default credential (root/root) not flagged: %v", anoms)
	}
}

func TestWinRMBasicCredentialFlagged(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second, ReadBytes: 8192}
	resC := make(chan Result, 1)
	go func() { r, _ := (&winrm{}).Handle(context.Background(), server, cfg); resC <- r }()
	go func() { _, _ = io.Copy(io.Discard, client) }()

	basic := base64.StdEncoding.EncodeToString([]byte("admin:admin"))
	_, _ = client.Write([]byte("POST /wsman HTTP/1.1\r\nHost: x\r\nAuthorization: Basic " + basic + "\r\n\r\n"))
	time.Sleep(20 * time.Millisecond)
	_ = client.Close()
	r := <-resC
	if r.Meta["basic_user"] != "admin" || r.Meta["basic_pass"] != "admin" {
		t.Errorf("WinRM did not capture Basic creds: %v / %v", r.Meta["basic_user"], r.Meta["basic_pass"])
	}
	if !containsStr(metaAnoms(r), "default-credential-attempt") {
		t.Errorf("WinRM default Basic credential not flagged: %v", metaAnoms(r))
	}
}

func TestVNCCapturesChallengeAndResponse(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&vnc{}).Handle(context.Background(), server, cfg); resC <- r }()

	ver := make([]byte, 12)
	if _, err := io.ReadFull(client, ver); err != nil {
		t.Fatal(err)
	}
	_, _ = client.Write([]byte("RFB 003.008\n"))
	sec := make([]byte, 2) // [count=1][type=2]
	if _, err := io.ReadFull(client, sec); err != nil {
		t.Fatal(err)
	}
	_, _ = client.Write([]byte{0x02}) // select VNC auth
	chal := make([]byte, 16)
	if _, err := io.ReadFull(client, chal); err != nil {
		t.Fatal(err)
	}
	_, _ = client.Write(make([]byte, 16)) // DES response
	secRes := make([]byte, 4)
	_, _ = io.ReadFull(client, secRes)
	_ = client.Close()
	r := <-resC

	ch, _ := r.Meta["challenge_hex"].(string)
	rh, _ := r.Meta["auth_response_hex"].(string)
	if len(ch) != 32 || len(rh) != 32 {
		t.Errorf("VNC challenge/response not captured: chal=%q resp=%q", ch, rh)
	}
	if !containsStr(metaAnoms(r), "vnc-auth-attempt") {
		t.Errorf("VNC auth attempt not flagged: %v", metaAnoms(r))
	}
}

func TestKerberosExtractsPrincipal(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&kerberos{}).Handle(context.Background(), server, cfg); resC <- r }()
	go func() { _, _ = io.Copy(io.Discard, client) }()

	// AS-REQ tag (0x6A) followed by a GeneralString (0x1B) carrying the
	// principal — the username an AS-REP-roast / spray targets.
	name := "EVILUSER"
	body := append([]byte{0x6A, 0x1B, byte(len(name))}, []byte(name)...)
	msg := append([]byte{0x00, 0x00, 0x00, byte(len(body))}, body...)
	_, _ = client.Write(msg)
	time.Sleep(20 * time.Millisecond)
	_ = client.Close()
	r := <-resC
	if r.Meta["principal"] != name {
		t.Errorf("Kerberos principal = %v; want %q", r.Meta["principal"], name)
	}
	if !containsStr(metaAnoms(r), "kerberos-principal-probe") {
		t.Errorf("Kerberos principal probe not flagged: %v", metaAnoms(r))
	}
}

// --- helpers ---------------------------------------------------------------

func metaAnoms(r Result) []string {
	a, _ := r.Meta["anomalies"].([]string)
	return a
}

// mqttConnectWithCreds builds an MQTT 3.1.1 CONNECT carrying a username +
// password (clean session), for the credential-capture test.
func mqttConnectWithCreds(user, pass string) []byte {
	str := func(s string) []byte { return append([]byte{byte(len(s) >> 8), byte(len(s))}, s...) }
	body := []byte{0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0xC2, 0x00, 0x3c} // flags 0xC2 = user|pass|clean
	body = append(body, str("id")...)
	body = append(body, str(user)...)
	body = append(body, str(pass)...)
	return append([]byte{0x10, byte(len(body))}, body...)
}
