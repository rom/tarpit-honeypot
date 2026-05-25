package handler

// Tests for the deeper Kerberos (enctypes, two-round pre-auth timestamp capture)
// and VNC (accept-gated post-auth session: keystroke + clipboard capture).

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// --- Kerberos ---------------------------------------------------------------

func TestKerberosEnctypesAndDerLen(t *testing.T) {
	body := []byte{0x6A, 0x02, 0x01, 0x17, 0x02, 0x01, 0x12} // rc4 + aes256
	ets := kerberosEnctypes(body)
	if !containsStr(ets, "rc4-hmac") || !containsStr(ets, "aes256-cts") {
		t.Errorf("enctypes = %v; want rc4-hmac + aes256-cts", ets)
	}
	if n, hdr, ok := derLen([]byte{0x12}, 0); !ok || n != 18 || hdr != 1 {
		t.Errorf("short derLen = %d,%d,%v", n, hdr, ok)
	}
	if n, hdr, ok := derLen([]byte{0x82, 0x01, 0x00}, 0); !ok || n != 256 || hdr != 3 {
		t.Errorf("long derLen = %d,%d,%v", n, hdr, ok)
	}
}

func TestPaEncTimestamp(t *testing.T) {
	ts := bytes.Repeat([]byte{0x42}, 16)
	body := append([]byte{0x6A, 0xA1, 0x03, 0x02, 0x01, 0x02, 0xA2, 0x12, 0x04, 0x10}, ts...)
	got := paEncTimestamp(body)
	if !bytes.Equal(got, ts) {
		t.Errorf("paEncTimestamp = % x; want % x", got, ts)
	}
	if paEncTimestamp([]byte{0x6A, 0x30, 0x00}) != nil {
		t.Error("paEncTimestamp should be nil when no PA-ENC-TIMESTAMP present")
	}
}

func readKRBFrame(t *testing.T, c io.Reader) []byte {
	t.Helper()
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatalf("read krb frame len: %v", err)
	}
	n := binary.BigEndian.Uint32(hdr)
	if n > 65535 {
		t.Fatalf("krb frame too big: %d", n)
	}
	b := make([]byte, n)
	_, _ = io.ReadFull(c, b)
	return b
}

func TestKerberosTwoRoundPreauthCapture(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ID: "krb", ReadTimeout: 5 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&kerberos{}).Handle(context.Background(), server, cfg); resC <- r }()

	// Round 1: AS-REQ with principal + RC4 requested.
	body1 := append([]byte{0x6A, 0x1B, 0x08}, []byte("EVILUSER")...)
	body1 = append(body1, 0x02, 0x01, 0x17) // etype rc4
	_, _ = client.Write(krbFrame(body1))
	if r := readKRBFrame(t, client); len(r) == 0 { // KRB-ERROR(25)
		t.Fatal("no preauth-required reply")
	}
	// Round 2: pre-auth retry carrying the (crackable) encrypted timestamp.
	ts := bytes.Repeat([]byte{0x42}, 16)
	body2 := append([]byte{0x6A, 0xA1, 0x03, 0x02, 0x01, 0x02, 0xA2, 0x12, 0x04, 0x10}, ts...)
	_, _ = client.Write(krbFrame(body2))
	readKRBFrame(t, client) // KRB-ERROR(24)
	_ = client.Close()
	r := <-resC

	if r.Meta["principal"] != "EVILUSER" {
		t.Errorf("principal = %v; want EVILUSER", r.Meta["principal"])
	}
	if ets, _ := r.Meta["enctypes"].([]string); !containsStr(ets, "rc4-hmac") {
		t.Errorf("enctypes = %v; want rc4-hmac", r.Meta["enctypes"])
	}
	if r.Meta["preauth_enc_timestamp_hex"] != byteToHex(ts) {
		t.Errorf("preauth timestamp = %v; want %s", r.Meta["preauth_enc_timestamp_hex"], byteToHex(ts))
	}
	for _, a := range []string{"kerberos-principal-probe", "kerberos-rc4-requested", "kerberos-preauth-bruteforce"} {
		if !containsStr(metaAnoms(r), a) {
			t.Errorf("missing anomaly %q in %v", a, metaAnoms(r))
		}
	}
}

// --- VNC --------------------------------------------------------------------

// vncHandshake drives the client side through RFB 3.8 version + VNC-auth
// negotiation and returns the 4-byte SecurityResult.
func vncHandshake(t *testing.T, client io.ReadWriter) []byte {
	t.Helper()
	ver := make([]byte, 12)
	if _, err := io.ReadFull(client, ver); err != nil {
		t.Fatalf("read server version: %v", err)
	}
	_, _ = client.Write([]byte("RFB 003.008\n"))
	sec := make([]byte, 2) // [count=1][type=2]
	_, _ = io.ReadFull(client, sec)
	_, _ = client.Write([]byte{0x02}) // select VNC auth
	chal := make([]byte, 16)
	_, _ = io.ReadFull(client, chal)
	_, _ = client.Write(make([]byte, 16)) // DES response
	sr := make([]byte, 4)
	_, _ = io.ReadFull(client, sr)
	return sr
}

func TestVNCRejectsByDefault(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ID: "vnc", ReadTimeout: 3 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&vnc{}).Handle(context.Background(), server, cfg); resC <- r }()
	sr := vncHandshake(t, client)
	_ = client.Close()
	r := <-resC
	if !bytes.Equal(sr, []byte{0, 0, 0, 1}) {
		t.Errorf("default SecurityResult = % x; want 00000001 (failed)", sr)
	}
	if r.Meta["auth_accepted"] == true {
		t.Error("auth must not be accepted without accept_creds")
	}
	if r.Meta["auth_response_hex"] == nil {
		t.Error("the DES response should still be captured")
	}
}

func keyEvent(keysym uint32) []byte {
	b := []byte{4, 1, 0, 0, 0, 0, 0, 0} // type=4, down=1, 2 pad, keysym(4)
	binary.BigEndian.PutUint32(b[4:8], keysym)
	return b
}

func TestVNCAcceptsAndCapturesSession(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ID: "vnc", ReadTimeout: 5 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&vnc{acceptCreds: "any"}).Handle(context.Background(), server, cfg); resC <- r }()

	sr := vncHandshake(t, client)
	if !bytes.Equal(sr, []byte{0, 0, 0, 0}) {
		t.Fatalf("accepted SecurityResult = % x; want 00000000", sr)
	}
	_, _ = client.Write([]byte{1}) // ClientInit (shared)
	// Read ServerInit: 24 fixed + name.
	head := make([]byte, 24)
	if _, err := io.ReadFull(client, head); err != nil {
		t.Fatalf("read ServerInit: %v", err)
	}
	nameLen := binary.BigEndian.Uint32(head[20:24])
	if nameLen > 256 {
		t.Fatalf("implausible desktop name length %d", nameLen)
	}
	_, _ = io.ReadFull(client, make([]byte, nameLen))
	// Type "hi" + Return, then paste a clipboard secret.
	var msgs []byte
	msgs = append(msgs, keyEvent('h')...)
	msgs = append(msgs, keyEvent('i')...)
	msgs = append(msgs, keyEvent(0xff0d)...) // Return
	cut := []byte{6, 0, 0, 0, 0, 0, 0, 6}    // ClientCutText, len=6
	cut = append(cut, []byte("secret")...)
	msgs = append(msgs, cut...)
	_, _ = client.Write(msgs)
	_ = client.Close()
	r := <-resC

	if r.Meta["auth_accepted"] != true {
		t.Error("auth_accepted should be true")
	}
	if r.Meta["keystrokes"] != "hi\n" {
		t.Errorf("keystrokes = %q; want \"hi\\n\"", r.Meta["keystrokes"])
	}
	if r.Meta["clipboard"] != "secret" {
		t.Errorf("clipboard = %q; want secret", r.Meta["clipboard"])
	}
	for _, a := range []string{"vnc-session", "vnc-clipboard-capture"} {
		if !containsStr(metaAnoms(r), a) {
			t.Errorf("missing anomaly %q in %v", a, metaAnoms(r))
		}
	}
}
