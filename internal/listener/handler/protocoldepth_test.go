package handler

// Tests for the protocol-depth batch: MQTT version-aware / rejecting CONNACK,
// per-deployment Oracle TNS version, and the RDP TLS upgrade + NLA (NTLMSSP)
// capture.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// --- MQTT CONNACK ----------------------------------------------------------

func mqttConnectLevel(level byte) []byte {
	body := []byte{0x00, 0x04, 'M', 'Q', 'T', 'T', level, 0x02, 0x00, 0x3c} // clean session, no auth
	body = append(body, 0x00, 0x02, 'i', 'd')                               // client id "id"
	return append([]byte{0x10, byte(len(body))}, body...)
}

func driveMQTT(t *testing.T, connect []byte, ackLen int) ([]byte, Result) {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{ID: "mqtt", ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&mqtt{}).Handle(context.Background(), server, cfg); resC <- r }()
	_, _ = client.Write(connect)
	ack := make([]byte, ackLen)
	_, _ = io.ReadFull(client, ack)
	_ = client.Close()
	return ack, <-resC
}

func TestMQTTConnackV5(t *testing.T) {
	ack, _ := driveMQTT(t, mqttConnectLevel(5), 5)
	want := []byte{0x20, 0x03, 0x00, 0x00, 0x00}
	if !bytes.Equal(ack, want) {
		t.Errorf("v5 CONNACK = % x; want % x (v5 carries a properties-length byte)", ack, want)
	}
}

func TestMQTTConnackV311(t *testing.T) {
	ack, _ := driveMQTT(t, mqttConnectLevel(4), 4)
	want := []byte{0x20, 0x02, 0x00, 0x00}
	if !bytes.Equal(ack, want) {
		t.Errorf("v3.1.1 CONNACK = % x; want % x", ack, want)
	}
}

func TestMQTTRejectsUnsupportedLevel(t *testing.T) {
	ack, r := driveMQTT(t, mqttConnectLevel(2), 4)
	want := []byte{0x20, 0x02, 0x00, 0x01} // unacceptable protocol version
	if !bytes.Equal(ack, want) {
		t.Errorf("bad-level CONNACK = % x; want % x", ack, want)
	}
	if !containsStr(metaAnoms(r), "mqtt-unsupported-protocol-level") {
		t.Errorf("unsupported protocol level not flagged: %v", metaAnoms(r))
	}
}

// --- Oracle TNS version ----------------------------------------------------

func TestOracleVSNNUMFormula(t *testing.T) {
	// 19.0.0.0.0 must map to the canonical VSNNUM 318767104 (19<<24).
	for _, v := range oracleVersions() {
		if v.ver == "19.0.0.0.0" && v.vsnnum != 318767104 {
			t.Errorf("19.0.0.0.0 VSNNUM = %d; want 318767104", v.vsnnum)
		}
	}
	if got := (&oracleTNS{}).version().ver; got != "19.0.0.0.0" {
		t.Errorf("nil-identity default version = %q; want 19.0.0.0.0", got)
	}
}

func TestOracleVersionDataConsistent(t *testing.T) {
	o := &oracleTNS{}
	data := string(o.buildVersionData())
	v := o.version()
	if !strings.Contains(data, "Version "+v.ver) {
		t.Errorf("version DATA missing %q:\n%s", v.ver, data)
	}
	if !strings.Contains(data, "VSNNUM="+itoa(int(v.vsnnum))) {
		t.Errorf("version DATA VSNNUM inconsistent with %s", v.ver)
	}
}

func TestOracleVersionRespondsToProbe(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ID: "ora", ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&oracleTNS{}).Handle(context.Background(), server, cfg); resC <- r }()
	desc := "(DESCRIPTION=(CONNECT_DATA=(COMMAND=version)))"
	body := []byte(desc)
	total := 8 + len(body)
	pkt := make([]byte, total)
	binary.BigEndian.PutUint16(pkt[0:2], uint16(total))
	pkt[4] = tnsConnect
	copy(pkt[8:], body)
	_, _ = client.Write(pkt)
	resp := make([]byte, 512)
	n, _ := client.Read(resp)
	_ = client.Close()
	<-resC
	if !strings.Contains(string(resp[:n]), "TNSLSNR for Linux: Version 1") &&
		!strings.Contains(string(resp[:n]), "Version 2") {
		t.Errorf("oracle version probe response missing a version banner: %q", resp[:n])
	}
}

// --- RDP TLS + NLA ---------------------------------------------------------

func readTPKTMsg(t *testing.T, c io.Reader) []byte {
	t.Helper()
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatalf("read TPKT header: %v", err)
	}
	total := int(binary.BigEndian.Uint16(hdr[2:4]))
	if total < 4 || total > 8192 {
		t.Fatalf("bad TPKT length %d", total)
	}
	rest := make([]byte, total-4)
	_, _ = io.ReadFull(c, rest)
	return append(hdr, rest...)
}

// ntlmType3 builds a minimal NTLMSSP AUTHENTICATE (type 3) with OEM (ASCII)
// domain/user and an NT response, matching the layout parseNTLMType3 reads.
func ntlmType3(domain, user string, nt []byte) []byte {
	buf := make([]byte, 64)
	copy(buf, []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(buf[8:], 3)
	var payload []byte
	put := func(fieldOff int, data []byte) {
		off := 64 + len(payload)
		binary.LittleEndian.PutUint16(buf[fieldOff:], uint16(len(data)))
		binary.LittleEndian.PutUint16(buf[fieldOff+2:], uint16(len(data)))
		binary.LittleEndian.PutUint32(buf[fieldOff+4:], uint32(off))
		payload = append(payload, data...)
	}
	put(20, nt)             // NtChallengeResponse
	put(28, []byte(domain)) // DomainName
	put(36, []byte(user))   // UserName
	// NegotiateFlags at offset 60 left zero => OEM (ASCII) strings.
	return append(buf, payload...)
}

func TestRDPTLSUpgradeAndNTLM(t *testing.T) {
	h := newRDP(Deps{DataDir: t.TempDir()})
	client, server := pipePair(t)
	cfg := config.Listener{ID: "rdp-1", ReadTimeout: 5 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := h.Handle(context.Background(), server, cfg); resC <- r }()

	// X.224 Connection Request with RDP_NEG_REQ requesting PROTOCOL_SSL.
	negReq := []byte{0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00}
	body := append([]byte{0x0E, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00}, negReq...)
	tpkt := []byte{0x03, 0x00, byte((4 + len(body)) >> 8), byte((4 + len(body)) & 0xff)}
	_, _ = client.Write(append(tpkt, body...))
	readTPKTMsg(t, client) // consume the Connection Confirm

	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, tc) }()
	// CredSSP-ish blob carrying an NTLMSSP type 3.
	blob := append([]byte{0x30, 0x82, 0x01, 0x00, 0xa0, 0x03}, ntlmType3("EVIL", "admin", bytes.Repeat([]byte{0x41}, 24))...)
	_, _ = tc.Write(blob)
	r := <-resC

	if r.Meta["tls"] != true {
		t.Errorf("RDP did not complete the TLS upgrade: %v", r.Meta)
	}
	if r.Meta["ntlm_user"] != "admin" || r.Meta["ntlm_domain"] != "EVIL" {
		t.Errorf("RDP NLA capture wrong: user=%v domain=%v", r.Meta["ntlm_user"], r.Meta["ntlm_domain"])
	}
	if !containsStr(metaAnoms(r), "rdp-ntlm-auth") {
		t.Errorf("RDP NTLM auth not flagged: %v", metaAnoms(r))
	}
}
