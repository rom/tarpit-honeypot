package handler

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// minimal NTLMSSP NEGOTIATE (type 1) — captureNLA only needs the signature +
// message type to recognise it and reply with a challenge.
func ntlmType1() []byte {
	m := make([]byte, 32)
	copy(m[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(m[8:12], 1) // NEGOTIATE
	return m
}

// TestRDPCaptureNetNTLMv2 drives the post-TLS CredSSP/NLA exchange and asserts
// the handler issues a challenge and harvests the offline-crackable NetNTLMv2.
func TestRDPCaptureNetNTLMv2(t *testing.T) {
	r := &rdp{id: identity.New("rdp-nla-test")}
	cfg := config.Listener{ReadTimeout: 3 * time.Second}

	clientConn, serverConn := net.Pipe()
	res := Result{Meta: map[string]any{}}

	ntProof := bytes.Repeat([]byte{0x5a}, 16)
	// Realistic NTLMv2 temp blob (> 8 bytes -> NT response > 24 -> v2).
	blob := []byte{
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x00, 0x00, 0x00, 0x00,
	}
	ntResp := append(append([]byte{}, ntProof...), blob...)

	var serverChallenge []byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer clientConn.Close()
		// 1. send a CredSSP TSRequest carrying the NTLM NEGOTIATE (type 1).
		if _, err := clientConn.Write(buildCredSSPTSRequest(6, ntlmType1())); err != nil {
			return
		}
		// 2. read the server's TSRequest carrying the NTLM CHALLENGE (type 2);
		//    the 8-byte server challenge lives at offset 24 of the NTLM message.
		cbuf := make([]byte, 8192)
		n, err := clientConn.Read(cbuf)
		if err != nil {
			return
		}
		ch := findNTLMSSP(cbuf[:n])
		if ch == nil || len(ch) < 32 || binary.LittleEndian.Uint32(ch[8:12]) != 2 {
			t.Errorf("did not receive an NTLM CHALLENGE; got % x", cbuf[:n])
			return
		}
		serverChallenge = append([]byte{}, ch[24:32]...)
		// 3. send the AUTHENTICATE (type 3) with our NetNTLMv2 response.
		t3 := buildType3("CORP", "alice", "WS01", ntResp)
		_, _ = clientConn.Write(buildCredSSPTSRequest(6, t3))
	}()

	r.captureNLA(serverConn, cfg, &res)
	<-done

	if res.Meta["nla"] != true {
		t.Errorf("nla flag not set: %v", res.Meta["nla"])
	}
	if res.Meta["ntlm_user"] != "alice" || res.Meta["ntlm_domain"] != "CORP" {
		t.Fatalf("user/domain = %v / %v", res.Meta["ntlm_user"], res.Meta["ntlm_domain"])
	}
	if !hasAnom(res, "rdp-ntlmv2-capture") {
		t.Errorf("rdp-ntlmv2-capture not flagged: %v", res.Meta["anomalies"])
	}
	if len(serverChallenge) != 8 {
		t.Fatal("test did not capture the server challenge")
	}
	want := "alice::CORP:" + hex.EncodeToString(serverChallenge) + ":" +
		hex.EncodeToString(ntProof) + ":" + hex.EncodeToString(blob)
	if res.Meta["ntlmv2_hash"] != want {
		t.Errorf("ntlmv2_hash =\n %v\nwant\n %v", res.Meta["ntlmv2_hash"], want)
	}
}

// An AUTHENTICATE (type 3) sent without first negotiating still records the
// username/domain (best effort) but no crackable hash.
func TestRDPCaptureNLAUnsolicitedType3(t *testing.T) {
	r := &rdp{id: identity.New("rdp-nla-test2")}
	cfg := config.Listener{ReadTimeout: 3 * time.Second}
	clientConn, serverConn := net.Pipe()
	res := Result{Meta: map[string]any{}}

	go func() {
		defer clientConn.Close()
		t3 := buildType3("WORKGROUP", "bob", "PC", bytes.Repeat([]byte{0x11}, 24))
		binary.LittleEndian.PutUint32(t3[60:64], 0x00000001) // NTLMSSP_NEGOTIATE_UNICODE (set by real clients)
		_, _ = clientConn.Write(buildCredSSPTSRequest(6, t3))
	}()
	r.captureNLA(serverConn, cfg, &res)

	if res.Meta["ntlm_user"] != "bob" {
		t.Errorf("ntlm_user = %v, want bob", res.Meta["ntlm_user"])
	}
	if !hasAnom(res, "rdp-ntlm-auth") {
		t.Errorf("rdp-ntlm-auth not flagged: %v", res.Meta["anomalies"])
	}
	if _, ok := res.Meta["ntlmv2_hash"]; ok {
		t.Error("must not claim a crackable hash without issuing a challenge")
	}
}

func TestCredSSPVersion(t *testing.T) {
	cases := []struct {
		ver  int
		want int
	}{{2, 2}, {3, 3}, {6, 6}}
	for _, c := range cases {
		ts := buildCredSSPTSRequest(c.ver, ntlmType1())
		if got := credsspVersion(ts); got != c.want {
			t.Errorf("credsspVersion(v%d) = %d, want %d", c.ver, got, c.want)
		}
		// The built TSRequest must embed the NTLM token intact.
		if findNTLMSSP(ts) == nil {
			t.Errorf("v%d: TSRequest lost the NTLM token", c.ver)
		}
	}
	// Out-of-range versions clamp into 2..6; absent version defaults to 6.
	if got := credsspVersion(buildCredSSPTSRequest(9, ntlmType1())); got != 6 {
		t.Errorf("clamp high: got %d, want 6", got)
	}
	if got := credsspVersion([]byte{0x30, 0x00}); got != 6 {
		t.Errorf("absent version: got %d, want 6", got)
	}
}
