package handler

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// buildType3LM is buildType3 but with an explicit LM-response field (the v1
// path reads it; buildType3 always leaves LM empty).
func buildType3LM(domain, user, ws string, lm, nt []byte) []byte {
	d, u, w := utf16le(domain), utf16le(user), utf16le(ws)
	var payload []byte
	off := 64
	field := func(b []byte) []byte {
		desc := make([]byte, 8)
		binary.LittleEndian.PutUint16(desc[0:2], uint16(len(b)))
		binary.LittleEndian.PutUint16(desc[2:4], uint16(len(b)))
		binary.LittleEndian.PutUint32(desc[4:8], uint32(off))
		payload = append(payload, b...)
		off += len(b)
		return desc
	}
	msg := make([]byte, 64)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 3)           // AUTHENTICATE
	copy(msg[12:20], field(lm))                           // LmChallengeResponse
	copy(msg[20:28], field(nt))                           // NtChallengeResponse
	copy(msg[28:36], field(d))                            // DomainName
	copy(msg[36:44], field(u))                            // UserName
	copy(msg[44:52], field(w))                            // Workstation
	binary.LittleEndian.PutUint32(msg[60:64], 0x00000001) // NEGOTIATE_UNICODE
	return append(msg, payload...)
}

// A 24-byte NT response is NetNTLMv1 → a hashcat mode-5500 line, not a v2 hash.
func TestCaptureNetNTLMv1Plain(t *testing.T) {
	chal := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}
	lm := bytes.Repeat([]byte{0x11}, 24)
	nt := bytes.Repeat([]byte{0x22}, 24)

	res := Result{Meta: map[string]any{}}
	captureNetNTLM("smb", buildType3LM("CORP", "alice", "WS1", lm, nt), chal, &res)

	if res.Meta["auth_type"] != "ntlmv1" {
		t.Fatalf("auth_type = %v, want ntlmv1", res.Meta["auth_type"])
	}
	if res.Meta["ntlm_ess"] != nil {
		t.Errorf("plain v1 must not set ntlm_ess: %v", res.Meta["ntlm_ess"])
	}
	if _, ok := res.Meta["ntlmv2_hash"]; ok {
		t.Error("a v1 response must not emit a v2 hash")
	}
	want := "alice::CORP:" + hex.EncodeToString(lm) + ":" + hex.EncodeToString(nt) + ":" + hex.EncodeToString(chal)
	if res.Meta["ntlmv1_hash"] != want {
		t.Errorf("ntlmv1_hash =\n %v\nwant\n %v", res.Meta["ntlmv1_hash"], want)
	}
	if !hasAnom(res, "smb-ntlmv1-capture") {
		t.Error("smb-ntlmv1-capture not flagged")
	}
}

// The NTLM2 session-response (ESS) variant: LM = 8-byte client challenge + 16
// zero bytes; the effective challenge is MD5(serverChal||clientChal)[:8].
func TestCaptureNetNTLMv1ESS(t *testing.T) {
	chal := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}
	clientChal := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	lm := append(append([]byte{}, clientChal...), make([]byte, 16)...) // 8 + 16 zeros
	nt := bytes.Repeat([]byte{0x33}, 24)

	res := Result{Meta: map[string]any{}}
	captureNetNTLM("rdp", buildType3LM("AD", "bob", "PC", lm, nt), chal, &res)

	if res.Meta["ntlm_ess"] != true {
		t.Fatalf("ess not detected: %v", res.Meta["ntlm_ess"])
	}
	sum := md5.Sum(append(append([]byte{}, chal...), clientChal...))
	want := "bob::AD:" + hex.EncodeToString(lm) + ":" + hex.EncodeToString(nt) + ":" + hex.EncodeToString(sum[:8])
	if res.Meta["ntlmv1_hash"] != want {
		t.Errorf("ESS ntlmv1_hash =\n %v\nwant\n %v", res.Meta["ntlmv1_hash"], want)
	}
	if !hasAnom(res, "rdp-ntlmv1-capture") {
		t.Error("rdp-ntlmv1-capture not flagged")
	}
}
