package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestNTLMSSPChallengeLayout(t *testing.T) {
	sc := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	c := ntlmsspChallenge(sc)
	if string(c[0:8]) != "NTLMSSP\x00" {
		t.Fatal("missing signature")
	}
	if binary.LittleEndian.Uint32(c[8:12]) != 2 {
		t.Errorf("message type = %d, want 2", binary.LittleEndian.Uint32(c[8:12]))
	}
	if !bytes.Equal(c[24:32], sc) {
		t.Errorf("server challenge not at offset 24: %x", c[24:32])
	}
	// TargetInfo must be present (NTLMv2 needs AV_PAIRs).
	tiLen := binary.LittleEndian.Uint16(c[40:42])
	if tiLen == 0 {
		t.Error("target info (AV_PAIRs) missing")
	}
}

// buildType3 crafts an NTLMSSP AUTHENTICATE message with the given fields and
// NtChallengeResponse, with the payload laid out after a 64-byte fixed header.
func buildType3(domain, user, workstation string, ntResp []byte) []byte {
	d := utf16le(domain)
	u := utf16le(user)
	w := utf16le(workstation)
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
	binary.LittleEndian.PutUint32(msg[8:12], 3) // AUTHENTICATE
	// Order payload as LM, NT, Domain, User, Workstation to match ascending offsets.
	copy(msg[12:20], field(nil))    // LmChallengeResponse (empty)
	copy(msg[20:28], field(ntResp)) // NtChallengeResponse
	copy(msg[28:36], field(d))      // DomainName
	copy(msg[36:44], field(u))      // UserName
	copy(msg[44:52], field(w))      // Workstation
	// EncryptedRandomSessionKey @52, flags @60 left zero.
	return append(msg, payload...)
}

func TestCaptureNetNTLMv2(t *testing.T) {
	serverChallenge := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}
	ntProof := bytes.Repeat([]byte{0x5a}, 16)
	blob := []byte{0x01, 0x01, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef}
	ntResp := append(append([]byte{}, ntProof...), blob...)

	res := Result{Meta: map[string]any{}}
	captureNetNTLMv2(buildType3("CORP", "alice", "WS01", ntResp), serverChallenge, &res)

	if res.Meta["ntlm_user"] != "alice" || res.Meta["ntlm_domain"] != "CORP" {
		t.Fatalf("user/domain = %v / %v", res.Meta["ntlm_user"], res.Meta["ntlm_domain"])
	}
	if res.Meta["ntlm_workstation"] != "WS01" {
		t.Errorf("workstation = %v", res.Meta["ntlm_workstation"])
	}
	want := "alice::CORP:" + hex.EncodeToString(serverChallenge) + ":" +
		hex.EncodeToString(ntProof) + ":" + hex.EncodeToString(blob)
	if res.Meta["ntlmv2_hash"] != want {
		t.Errorf("ntlmv2_hash =\n %v\nwant\n %v", res.Meta["ntlmv2_hash"], want)
	}
	if !hasAnom(res, "smb-ntlmv2-capture") {
		t.Error("smb-ntlmv2-capture not flagged")
	}
}

func TestSPNEGOContainsNTLM(t *testing.T) {
	init := spnegoNegTokenInit()
	if !bytes.Contains(init, oidNTLMSSP) {
		t.Error("negTokenInit missing NTLMSSP OID")
	}
	if init[0] != 0x60 {
		t.Errorf("negTokenInit must start with APPLICATION 0 (0x60), got 0x%02x", init[0])
	}
	chal := spnegoChallenge([]byte("NTLMSSP\x00challengebytes"))
	if chal[0] != 0xa1 {
		t.Errorf("negTokenResp must start with [1] (0xa1), got 0x%02x", chal[0])
	}
	if !bytes.Contains(chal, []byte("NTLMSSP\x00")) {
		t.Error("negTokenResp missing wrapped NTLMSSP token")
	}
}

// readNBSSMsg reads one NBSS-framed message from c.
func readNBSSMsg(t *testing.T, c net.Conn) []byte {
	t.Helper()
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatalf("read nbss header: %v", err)
	}
	n := int(uint32(hdr[1])<<16 | uint32(hdr[2])<<8 | uint32(hdr[3]))
	body := make([]byte, n)
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatalf("read nbss body: %v", err)
	}
	return body
}

// smb2ClientMsg frames a 64-byte SMB2 header (command, msgID) + body in NBSS.
func smb2ClientMsg(command uint16, msgID uint64, body []byte) []byte {
	h := make([]byte, 64)
	copy(h[0:4], "\xfeSMB")
	binary.LittleEndian.PutUint16(h[4:6], 64)
	binary.LittleEndian.PutUint16(h[12:14], command)
	binary.LittleEndian.PutUint64(h[24:32], msgID)
	msg := append(h, body...)
	return buildNBSS(msg)
}

// sessionSetupReqBody builds a SESSION_SETUP request body with the security
// buffer placed right after the 24-byte fixed body.
func sessionSetupReqBody(sec []byte) []byte {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 25) // StructureSize
	secOff := 64 + 24
	binary.LittleEndian.PutUint16(body[12:14], uint16(secOff))
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(sec)))
	return append(body, sec...)
}

// TestSMBNTLMv2EndToEnd drives the full SMB2 negotiate + NTLMSSP exchange
// against the handler and asserts the NetNTLMv2 is captured.
func TestSMBNTLMv2EndToEnd(t *testing.T) {
	srv, cli := net.Pipe()
	resCh := make(chan Result, 1)
	go func() {
		r, _ := (&smb{}).Handle(context.Background(), srv, config.Listener{ReadTimeout: 2 * time.Second})
		resCh <- r
	}()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))

	// 1) SMB2 NEGOTIATE request (minimal — handler only needs the header).
	if _, err := cli.Write(smb2ClientMsg(0x0000, 0, make([]byte, 36))); err != nil {
		t.Fatalf("write negotiate: %v", err)
	}
	readNBSSMsg(t, cli) // negotiate response

	// 2) SESSION_SETUP with NTLMSSP NEGOTIATE (type 1).
	type1 := make([]byte, 32)
	copy(type1[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(type1[8:12], 1)
	if _, err := cli.Write(smb2ClientMsg(0x0001, 1, sessionSetupReqBody(type1))); err != nil {
		t.Fatalf("write type1: %v", err)
	}
	challResp := readNBSSMsg(t, cli)

	// Recover the server challenge the handler issued (NTLMSSP type2 @24:32).
	ntlm2 := findNTLMSSP(challResp)
	if ntlm2 == nil || len(ntlm2) < 32 {
		t.Fatal("no NTLMSSP challenge in server response")
	}
	serverChallenge := ntlm2[24:32]

	// 3) SESSION_SETUP with NTLMSSP AUTHENTICATE (type 3).
	ntResp := append(bytes.Repeat([]byte{0x5a}, 16), []byte{0xde, 0xad}...)
	type3 := buildType3("CORP", "bob", "WS9", ntResp)
	if _, err := cli.Write(smb2ClientMsg(0x0001, 2, sessionSetupReqBody(type3))); err != nil {
		t.Fatalf("write type3: %v", err)
	}
	readNBSSMsg(t, cli) // logon-failure response
	_ = cli.Close()

	r := <-resCh
	if r.Meta["ntlm_user"] != "bob" {
		t.Errorf("ntlm_user = %v", r.Meta["ntlm_user"])
	}
	hash, _ := r.Meta["ntlmv2_hash"].(string)
	if !strings.HasPrefix(hash, "bob::CORP:") {
		t.Errorf("ntlmv2_hash = %q", hash)
	}
	if !strings.Contains(hash, hex.EncodeToString(serverChallenge)) {
		t.Errorf("hash does not embed the issued server challenge %x: %q", serverChallenge, hash)
	}
}
