package handler

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
)

// buildClientKEXINIT renders a client SSH_MSG_KEXINIT payload (type byte
// first) for the given algorithm lists, mirroring buildKEXINITPayload but
// letting the test drive each list independently.
func buildClientKEXINIT(set sshAlgoSet, firstFollows bool) []byte {
	var b bytes.Buffer
	b.WriteByte(sshMsgKexInit)
	b.Write(make([]byte, 16)) // cookie
	putNameList(&b, set.kex)
	putNameList(&b, set.hostKeys)
	putNameList(&b, set.ciphers) // enc c2s
	putNameList(&b, set.ciphers) // enc s2c
	putNameList(&b, set.macs)    // mac c2s
	putNameList(&b, set.macs)    // mac s2c
	putNameList(&b, set.comp)    // comp c2s
	putNameList(&b, set.comp)    // comp s2c
	putNameList(&b, nil)         // lang c2s
	putNameList(&b, nil)         // lang s2c
	if firstFollows {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	b.Write([]byte{0, 0, 0, 0}) // reserved
	return b.Bytes()
}

func TestParseClientKEXINIT(t *testing.T) {
	payload := buildClientKEXINIT(sshModern, true)
	ki := parseClientKEXINIT(payload)
	if ki == nil {
		t.Fatal("parseClientKEXINIT returned nil for a valid KEXINIT")
	}
	if len(ki.kex) != len(sshModern.kex) || ki.kex[0] != sshModern.kex[0] {
		t.Errorf("kex list mismatch: got %v", ki.kex)
	}
	if len(ki.hostKeys) != len(sshModern.hostKeys) {
		t.Errorf("hostKeys mismatch: got %v", ki.hostKeys)
	}
	if !ki.firstFollows {
		t.Error("firstFollows should be true")
	}
}

func TestParseClientKEXINITMalformed(t *testing.T) {
	cases := [][]byte{
		nil,
		{sshMsgKexInit}, // too short
		append([]byte{0x99}, make([]byte, 40)...), // wrong type byte
	}
	for i, c := range cases {
		if ki := parseClientKEXINIT(c); ki != nil {
			t.Errorf("case %d: expected nil, got %+v", i, ki)
		}
	}
	// A KEXINIT claiming a name-list longer than the buffer must be rejected.
	bad := buildClientKEXINIT(sshModern, false)
	binary.BigEndian.PutUint32(bad[17:21], 0xffffff) // first list length
	if ki := parseClientKEXINIT(bad); ki != nil {
		t.Error("oversized name-list length should be rejected")
	}
}

func TestNegotiatedKex(t *testing.T) {
	client := []string{"curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha1"}
	server := []string{"ecdh-sha2-nistp256", "diffie-hellman-group14-sha1"}
	// Client order wins: nistp256 is the first client algo the server has.
	if got := negotiatedKex(client, server); got != "ecdh-sha2-nistp256" {
		t.Errorf("negotiatedKex = %q, want ecdh-sha2-nistp256", got)
	}
	if got := negotiatedKex([]string{"a"}, []string{"b"}); got != "" {
		t.Errorf("no overlap should yield empty, got %q", got)
	}
}

func TestReadSSHPacketRoundTrip(t *testing.T) {
	payload := buildClientKEXINIT(sshModern, false)
	framed := frameSSHPacket(payload)
	br := bufio.NewReader(bytes.NewReader(framed))
	got, ok := readSSHPacket(br)
	if !ok {
		t.Fatal("readSSHPacket failed on well-formed packet")
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload round-trip mismatch:\n got %x\nwant %x", got, payload)
	}
	// HASSH computed from the unframed payload must equal the framed-path HASSH.
	rawA, sumA := fingerprint.HASSH(got)
	rawB, sumB := fingerprint.HASSH(framed)
	if sumA == "" || sumA != sumB || rawA != rawB {
		t.Errorf("HASSH mismatch unframed vs framed: %q/%q vs %q/%q", rawA, sumA, rawB, sumB)
	}
}

func TestReadSSHPacketShort(t *testing.T) {
	if _, ok := readSSHPacket(bufio.NewReader(bytes.NewReader([]byte{0, 0}))); ok {
		t.Error("short header should fail")
	}
	// Length header promises more than the reader holds.
	hdr := []byte{0, 0, 0, 100, 5}
	if _, ok := readSSHPacket(bufio.NewReader(bytes.NewReader(hdr))); ok {
		t.Error("truncated body should fail")
	}
}

func TestCaptureExtendedKexECDH(t *testing.T) {
	kexInit := buildClientKEXINIT(sshModern, false)
	// Client ECDH_INIT: type + string(Q_C). Use a 32-byte curve25519 pubkey.
	pub := bytes.Repeat([]byte{0xab}, 32)
	var ecdh bytes.Buffer
	ecdh.WriteByte(sshMsgKexDHInit)
	binary.Write(&ecdh, binary.BigEndian, uint32(len(pub)))
	ecdh.Write(pub)
	br := bufio.NewReader(bytes.NewReader(frameSSHPacket(ecdh.Bytes())))

	res := Result{Meta: map[string]any{}}
	captureExtendedKex(br, kexInit, sshModern.kex, &res)

	if res.Meta["ssh_kex_negotiated"] != sshModern.kex[0] {
		t.Errorf("negotiated = %v, want %v", res.Meta["ssh_kex_negotiated"], sshModern.kex[0])
	}
	if res.Meta["ssh_kex_msg"] != "ecdh_or_dh_init" {
		t.Errorf("msg = %v, want ecdh_or_dh_init", res.Meta["ssh_kex_msg"])
	}
	if res.Meta["ssh_kex_client_pubkey_bytes"] != 32 {
		t.Errorf("pubkey bytes = %v, want 32", res.Meta["ssh_kex_client_pubkey_bytes"])
	}
	want := sha256.Sum256(pub)
	if res.Meta["ssh_kex_client_pubkey_sha256"] != hex.EncodeToString(want[:]) {
		t.Errorf("pubkey sha256 mismatch")
	}
	if hk, ok := res.Meta["ssh_kex_hostkeys"].([]string); !ok || len(hk) == 0 {
		t.Errorf("hostkeys not captured: %v", res.Meta["ssh_kex_hostkeys"])
	}
}

func TestCaptureExtendedKexGEX(t *testing.T) {
	kexInit := buildClientKEXINIT(sshModern, false)
	var gex bytes.Buffer
	gex.WriteByte(sshMsgKexDHGexReq)
	binary.Write(&gex, binary.BigEndian, uint32(2048)) // min
	binary.Write(&gex, binary.BigEndian, uint32(3072)) // n
	binary.Write(&gex, binary.BigEndian, uint32(8192)) // max
	br := bufio.NewReader(bytes.NewReader(frameSSHPacket(gex.Bytes())))

	res := Result{Meta: map[string]any{}}
	captureExtendedKex(br, kexInit, sshModern.kex, &res)
	if res.Meta["ssh_kex_msg"] != "dh_gex_request" {
		t.Fatalf("msg = %v, want dh_gex_request", res.Meta["ssh_kex_msg"])
	}
	if res.Meta["ssh_kex_gex_n"] != uint32(3072) {
		t.Errorf("gex_n = %v, want 3072", res.Meta["ssh_kex_gex_n"])
	}
}

// End-to-end: an SSH handler with kexExt set must, after the banner and its
// own KEXINIT, read the client KEXINIT (HASSH) and the client's ECDH_INIT,
// recording both the HASSH and the extended key-exchange fields.
func TestSSHHandleExtendedKex(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Banner: "SSH-2.0-OpenSSH_9.2p1\r\n", ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() {
		r, _ := (&ssh{kexExt: true}).Handle(context.Background(), server, cfg)
		resC <- r
	}()
	br := bufio.NewReader(client)
	if _, err := br.ReadString('\n'); err != nil { // banner
		t.Fatalf("read banner: %v", err)
	}
	readSSHKexPayload(t, br) // drain server KEXINIT

	// Client side: identification line, then KEXINIT, then ECDH_INIT.
	if _, err := client.Write([]byte("SSH-2.0-paramiko_3.4.0\r\n")); err != nil {
		t.Fatalf("write client id: %v", err)
	}
	if _, err := client.Write(frameSSHPacket(buildClientKEXINIT(sshModern, false))); err != nil {
		t.Fatalf("write client kexinit: %v", err)
	}
	pub := bytes.Repeat([]byte{0x07}, 32)
	var ecdh bytes.Buffer
	ecdh.WriteByte(sshMsgKexDHInit)
	_ = binary.Write(&ecdh, binary.BigEndian, uint32(len(pub)))
	ecdh.Write(pub)
	if _, err := client.Write(frameSSHPacket(ecdh.Bytes())); err != nil {
		t.Fatalf("write ecdh: %v", err)
	}
	_ = client.Close()

	r := <-resC
	if s, _ := r.Meta["hassh"].(string); len(s) != 32 {
		t.Errorf("hassh = %q; want 32-char md5", s)
	}
	if r.Meta["ssh_kex_negotiated"] != sshModern.kex[0] {
		t.Errorf("ssh_kex_negotiated = %v, want %v", r.Meta["ssh_kex_negotiated"], sshModern.kex[0])
	}
	if r.Meta["ssh_kex_client_pubkey_bytes"] != 32 {
		t.Errorf("pubkey bytes = %v, want 32", r.Meta["ssh_kex_client_pubkey_bytes"])
	}
}

func TestHasWeakKexPrimitive(t *testing.T) {
	if !hasWeakKexPrimitive(&sshKexInit{kex: []string{"diffie-hellman-group1-sha1"}}) {
		t.Error("group1-sha1 should be weak")
	}
	if !hasWeakKexPrimitive(&sshKexInit{encC2S: []string{"aes128-cbc"}}) {
		t.Error("cbc cipher should be weak")
	}
	if hasWeakKexPrimitive(&sshKexInit{kex: sshModern.kex, encC2S: sshModern.ciphers, macC2S: sshModern.macs}) {
		t.Error("modern set should not be weak")
	}
}
