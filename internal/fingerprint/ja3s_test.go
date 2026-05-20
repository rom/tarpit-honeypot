package fingerprint

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// buildServerHello synthesizes a minimal but valid ServerHello handshake
// message (starting with handshake type = 0x02).
func buildServerHello(version uint16, cipher uint16, exts []uint16) []byte {
	body := []byte{}
	body = binary.BigEndian.AppendUint16(body, version) // legacy_version
	body = append(body, make([]byte, 32)...)            // random
	body = append(body, 0)                              // session_id length = 0
	body = binary.BigEndian.AppendUint16(body, cipher)  // selected cipher
	body = append(body, 0)                              // compression method = null

	extBlock := []byte{}
	for _, e := range exts {
		extBlock = binary.BigEndian.AppendUint16(extBlock, e)
		extBlock = binary.BigEndian.AppendUint16(extBlock, 0) // zero-length ext data
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(extBlock)))
	body = append(body, extBlock...)

	msg := []byte{0x02} // handshake type = ServerHello
	msg = append(msg, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	msg = append(msg, body...)
	return msg
}

func TestJA3SKnownString(t *testing.T) {
	// TLS 1.2 (771), cipher TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f
	// = 49199), extensions renegotiation_info (65281), SNI (0), ALPN (16).
	sh := buildServerHello(0x0303, 0xc02f, []uint16{0xff01, 0x0000, 0x0010})
	raw, hash := JA3S(sh)
	wantRaw := "771,49199,65281-0-16"
	if raw != wantRaw {
		t.Fatalf("JA3S raw = %q; want %q", raw, wantRaw)
	}
	sum := md5.Sum([]byte(wantRaw))
	if hash != hex.EncodeToString(sum[:]) {
		t.Fatalf("JA3S hash = %q; not MD5 of raw", hash)
	}
}

func TestJA3SFiltersGREASE(t *testing.T) {
	// A GREASE extension value (0x1a1a) must be dropped from the list.
	sh := buildServerHello(0x0303, 0x1301, []uint16{0x1a1a, 0x002b, 0x0033})
	raw, _ := JA3S(sh)
	want := "771,4865,43-51"
	if raw != want {
		t.Fatalf("JA3S raw = %q; want %q (GREASE 0x1a1a filtered)", raw, want)
	}
}

func TestJA3SNoExtensions(t *testing.T) {
	sh := buildServerHello(0x0301, 0x002f, nil)
	raw, hash := JA3S(sh)
	if raw != "769,47," {
		t.Fatalf("JA3S raw = %q; want %q", raw, "769,47,")
	}
	if hash == "" {
		t.Fatal("JA3S hash empty for valid no-extension ServerHello")
	}
}

func TestJA3SRejectsGarbage(t *testing.T) {
	if raw, hash := JA3S([]byte{0x01, 0x00, 0x00, 0x00}); raw != "" || hash != "" {
		t.Fatalf("JA3S accepted a non-ServerHello (type 0x01): raw=%q hash=%q", raw, hash)
	}
	if raw, _ := JA3S([]byte{0x02, 0xff}); raw != "" {
		t.Fatalf("JA3S accepted a truncated message")
	}
	if raw, _ := JA3S(nil); raw != "" {
		t.Fatalf("JA3S accepted nil")
	}
}
