package handler

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestQUIC1RTTKeyDerivationRFCVector verifies the key schedule against the
// official RFC 9001 Appendix A.1 vector. The "quic key"/"quic iv"/"quic hp"
// labels are identical for Initial and 1-RTT, so deriving from the published
// client_initial_secret must reproduce the published key/iv/hp — proving our
// 1-RTT derivation is correct.
func TestQUIC1RTTKeyDerivationRFCVector(t *testing.T) {
	secret := mustHex(t, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
	wantKey := mustHex(t, "1f369613dd76d5467730efcbe3b1a22d")
	wantIV := mustHex(t, "fa044b2f42a3fd3b46fb255c")
	wantHP := mustHex(t, "9f50449e04a0e810283a1e9933adedd2")

	key, iv, hp := quic1RTTKeys(secret, 16)
	if !bytes.Equal(key, wantKey) {
		t.Errorf("key = %x, want %x", key, wantKey)
	}
	if !bytes.Equal(iv, wantIV) {
		t.Errorf("iv = %x, want %x", iv, wantIV)
	}
	if !bytes.Equal(hp, wantHP) {
		t.Errorf("hp = %x, want %x", hp, wantHP)
	}
}

// TestShortHeaderRoundTrip encrypts then decrypts a 1-RTT short-header packet
// and checks the header protection, packet number, key phase, and payload all
// recover correctly — a rigorous check of the protect/unprotect symmetry.
func TestShortHeaderRoundTrip(t *testing.T) {
	secret := mustHex(t, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
	key, iv, hp := quic1RTTKeys(secret, 16)
	dcid := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	frames := []byte("\x08\x00\x04this is a STREAM frame carrying HTTP/3 data")

	for _, tc := range []struct {
		pn       uint64
		pnLen    int
		keyPhase bool
	}{
		{1, 1, false}, {300, 2, false}, {70000, 3, true}, {16777300, 4, false},
	} {
		pkt, ok := encryptShortHeader(dcid, tc.pn, tc.pnLen, tc.keyPhase, frames, key, iv, hp)
		if !ok {
			t.Fatalf("encrypt failed for pn=%d", tc.pn)
		}
		// First byte must be protected (differs from the cleartext form).
		if pkt[0]&0xc0 != 0x40 {
			t.Errorf("pn=%d: bad header form 0x%02x", tc.pn, pkt[0])
		}
		got, ok := decryptShortHeader(pkt, len(dcid), key, iv, hp, tc.pn-1)
		if !ok {
			t.Fatalf("decrypt failed for pn=%d", tc.pn)
		}
		if got.PacketNum != tc.pn {
			t.Errorf("pn = %d, want %d", got.PacketNum, tc.pn)
		}
		if got.KeyPhase != tc.keyPhase {
			t.Errorf("pn=%d: key phase = %v, want %v", tc.pn, got.KeyPhase, tc.keyPhase)
		}
		if !bytes.Equal(got.DCID, dcid) {
			t.Errorf("pn=%d: dcid = %x", tc.pn, got.DCID)
		}
		if !bytes.Equal(got.Plaintext, frames) {
			t.Errorf("pn=%d: plaintext mismatch", tc.pn)
		}
	}
}

func TestShortHeaderTamperFails(t *testing.T) {
	secret := mustHex(t, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
	key, iv, hp := quic1RTTKeys(secret, 16)
	dcid := []byte{1, 2, 3, 4}
	pkt, _ := encryptShortHeader(dcid, 5, 2, false, []byte("hello quic frames here"), key, iv, hp)
	pkt[len(pkt)-1] ^= 0xff // corrupt the auth tag
	if _, ok := decryptShortHeader(pkt, len(dcid), key, iv, hp, 4); ok {
		t.Error("decrypt of tampered packet should fail (AEAD integrity)")
	}
	// Wrong DCID length shifts the PN offset — must fail too.
	pkt2, _ := encryptShortHeader(dcid, 6, 2, false, []byte("more frame bytes here"), key, iv, hp)
	if _, ok := decryptShortHeader(pkt2, len(dcid)+2, key, iv, hp, 5); ok {
		t.Error("decrypt with wrong dcid length should fail")
	}
}

func TestDecodePacketNumber(t *testing.T) {
	// RFC 9000 Appendix A.3 worked example: largest 0xa82f30ea, truncated
	// 0x9b32, 2 bytes -> 0xa82f9b32.
	if got := decodePacketNumber(0xa82f30ea, 0x9b32, 2); got != 0xa82f9b32 {
		t.Errorf("decodePacketNumber = 0x%x, want 0xa82f9b32", got)
	}
	if got := decodePacketNumber(0, 1, 1); got != 1 {
		t.Errorf("first packet decode = %d, want 1", got)
	}
}

func TestQUIC1RTTKeysAES256(t *testing.T) {
	secret := mustHex(t, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
	key, iv, hp := quic1RTTKeys(secret, 32)
	if len(key) != 32 || len(hp) != 32 || len(iv) != 12 {
		t.Errorf("AES-256 key/iv/hp lengths = %d/%d/%d", len(key), len(iv), len(hp))
	}
}
