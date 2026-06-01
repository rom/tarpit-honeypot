package handler

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
)

// sampleTLSClientHello builds a minimal TLS ClientHello handshake message
// (type 0x01) with two cipher suites and one extension — enough for JA3/JA4.
func sampleTLSClientHello() []byte {
	body := []byte{0x03, 0x03} // legacy_version TLS 1.2
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)                               // session_id len
	body = append(body, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02) // 2 cipher suites
	body = append(body, 0x01, 0x00)                         // compression null
	ext := []byte{0x00, 0x2b, 0x00, 0x00}                   // supported_versions, len 0
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

// buildQUICInitial encrypts a CRYPTO(ClientHello) into a QUIC v1 Initial packet
// using the same (RFC-9001-verified) key schedule the handler decrypts with.
func buildQUICInitial(t *testing.T, dcid []byte, ch []byte) []byte {
	t.Helper()
	key, iv, hp, err := quicInitialKeys(quicV1Salt, dcid)
	if err != nil {
		t.Fatal(err)
	}

	// CRYPTO frame: type 0x06, offset 0, length, data. Pad to >= sample size.
	crypto := []byte{0x06, 0x00, byte(len(ch))}
	if len(ch) > 63 {
		// 2-byte varint length.
		crypto = []byte{0x06, 0x00, 0x40 | byte(len(ch)>>8), byte(len(ch))}
	}
	crypto = append(crypto, ch...)
	// Pad the QUIC payload so the header-protection sample (16 bytes past the
	// PN) is always present.
	for len(crypto) < 64 {
		crypto = append(crypto, 0x00) // PADDING frames
	}

	pnLen := 1
	pn := byte(0)
	// Build the unprotected header: first byte (long, Initial, pnLen-1),
	// version, DCID, SCID(0), token(0), payload length(varint), PN.
	// The QUIC Length field covers the packet number + the encrypted payload +
	// the AEAD tag.
	payloadLen := pnLen + len(crypto) + 16
	var pktLenVarint []byte
	if payloadLen < 64 {
		pktLenVarint = []byte{byte(payloadLen)}
	} else {
		pktLenVarint = []byte{0x40 | byte(payloadLen>>8), byte(payloadLen)}
	}

	hdr := []byte{0xc0 | byte(pnLen-1)} // header form+fixed+Initial(00)+pnLen
	ver := make([]byte, 4)
	binary.BigEndian.PutUint32(ver, 0x00000001)
	hdr = append(hdr, ver...)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00) // SCID len 0
	hdr = append(hdr, 0x00) // token len 0
	hdr = append(hdr, pktLenVarint...)
	pnOffset := len(hdr)
	hdr = append(hdr, pn)

	// AEAD encrypt the payload with AAD = header (incl. PN).
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, len(iv))
	copy(nonce, iv) // pn=0 → nonce == iv
	sealed := aead.Seal(nil, nonce, crypto, hdr)

	pkt := append(append([]byte(nil), hdr...), sealed...)

	// Apply header protection: sample 16 bytes 4 past the PN offset.
	sampleOff := pnOffset + 4
	hpBlock, _ := aes.NewCipher(hp)
	mask := make([]byte, 16)
	hpBlock.Encrypt(mask, pkt[sampleOff:sampleOff+16])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt
}

func TestQUICDecryptsInitialAndFingerprints(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	ch := sampleTLSClientHello()
	pkt := buildQUICInitial(t, dcid, ch)

	gotCH, version, ok := quicClientHello(pkt)
	if !ok {
		t.Fatal("handler failed to decrypt a valid QUIC v1 Initial")
	}
	if version != 0x00000001 {
		t.Errorf("version = %#x, want QUIC v1", version)
	}
	// The recovered handshake must start with ClientHello (0x01) and produce
	// the same JA4 as the original ClientHello.
	if gotCH[0] != 0x01 {
		t.Fatalf("recovered crypto does not start with ClientHello: %#x", gotCH[0])
	}
	if fingerprint.JA4(gotCH) != fingerprint.JA4(ch) {
		t.Errorf("JA4 from decrypted QUIC CH != JA4 of the original")
	}
}

func TestQUICHandlerEmitsJA4(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	pkt := buildQUICInitial(t, dcid, sampleTLSClientHello())
	res, err := (&quicH{}).Handle(context.Background(), pkt, &net.UDPAddr{}, nil, config.Listener{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["ja4"] == nil || res.Meta["ja4"] == "" {
		t.Errorf("expected ja4 from QUIC Initial; meta=%v", res.Meta)
	}
	if res.Meta["quic_version"] != "QUIC v1" {
		t.Errorf("quic_version = %v, want QUIC v1", res.Meta["quic_version"])
	}
	if !hasAnomaly(res, "quic-initial") {
		t.Errorf("expected quic-initial anomaly; got %v", anomaliesOf(res))
	}
}

func TestQUICNonInitialIgnored(t *testing.T) {
	res, _ := (&quicH{}).Handle(context.Background(), []byte("not a quic packet"), &net.UDPAddr{}, nil, config.Listener{})
	if res.Meta["ja4"] != nil {
		t.Errorf("non-QUIC input should not fingerprint")
	}
	if res.Meta["quic"] != "no-clienthello" {
		t.Errorf("expected no-clienthello marker, got %v", res.Meta["quic"])
	}
}
