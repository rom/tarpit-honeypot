package handler

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"net"

	"golang.org/x/crypto/hkdf"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
)

// quicH is a UDP QUIC / HTTP-3 receiver. A QUIC Initial packet is "encrypted",
// but with keys derived from a *public* salt and the client's connection ID
// (RFC 9001) — so anyone can decrypt an Initial. We do exactly that: derive
// the client initial keys, remove header protection, AES-128-GCM-decrypt the
// payload, reassemble the CRYPTO frames into the TLS ClientHello, and compute
// JA3/JA4 over it. That gives QUIC/HTTP-3 scans the same fingerprinting the TLS
// handlers give HTTPS — without implementing a QUIC transport.
//
// We never reply (a QUIC handshake needs real key exchange and a UDP reply to
// a spoofable source is a reflection risk), so this is a capture-only surface,
// like the UDP `auto` handler.
type quicH struct{}

func (q *quicH) Name() string { return "quic" }

// quicV1Salt is the fixed initial salt for QUIC v1 (RFC 9001 §5.2).
var quicV1Salt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// quicV2Salt is the initial salt for QUIC v2 (RFC 9369).
var quicV2Salt = []byte{
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
	0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
}

func (q *quicH) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{"proto": "quic"}}
	res.Payload = payload

	ch, version, ok := quicClientHello(payload)
	if !ok {
		res.Meta["quic"] = "no-clienthello"
		return res, nil
	}
	res.Meta["quic_version"] = quicVersionName(version)
	if raw, hash := fingerprint.JA3(ch); hash != "" {
		res.Meta["ja3"] = hash
		res.Meta["ja3_raw"] = raw
	}
	if ja4 := fingerprint.JA4(ch); ja4 != "" {
		res.Meta["ja4"] = ja4
	}
	flagAnomaly(&res, "quic-initial")

	// Deep-parse the decrypted ClientHello for the request-shaping fields:
	// the SNI host, the ALPN list (which reveals HTTP/3), and the QUIC
	// transport parameters. The actual 1-RTT HTTP/3 request stays encrypted
	// without a completed handshake (out of scope — see quic_clienthello.go).
	hi := parseQUICClientHello(ch)
	if hi.SNI != "" {
		res.Meta["quic_sni"] = hi.SNI
	}
	if len(hi.ALPN) > 0 {
		res.Meta["quic_alpn"] = hi.ALPN
	}
	if len(hi.TransportParam) > 0 {
		res.Meta["quic_transport_params"] = hi.TransportParam
	}
	if hi.HTTP3 {
		res.Meta["http3"] = true
		flagAnomaly(&res, "quic-http3")
	}
	return res, nil
}

// quicClientHello decrypts a QUIC Initial packet and returns the TLS
// Handshake message (the ClientHello) reassembled from its CRYPTO frames, plus
// the QUIC version. Returns ok=false for anything that isn't a decryptable
// v1/v2 Initial carrying a ClientHello.
func quicClientHello(p []byte) (handshake []byte, version uint32, ok bool) {
	// Long header: first byte has 0x80 (header form) + 0x40 (fixed bit); the
	// low bits are protected. Then version(4), DCID len(1)+DCID, SCID len(1)+SCID.
	if len(p) < 7 || p[0]&0xc0 != 0xc0 {
		return nil, 0, false
	}
	version = binary.BigEndian.Uint32(p[1:5])
	salt, vok := quicSaltFor(version)
	if !vok {
		return nil, version, false
	}
	off := 5
	dcidLen := int(p[off])
	off++
	if off+dcidLen > len(p) {
		return nil, version, false
	}
	dcid := p[off : off+dcidLen]
	off += dcidLen
	if off >= len(p) {
		return nil, version, false
	}
	scidLen := int(p[off])
	off++
	off += scidLen
	if off >= len(p) {
		return nil, version, false
	}
	// Initial packet: token length (varint) + token, then payload length
	// (varint), then the protected packet-number + payload.
	tokLen, n := quicVarint(p[off:])
	if n == 0 {
		return nil, version, false
	}
	off += n + int(tokLen)
	if off >= len(p) {
		return nil, version, false
	}
	payLen, n := quicVarint(p[off:])
	if n == 0 {
		return nil, version, false
	}
	off += n
	pnOffset := off
	if pnOffset+int(payLen) > len(p) || int(payLen) < 20 {
		return nil, version, false
	}

	key, iv, hp, derr := quicInitialKeys(salt, dcid)
	if derr != nil {
		return nil, version, false
	}

	// Header protection: sample 16 bytes starting 4 bytes past the PN offset,
	// AES-ECB encrypt with hp to get the mask, then unprotect the first byte
	// and the packet number.
	sampleOff := pnOffset + 4
	if sampleOff+16 > len(p) {
		return nil, version, false
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, version, false
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, p[sampleOff:sampleOff+16])

	// Recover the unprotected first byte and packet number.
	firstByte := p[0] ^ (mask[0] & 0x0f) // long header: low 4 bits protected
	pnLen := int(firstByte&0x03) + 1
	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = p[pnOffset+i] ^ mask[1+i]
	}
	pn := uint64(0)
	for i := 0; i < pnLen; i++ {
		pn = pn<<8 | uint64(pnBytes[i])
	}

	// AEAD nonce = iv XOR left-padded packet number.
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}

	aead, err := cipher.NewGCM(block2(key))
	if err != nil {
		return nil, version, false
	}
	ciphertextStart := pnOffset + pnLen
	ciphertextEnd := pnOffset + int(payLen)
	if ciphertextStart >= ciphertextEnd || ciphertextEnd > len(p) {
		return nil, version, false
	}
	// AAD is the packet header with the unprotected first byte + packet number,
	// from byte 0 through the end of the (now-known-length) packet number.
	aad := make([]byte, ciphertextStart)
	copy(aad, p[:ciphertextStart])
	aad[0] = firstByte
	copy(aad[pnOffset:], pnBytes)
	plaintext, err := aead.Open(nil, nonce, p[ciphertextStart:ciphertextEnd], aad)
	if err != nil {
		return nil, version, false
	}

	cryptoData, ok := quicReassembleCrypto(plaintext)
	if !ok || len(cryptoData) < 4 || cryptoData[0] != 0x01 {
		return nil, version, false
	}
	return cryptoData, version, true
}

func quicSaltFor(v uint32) ([]byte, bool) {
	switch v {
	case 0x00000001:
		return quicV1Salt, true
	case 0x6b3343cf: // QUIC v2 (RFC 9369)
		return quicV2Salt, true
	default:
		return nil, false
	}
}

// quicInitialKeys derives the client initial key, iv, and header-protection
// key per RFC 9001 §5.1–5.2.
func quicInitialKeys(salt, dcid []byte) (key, iv, hp []byte, err error) {
	initialSecret := hkdfExtract(salt, dcid)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", 32)
	key = hkdfExpandLabel(clientSecret, "quic key", 16)
	iv = hkdfExpandLabel(clientSecret, "quic iv", 12)
	hp = hkdfExpandLabel(clientSecret, "quic hp", 16)
	return key, iv, hp, nil
}

func hkdfExtract(salt, ikm []byte) []byte {
	r := hkdf.Extract(sha256.New, ikm, salt)
	return r
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0x00) // zero-length context
	out := make([]byte, length)
	r := hkdf.Expand(sha256.New, secret, info)
	_, _ = r.Read(out)
	return out
}

func block2(key []byte) cipher.Block {
	b, _ := aes.NewCipher(key)
	return b
}

// quicReassembleCrypto walks the decrypted Initial payload's frames and
// concatenates the CRYPTO frame (0x06) data in offset order (the common case is
// a single CRYPTO frame at offset 0). PADDING (0x00) and PING (0x01) are
// skipped; an unrecognized frame stops the walk (whatever CRYPTO we have by
// then is enough to fingerprint the ClientHello head).
func quicReassembleCrypto(b []byte) ([]byte, bool) {
	type chunk struct {
		off  uint64
		data []byte
	}
	var chunks []chunk
	i := 0
	for i < len(b) {
		switch b[i] {
		case 0x00: // PADDING
			i++
		case 0x01: // PING
			i++
		case 0x06: // CRYPTO
			i++
			off, n := quicVarint(b[i:])
			if n == 0 {
				return nil, false
			}
			i += n
			ln, n2 := quicVarint(b[i:])
			if n2 == 0 {
				return nil, false
			}
			i += n2
			if i+int(ln) > len(b) {
				return nil, false
			}
			chunks = append(chunks, chunk{off: off, data: append([]byte(nil), b[i:i+int(ln)]...)})
			i += int(ln)
		default:
			// Unknown / unsupported frame: stop. If we already have CRYPTO at
			// offset 0 that's enough to fingerprint the ClientHello head.
			i = len(b)
		}
	}
	if len(chunks) == 0 {
		return nil, false
	}
	// Order by offset and concatenate contiguous data from 0. Skip
	// zero-length chunks and stop as soon as no chunk advances the cursor —
	// otherwise a CRYPTO frame with length 0 at offset 0 would spin forever
	// (next never advances) allocating without bound.
	var out []byte
	for next := uint64(0); ; {
		found := false
		for _, c := range chunks {
			if c.off == next && len(c.data) > 0 {
				out = append(out, c.data...)
				next += uint64(len(c.data))
				found = true
			}
		}
		if !found {
			break
		}
	}
	return out, len(out) > 0
}

// quicVarint decodes a QUIC variable-length integer (RFC 9000 §16),
// returning the value and the number of bytes consumed (0 on error).
func quicVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	prefix := b[0] >> 6
	length := 1 << prefix
	if len(b) < length {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		v = v<<8 | uint64(b[i])
	}
	// A QUIC varint maxes out at 2^62-1 (the 2-bit length prefix is masked
	// off above), which always fits in an int64. Cap defensively anyway so a
	// later int() conversion can never go negative even on a 32-bit build —
	// the callers add these to a buffer offset.
	if v > 1<<31 {
		v = 1 << 31
	}
	return v, length
}

func quicVersionName(v uint32) string {
	switch v {
	case 0x00000001:
		return "QUIC v1"
	case 0x6b3343cf:
		return "QUIC v2"
	default:
		return "QUIC"
	}
}
