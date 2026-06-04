package handler

import (
	"crypto/aes"
	"crypto/cipher"
)

// QUIC 1-RTT (short-header) packet protection — the building block needed to
// capture an actual HTTP/3 request once a handshake is completed.
//
// SCOPE / STATUS: this is a verified, self-contained crypto layer, NOT a live
// capability. Decrypting 1-RTT application data requires the TLS 1.3 *handshake*
// to have completed so the application traffic secret is known, which in turn
// requires driving a full QUIC+TLS handshake across several datagrams. The
// sensor's UDP listener hands each handler a single datagram with no
// per-connection state, so a live handshake needs a new connection-oriented
// QUIC listener (see docs/design.md §15). This file implements the packet
// protection / unprotection per RFC 9001 §5.3–5.4 so that listener, when built,
// has a tested foundation — and so the key schedule is verifiable today against
// the RFC's published vectors.
//
// Only the AES-GCM cipher families are handled (the QUIC-mandatory
// AEAD_AES_128_GCM and AEAD_AES_256_GCM, whose header protection uses AES-ECB).
// ChaCha20-Poly1305 is out of scope here.

// quic1RTTKeys derives the QUIC packet-protection key, IV, and header-
// protection key from a TLS 1.3 traffic secret (RFC 9001 §5.1). keyLen is 16
// for AES-128-GCM or 32 for AES-256-GCM; the IV is always 12 bytes and the
// header-protection key matches keyLen. The label set ("quic key" / "quic iv"
// / "quic hp") is identical for Initial and 1-RTT — only the input secret
// differs — so this reuses the exact derivation the Initial path is verified
// against.
func quic1RTTKeys(secret []byte, keyLen int) (key, iv, hp []byte) {
	if keyLen != 16 && keyLen != 32 {
		keyLen = 16
	}
	key = hkdfExpandLabel(secret, "quic key", keyLen)
	iv = hkdfExpandLabel(secret, "quic iv", 12)
	hp = hkdfExpandLabel(secret, "quic hp", keyLen)
	return key, iv, hp
}

// quicShortHeaderResult is the parsed/decrypted 1-RTT packet.
type quicShortHeaderResult struct {
	DCID      []byte
	PacketNum uint64
	KeyPhase  bool
	Plaintext []byte // decrypted QUIC frames
	HeaderLen int    // bytes of (unprotected) header
}

// decryptShortHeader removes header protection and AEAD-decrypts a QUIC 1-RTT
// short-header packet (RFC 9001 §5.4.1 + §5.3). dcidLen is the
// destination-connection-ID length the endpoint chose at handshake time (not
// on the wire for short headers). largestPN is the largest packet number seen
// in this number space, used to reconstruct the truncated packet number.
func decryptShortHeader(p []byte, dcidLen int, key, iv, hp []byte, largestPN uint64) (quicShortHeaderResult, bool) {
	var out quicShortHeaderResult
	// Short header: first byte (0x40 fixed bit set, 0x80 clear) + DCID +
	// protected packet number + protected payload.
	if len(p) < 1+dcidLen+4+16 || p[0]&0xc0 != 0x40 {
		return out, false
	}
	pnOffset := 1 + dcidLen
	out.DCID = append([]byte(nil), p[1:pnOffset]...)

	block, err := aes.NewCipher(hp)
	if err != nil {
		return out, false
	}
	// Sample 16 bytes starting 4 bytes into the packet-number field.
	sampleOff := pnOffset + 4
	if sampleOff+16 > len(p) {
		return out, false
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, p[sampleOff:sampleOff+16])

	// Short header: low 5 bits of the first byte are protected.
	firstByte := p[0] ^ (mask[0] & 0x1f)
	out.KeyPhase = firstByte&0x04 != 0
	pnLen := int(firstByte&0x03) + 1

	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = p[pnOffset+i] ^ mask[1+i]
	}
	truncated := uint64(0)
	for _, b := range pnBytes {
		truncated = truncated<<8 | uint64(b)
	}
	out.PacketNum = decodePacketNumber(largestPN, truncated, pnLen)
	out.HeaderLen = pnOffset + pnLen

	// AEAD nonce = iv XOR left-padded packet number.
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(out.PacketNum >> (8 * i))
	}
	gcm, err := cipher.NewGCM(block2(key))
	if err != nil {
		return out, false
	}
	ciphertextStart := out.HeaderLen
	if ciphertextStart > len(p) {
		return out, false
	}
	// AAD is the header with the unprotected first byte + packet number.
	aad := make([]byte, ciphertextStart)
	copy(aad, p[:ciphertextStart])
	aad[0] = firstByte
	copy(aad[pnOffset:], pnBytes)

	plaintext, err := gcm.Open(nil, nonce, p[ciphertextStart:], aad)
	if err != nil {
		return out, false
	}
	out.Plaintext = plaintext
	return out, true
}

// encryptShortHeader is the inverse of decryptShortHeader: it protects a 1-RTT
// short-header packet for the given DCID, packet number, and frames. It exists
// so the protection logic is round-trip-testable and so a future QUIC listener
// can emit 1-RTT packets. pnLen is 1..4.
func encryptShortHeader(dcid []byte, pn uint64, pnLen int, keyPhase bool, frames, key, iv, hp []byte) ([]byte, bool) {
	if pnLen < 1 || pnLen > 4 {
		return nil, false
	}
	firstByte := byte(0x40) | byte(pnLen-1) // fixed bit set, spin/reserved 0
	if keyPhase {
		firstByte |= 0x04
	}
	hdr := make([]byte, 0, 1+len(dcid)+pnLen)
	hdr = append(hdr, firstByte)
	hdr = append(hdr, dcid...)
	pnFull := make([]byte, 4)
	pnFull[0] = byte(pn >> 24)
	pnFull[1] = byte(pn >> 16)
	pnFull[2] = byte(pn >> 8)
	pnFull[3] = byte(pn)
	pnBytes := pnFull[4-pnLen:]
	hdr = append(hdr, pnBytes...)

	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	gcm, err := cipher.NewGCM(block2(key))
	if err != nil {
		return nil, false
	}
	ciphertext := gcm.Seal(nil, nonce, frames, hdr)

	packet := append(append([]byte(nil), hdr...), ciphertext...)
	// Apply header protection using a sample 4 bytes past the PN start.
	pnOffset := 1 + len(dcid)
	sampleOff := pnOffset + 4
	if sampleOff+16 > len(packet) {
		return nil, false
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, false
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, packet[sampleOff:sampleOff+16])
	packet[0] ^= mask[0] & 0x1f
	for i := 0; i < pnLen; i++ {
		packet[pnOffset+i] ^= mask[1+i]
	}
	return packet, true
}

// decodePacketNumber reconstructs a full packet number from its truncated
// on-wire form (RFC 9000 Appendix A.3) given the largest number already seen.
func decodePacketNumber(largest, truncated uint64, pnLen int) uint64 {
	pnBits := uint(pnLen * 8)
	pnWin := uint64(1) << pnBits
	pnHalfWin := pnWin / 2
	expected := largest + 1
	candidate := (expected &^ (pnWin - 1)) | truncated
	if candidate+pnHalfWin <= expected && candidate+pnWin < (uint64(1)<<62) {
		return candidate + pnWin
	}
	if candidate > expected+pnHalfWin && candidate >= pnWin {
		return candidate - pnWin
	}
	return candidate
}
