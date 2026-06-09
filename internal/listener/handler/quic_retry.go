package handler

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// QUIC Retry packet construction + long-header parsing.
//
// A Retry (RFC 9000 §17.2.5) is how a QUIC server validates a client's source
// address before committing handshake state: it carries an opaque token the
// client must echo in a retried Initial. RFC 9001 §5.8 binds the Retry to the
// connection with a Retry Integrity Tag — AES-128-GCM over a "Retry
// Pseudo-Packet" (the client's original DCID, length-prefixed, followed by the
// Retry packet bytes) under a fixed, version-specific key and nonce. We compute
// it exactly, so the Retry we emit is one a real client accepts — which is what
// makes a retried, token-echoing Initial proof that the source address is real
// (a Retry is also smaller than the >=1200-byte Initial it answers, so it can
// never be an amplifier).

// quicRetryKeys returns the Retry-integrity AES-128-GCM key + nonce for a QUIC
// version (RFC 9001 §5.8 for v1; RFC 9369 §3.3.3 for v2).
func quicRetryKeys(version uint32) (key, nonce []byte, ok bool) {
	switch version {
	case 0x00000001: // QUIC v1
		return []byte{0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e},
			[]byte{0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb}, true
	case 0x6b3343cf: // QUIC v2
		return []byte{0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92},
			[]byte{0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a}, true
	}
	return nil, nil, false
}

// quicRetryFirstByte returns the long-header first byte for a Retry packet. The
// type bits differ by version (v1: 0b11; v2: 0b00); the low 4 bits are unused
// and set to 0.
func quicRetryFirstByte(version uint32) byte {
	if version == 0x6b3343cf { // v2 Retry = type 0b00
		return 0xc0
	}
	return 0xf0 // v1 Retry = type 0b11 -> 0xc0 | (0b11 << 4)
}

// quicRetryIntegrityTag computes the 16-byte Retry Integrity Tag over the Retry
// Pseudo-Packet: the ODCID length-prefixed, the ODCID, then the Retry packet
// bytes excluding the tag itself.
func quicRetryIntegrityTag(version uint32, odcid, retryNoTag []byte) ([]byte, bool) {
	rkey, rnonce, ok := quicRetryKeys(version)
	if !ok {
		return nil, false
	}
	pseudo := make([]byte, 0, 1+len(odcid)+len(retryNoTag))
	pseudo = append(pseudo, byte(len(odcid)))
	pseudo = append(pseudo, odcid...)
	pseudo = append(pseudo, retryNoTag...)
	block, err := aes.NewCipher(rkey)
	if err != nil {
		return nil, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	// Empty plaintext, AAD = pseudo-packet → the 16-byte tag is the ciphertext.
	return aead.Seal(nil, rnonce, nil, pseudo), true
}

// buildQUICRetry assembles a complete Retry packet: it echoes the client's SCID
// as the Retry's DCID (so the client accepts it), advertises a fresh server
// SCID, carries the token the client must echo, and appends the Retry Integrity
// Tag binding the client's original DCID (odcid).
func buildQUICRetry(version uint32, odcid, clientSCID, serverSCID, token []byte) ([]byte, bool) {
	if len(clientSCID) > 20 || len(serverSCID) > 20 || len(odcid) > 20 {
		return nil, false
	}
	var pkt []byte
	pkt = append(pkt, quicRetryFirstByte(version))
	ver := make([]byte, 4)
	binary.BigEndian.PutUint32(ver, version)
	pkt = append(pkt, ver...)
	pkt = append(pkt, byte(len(clientSCID)))
	pkt = append(pkt, clientSCID...)
	pkt = append(pkt, byte(len(serverSCID)))
	pkt = append(pkt, serverSCID...)
	pkt = append(pkt, token...)
	tag, ok := quicRetryIntegrityTag(version, odcid, pkt)
	if !ok {
		return nil, false
	}
	return append(pkt, tag...), true
}

// parseQUICLongHeader extracts the version + DCID + SCID from a QUIC long-header
// packet plus the offset just past the SCID. The connection IDs are
// unprotected, so this needs no keys.
func parseQUICLongHeader(p []byte) (version uint32, dcid, scid []byte, hdrEnd int, ok bool) {
	if len(p) < 7 || p[0]&0xc0 != 0xc0 {
		return 0, nil, nil, 0, false
	}
	version = binary.BigEndian.Uint32(p[1:5])
	off := 5
	dl := int(p[off])
	off++
	if off+dl > len(p) {
		return version, nil, nil, 0, false
	}
	dcid = p[off : off+dl]
	off += dl
	if off >= len(p) {
		return version, dcid, nil, 0, false
	}
	sl := int(p[off])
	off++
	if off+sl > len(p) {
		return version, dcid, nil, 0, false
	}
	scid = p[off : off+sl]
	off += sl
	return version, dcid, scid, off, true
}

// quicIsInitial reports whether a long-header first byte denotes an Initial
// packet for the version. The long-header type bits are not protected, so this
// is readable on the wire. v1 Initial = type 0b00; v2 Initial = type 0b01.
func quicIsInitial(version uint32, first byte) bool {
	t := first & 0x30
	if version == 0x6b3343cf {
		return t == 0x10
	}
	return t == 0x00
}

// quicInitialToken returns the address-validation token carried in an Initial
// packet — the field a client echoes after it has accepted a Retry.
func quicInitialToken(p []byte) ([]byte, bool) {
	_, _, _, off, ok := parseQUICLongHeader(p)
	if !ok || off >= len(p) {
		return nil, false
	}
	tl, n := quicVarint(p[off:])
	if n == 0 {
		return nil, false
	}
	off += n
	if off+int(tl) > len(p) {
		return nil, false
	}
	return p[off : off+int(tl)], true
}
