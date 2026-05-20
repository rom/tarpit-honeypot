package fingerprint

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

// JA3S produces the JA3S server-side TLS fingerprint from a raw
// ServerHello handshake message (the bytes starting with handshake
// type=0x02, i.e. after the 5-byte TLS record header). JA3S is the
// server-side analogue of JA3: where JA3 fingerprints the client's
// ClientHello, JA3S fingerprints how the server *responded* — the
// single cipher it selected, the version it chose, and the extensions
// it returned. Pairing the inbound JA3 with the JA3S we emit gives the
// (client, server) tuple threat-intel feeds key on.
//
// JA3S string layout:
//
//	SSLVersion,Cipher,SSLExtension
//
// Note there are only three fields — unlike JA3 there are no
// elliptic-curve or point-format fields, because the ServerHello does
// not echo those lists.
//
// The version field is the ServerHello legacy_version as-sent. We do
// NOT rewrite it from a supported_versions extension (a TLS 1.3 server
// reports legacy_version 0x0303 = 771): that matches how the canonical
// JA3S corpora were built, so our hashes line up with public datasets.
//
// Returns ("", "") on parse failure so callers can silently skip
// short / garbled input.
func JA3S(handshake []byte) (raw, hash string) {
	sh, ok := parseServerHello(handshake)
	if !ok {
		return "", ""
	}
	parts := []string{
		strconv.Itoa(int(sh.Version)),
		strconv.Itoa(int(sh.Cipher)),
		joinUint16(filterGREASE(sh.ExtensionTypes), "-"),
	}
	raw = strings.Join(parts, ",")
	sum := md5.Sum([]byte(raw))
	return raw, hex.EncodeToString(sum[:])
}

// serverHello is the subset of ServerHello fields JA3S needs.
type serverHello struct {
	Version        uint16
	Cipher         uint16
	ExtensionTypes []uint16
}

// parseServerHello walks the bytes from the start of a ServerHello
// Handshake message (type 0x02). Returns (sh, true) on success or
// (_, false) on malformed input.
func parseServerHello(b []byte) (serverHello, bool) {
	var sh serverHello
	// Handshake header: type(1)=0x02, length(3), then ServerHello body.
	if len(b) < 4 || b[0] != 0x02 {
		return sh, false
	}
	hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if hsLen+4 > len(b) {
		return sh, false
	}
	body := b[4 : 4+hsLen]
	// ServerHello body: legacy_version(2) random(32) session_id(1+...)
	// cipher_suite(2) compression(1) extensions(2+...)
	if len(body) < 2+32+1 {
		return sh, false
	}
	sh.Version = binary.BigEndian.Uint16(body[0:2])
	p := 2 + 32
	if p >= len(body) {
		return sh, false
	}
	sidLen := int(body[p])
	p++
	if p+sidLen > len(body) {
		return sh, false
	}
	p += sidLen
	if p+2 > len(body) {
		return sh, false
	}
	sh.Cipher = binary.BigEndian.Uint16(body[p : p+2])
	p += 2
	if p+1 > len(body) {
		return sh, false
	}
	p++ // compression method (1 byte)
	if p+2 > len(body) {
		// extensions absent (legacy) — still a valid ServerHello.
		return sh, true
	}
	extTotal := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2
	if p+extTotal > len(body) {
		return sh, false
	}
	end := p + extTotal
	for p+4 <= end {
		etype := binary.BigEndian.Uint16(body[p : p+2])
		elen := int(binary.BigEndian.Uint16(body[p+2 : p+4]))
		p += 4
		if p+elen > end {
			return sh, false
		}
		sh.ExtensionTypes = append(sh.ExtensionTypes, etype)
		p += elen
	}
	return sh, true
}
