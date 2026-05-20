// Package fingerprint computes well-known fingerprints (JA3, JA4, HASSH)
// from the application-layer handshake bytes we already capture. The
// honeypot handlers feed raw bytes in; this package returns a stable
// short string identifying the client tool / library combo.
package fingerprint

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// JA3 produces the classic JA3 fingerprint from a raw TLS ClientHello
// (the bytes after the 5-byte TLS record header, i.e. the Handshake
// protocol message starting with type=0x01).
//
// JA3 string layout:
//
//	SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
//
// Returns ("", "") on parse failure rather than an error so callers can
// silently skip when input is short / garbled.
func JA3(handshake []byte) (raw, hash string) {
	ch, ok := parseClientHello(handshake)
	if !ok {
		return "", ""
	}
	parts := []string{
		strconv.Itoa(int(ch.Version)),
		joinUint16(filterGREASE(ch.CipherSuites), "-"),
		joinUint16(filterGREASE(ch.ExtensionTypes), "-"),
		joinUint16(filterGREASE(ch.SupportedGroups), "-"),
		joinUint8(ch.ECPointFormats, "-"),
	}
	raw = strings.Join(parts, ",")
	sum := md5.Sum([]byte(raw))
	return raw, hex.EncodeToString(sum[:])
}

// JA4 produces the newer JA4 fingerprint from the same ClientHello. JA4 is
// designed to survive client randomization (extension shuffling). Format:
//
//	t13d{n}{n}_{cipher_hash}_{ext_hash}
//
// where t13 = TLS 1.3 transport, d = direction (we always observe inbound),
// the two digit groups encode #ciphers and #extensions, and the two hashes
// are first-12-hex of SHA-256 over the sorted cipher and sorted extension
// (with SNI + ALPN removed) lists. We implement the most-cited variant —
// JA4 has a family of related strings (JA4S, JA4H, etc.) but only "JA4"
// itself is computed here.
func JA4(handshake []byte) (raw string) {
	ch, ok := parseClientHello(handshake)
	if !ok {
		return ""
	}
	ciphers := filterGREASE(ch.CipherSuites)
	exts := filterGREASE(ch.ExtensionTypes)

	// JA4 strips SNI (0x00) and ALPN (0x10) from the extension list before
	// hashing, because both are routinely set by clients and would
	// over-segment otherwise.
	var keptExts []uint16
	for _, e := range exts {
		if e == 0x00 || e == 0x10 {
			continue
		}
		keptExts = append(keptExts, e)
	}

	// Sort both for shuffling resistance.
	sortUint16(ciphers)
	sortUint16(keptExts)

	cipherList := joinUint16Hex4(ciphers, ",")
	extList := joinUint16Hex4(keptExts, ",")

	cipherHash := sha256Trunc(cipherList, 12)
	extHash := sha256Trunc(extList, 12)

	protoVer := tlsVersionDigits(ch.Version)
	sni := "i" // i = "no SNI present"
	if ch.HasSNI {
		sni = "d"
	}
	alpn := "00"
	if len(ch.ALPNFirst) >= 2 {
		alpn = fmt.Sprintf("%02x", ch.ALPNFirst[0])
	}

	nc := boundedCount(len(ciphers))
	ne := boundedCount(len(exts))

	return fmt.Sprintf("t%s%s%s%s_%s_%s",
		protoVer, sni, nc, ne+alpn, cipherHash, extHash)
}

// clientHello is the subset of fields JA3 / JA4 need.
type clientHello struct {
	Version         uint16
	CipherSuites    []uint16
	ExtensionTypes  []uint16
	SupportedGroups []uint16
	ECPointFormats  []uint8
	HasSNI          bool
	ALPNFirst       []byte
}

// parseClientHello walks the bytes from the start of the Handshake message.
// Returns (ch, true) on success or (_, false) on malformed input.
func parseClientHello(b []byte) (clientHello, bool) {
	var ch clientHello
	// Handshake header: type(1)=0x01, length(3), then ClientHello body.
	if len(b) < 4 || b[0] != 0x01 {
		return ch, false
	}
	hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if hsLen+4 > len(b) {
		return ch, false
	}
	body := b[4 : 4+hsLen]
	// ClientHello body: legacy_version(2) random(32) session_id(1+...) ciphers(2+...) compression(1+...) extensions(2+...)
	if len(body) < 2+32+1 {
		return ch, false
	}
	ch.Version = binary.BigEndian.Uint16(body[0:2])
	p := 2 + 32
	if p >= len(body) {
		return ch, false
	}
	sidLen := int(body[p])
	p++
	if p+sidLen > len(body) {
		return ch, false
	}
	p += sidLen
	if p+2 > len(body) {
		return ch, false
	}
	cipherLen := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2
	if p+cipherLen > len(body) || cipherLen%2 != 0 {
		return ch, false
	}
	for i := 0; i < cipherLen; i += 2 {
		ch.CipherSuites = append(ch.CipherSuites, binary.BigEndian.Uint16(body[p+i:p+i+2]))
	}
	p += cipherLen
	if p >= len(body) {
		return ch, false
	}
	compLen := int(body[p])
	p += 1 + compLen
	if p+2 > len(body) {
		// extensions absent (legacy)
		return ch, true
	}
	extTotal := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2
	if p+extTotal > len(body) {
		return ch, false
	}
	end := p + extTotal
	for p+4 <= end {
		etype := binary.BigEndian.Uint16(body[p : p+2])
		elen := int(binary.BigEndian.Uint16(body[p+2 : p+4]))
		p += 4
		if p+elen > end {
			return ch, false
		}
		edata := body[p : p+elen]
		ch.ExtensionTypes = append(ch.ExtensionTypes, etype)
		switch etype {
		case 0x0000: // SNI
			ch.HasSNI = true
		case 0x000a: // supported_groups
			if len(edata) >= 2 {
				gl := int(binary.BigEndian.Uint16(edata[0:2]))
				if 2+gl <= len(edata) {
					for i := 0; i+2 <= gl; i += 2 {
						ch.SupportedGroups = append(ch.SupportedGroups, binary.BigEndian.Uint16(edata[2+i:2+i+2]))
					}
				}
			}
		case 0x000b: // ec_point_formats
			if len(edata) >= 1 {
				fl := int(edata[0])
				if 1+fl <= len(edata) {
					for i := 0; i < fl; i++ {
						ch.ECPointFormats = append(ch.ECPointFormats, edata[1+i])
					}
				}
			}
		case 0x0010: // ALPN
			if len(edata) >= 4 {
				ch.ALPNFirst = edata
			}
		case 0x002b: // supported_versions — if a TLS 1.3 ID is present, treat that as effective version
			if len(edata) >= 3 {
				ll := int(edata[0])
				if 1+ll <= len(edata) {
					for i := 0; i+2 <= ll; i += 2 {
						v := binary.BigEndian.Uint16(edata[1+i : 1+i+2])
						if v == 0x0304 {
							ch.Version = 0x0304
						}
					}
				}
			}
		}
		p += elen
	}
	return ch, true
}

// filterGREASE removes the "Generate Random Extensions And Sustain Extensibility"
// values (RFC 8701) so fingerprints stay stable across browser-randomized
// ClientHellos.
func filterGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if isGREASE(v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func isGREASE(v uint16) bool {
	// GREASE values: 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xFAFA — pattern 0x?A?A
	return v&0x0f0f == 0x0a0a
}

func joinUint16(in []uint16, sep string) string {
	parts := make([]string, len(in))
	for i, v := range in {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, sep)
}

func joinUint8(in []uint8, sep string) string {
	parts := make([]string, len(in))
	for i, v := range in {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, sep)
}

func joinUint16Hex4(in []uint16, sep string) string {
	parts := make([]string, len(in))
	for i, v := range in {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, sep)
}

func sortUint16(s []uint16) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func boundedCount(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func tlsVersionDigits(v uint16) string {
	switch v {
	case 0x0301:
		return "10"
	case 0x0302:
		return "11"
	case 0x0303:
		return "12"
	case 0x0304:
		return "13"
	}
	return "00"
}
