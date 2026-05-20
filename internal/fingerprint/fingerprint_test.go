package fingerprint

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildClientHello synthesizes a minimal but valid ClientHello payload
// (starting with the Handshake type byte = 0x01). Real ClientHellos are
// far larger; we just need enough fields for JA3/JA4 to parse.
func buildClientHello(ciphers []uint16, exts []uint16, supportedGroups []uint16, withSNI bool, withALPN bool, tlsVersion uint16) []byte {
	hello := []byte{}
	hello = binary.BigEndian.AppendUint16(hello, tlsVersion) // legacy_version
	hello = append(hello, make([]byte, 32)...)               // random
	hello = append(hello, 0)                                 // session_id length = 0

	// cipher suites
	hello = binary.BigEndian.AppendUint16(hello, uint16(len(ciphers)*2))
	for _, c := range ciphers {
		hello = binary.BigEndian.AppendUint16(hello, c)
	}
	// compression methods
	hello = append(hello, 1, 0)

	// extensions
	extBlock := []byte{}
	for _, e := range exts {
		var edata []byte
		switch e {
		case 0x0000: // SNI
			if !withSNI {
				continue
			}
			sni := []byte("example.com")
			edata = append(edata, 0x00)                             // name_type host_name
			edata = append([]byte{0, byte(len(sni) + 3)}, edata...) // server_name_list length
			edata = append(edata, 0)                                // name_type=host_name
			edata = binary.BigEndian.AppendUint16(edata, uint16(len(sni)))
			edata = append(edata, sni...)
		case 0x0010: // ALPN
			if !withALPN {
				continue
			}
			protoBlock := []byte{}
			http11 := []byte("http/1.1")
			protoBlock = append(protoBlock, byte(len(http11)))
			protoBlock = append(protoBlock, http11...)
			edata = binary.BigEndian.AppendUint16(edata, uint16(len(protoBlock)))
			edata = append(edata, protoBlock...)
		case 0x000a: // supported_groups
			grpBlock := []byte{}
			for _, g := range supportedGroups {
				grpBlock = binary.BigEndian.AppendUint16(grpBlock, g)
			}
			edata = binary.BigEndian.AppendUint16(edata, uint16(len(grpBlock)))
			edata = append(edata, grpBlock...)
		case 0x000b: // ec_point_formats
			edata = []byte{1, 0}
		case 0x002b: // supported_versions
			edata = []byte{2, 0x03, 0x04}
		}
		extBlock = binary.BigEndian.AppendUint16(extBlock, e)
		extBlock = binary.BigEndian.AppendUint16(extBlock, uint16(len(edata)))
		extBlock = append(extBlock, edata...)
	}
	hello = binary.BigEndian.AppendUint16(hello, uint16(len(extBlock)))
	hello = append(hello, extBlock...)

	// Handshake header.
	out := []byte{0x01, 0, 0, 0}
	out[1] = byte(len(hello) >> 16)
	out[2] = byte(len(hello) >> 8)
	out[3] = byte(len(hello))
	return append(out, hello...)
}

func TestJA3Stable(t *testing.T) {
	pkt := buildClientHello(
		[]uint16{0x1301, 0x1302},
		[]uint16{0x0000, 0x000a, 0x000b, 0x0010},
		[]uint16{0x001d, 0x0017},
		true, true, 0x0303)

	raw1, hash1 := JA3(pkt)
	_, hash2 := JA3(pkt)
	if raw1 == "" || hash1 == "" {
		t.Fatal("JA3 empty")
	}
	if hash1 != hash2 {
		t.Fatalf("JA3 not deterministic: %s vs %s", hash1, hash2)
	}
	if strings.Count(raw1, ",") != 4 {
		t.Errorf("JA3 raw missing commas: %s", raw1)
	}
}

func TestJA3IgnoresGREASE(t *testing.T) {
	// Add a GREASE cipher; it must not appear in the raw string.
	pkt := buildClientHello(
		[]uint16{0x0a0a, 0x1301}, // 0x0A0A is GREASE
		[]uint16{0x000a, 0x000b},
		[]uint16{0x001d},
		false, false, 0x0303)
	raw, _ := JA3(pkt)
	if strings.Contains(raw, "2570") { // 0x0A0A = 2570
		t.Errorf("JA3 must strip GREASE; got %s", raw)
	}
}

func TestJA4Format(t *testing.T) {
	pkt := buildClientHello(
		[]uint16{0x1301, 0x1302, 0x1303},
		[]uint16{0x0000, 0x000a, 0x000b, 0x0010, 0x002b},
		[]uint16{0x001d, 0x0017},
		true, true, 0x0303)
	raw := JA4(pkt)
	if !strings.HasPrefix(raw, "t13") {
		t.Errorf("JA4 should detect TLS 1.3 (via supported_versions); got %s", raw)
	}
	parts := strings.Split(raw, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 should have 3 underscore-separated parts: %s", raw)
	}
}

func TestHASSH(t *testing.T) {
	// Build a minimal KEXINIT payload starting at the type byte.
	pkt := []byte{0x14}
	pkt = append(pkt, make([]byte, 16)...) // cookie
	// 10 name-lists. The 4 we care about are at indices 0, 2, 4, 6.
	names := []string{
		"curve25519-sha256,ecdh-sha2-nistp256", // kex
		"ssh-ed25519,ecdsa-sha2-nistp256",      // server_host_key
		"chacha20-poly1305@openssh.com",        // encryption_c2s
		"chacha20-poly1305@openssh.com",        // encryption_s2c
		"umac-64-etm@openssh.com",              // mac_c2s
		"umac-64-etm@openssh.com",              // mac_s2c
		"none,zlib@openssh.com",                // compression_c2s
		"none",                                 // compression_s2c
		"",                                     // languages_c2s
		"",                                     // languages_s2c
	}
	for _, n := range names {
		l := uint32(len(n))
		pkt = binary.BigEndian.AppendUint32(pkt, l)
		pkt = append(pkt, []byte(n)...)
	}
	raw, hash := HASSH(pkt)
	if raw == "" || hash == "" {
		t.Fatal("HASSH empty")
	}
	want := "curve25519-sha256,ecdh-sha2-nistp256;chacha20-poly1305@openssh.com;umac-64-etm@openssh.com;none,zlib@openssh.com"
	if raw != want {
		t.Errorf("HASSH raw mismatch:\n got %s\nwant %s", raw, want)
	}
	if len(hash) != 32 {
		t.Errorf("HASSH should be 32-char md5 hex; got %d chars", len(hash))
	}
}
