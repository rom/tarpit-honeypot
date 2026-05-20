package fingerprint

import (
	"testing"
)

// FuzzJA3 feeds arbitrary bytes through the TLS ClientHello parser.
// The parser walks several length-prefixed sub-structures (cipher list,
// extensions, supported_groups, ec_point_formats) and must reject every
// malformed combination without panicking.
func FuzzJA3(f *testing.F) {
	f.Add(buildClientHello(
		[]uint16{0x1301}, []uint16{0x0000, 0x000a},
		[]uint16{0x001d}, false, false, 0x0303))
	f.Add([]byte{})
	f.Add([]byte{0x01, 0, 0, 0}) // handshake header only
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("JA3 panicked: %v", r)
			}
		}()
		_, _ = JA3(data)
		_ = JA4(data)
	})
}

// FuzzJA3S exercises the ServerHello parser (server-side TLS fingerprint).
// Must never panic on a malformed / truncated ServerHello.
func FuzzJA3S(f *testing.F) {
	f.Add(buildServerHello(0x0303, 0xc02f, []uint16{0xff01, 0x0000, 0x0010}))
	f.Add([]byte{})
	f.Add([]byte{0x02, 0, 0, 0}) // handshake header only
	f.Add([]byte{0x02, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("JA3S panicked: %v", r)
			}
		}()
		_, _ = JA3S(data)
	})
}

// FuzzHASSH feeds arbitrary bytes through the SSH KEXINIT parser.
func FuzzHASSH(f *testing.F) {
	f.Add([]byte{0x14}) // bare type byte, no cookie
	f.Add([]byte{})
	// Valid 4-name-list packet
	pkt := []byte{0x14}
	pkt = append(pkt, make([]byte, 16)...)
	for i := 0; i < 10; i++ {
		pkt = append(pkt, 0, 0, 0, 0)
	}
	f.Add(pkt)
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("HASSH panicked: %v", r)
			}
		}()
		_, _ = HASSH(data)
	})
}

// FuzzJA4H exercises the HTTP request line + header parser.
func FuzzJA4H(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("POST /admin HTTP/1.1\r\nCookie: a=b; c=d\r\nReferer: x\r\n\r\n"))
	f.Add([]byte(""))
	f.Add([]byte("\xff\xff\xff"))
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("JA4H panicked: %v", r)
			}
		}()
		_, _ = JA4H(data)
	})
}
