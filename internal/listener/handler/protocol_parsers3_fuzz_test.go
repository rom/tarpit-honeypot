package handler

// Third batch of protocol fuzz targets. The first group fuzzes pure decoders
// across more protocols (the `auto` protocol-guesser, TLS ServerHello capture,
// IEC-104 frame classification, MongoDB BSON key extraction, DCE/RPC UUID
// formatting, VNC RFB version, Beckhoff ADS/AMS NetID) and asserts their bounds
// invariants. The second group drives the binary industrial / auth / proxy
// handlers (Modbus, S7, DNP3, Kerberos, SOCKS) end-to-end via an in-memory
// conn, seeded with valid frames so mutation reaches the framing + dispatch
// logic that random bytes in FuzzTCPHandlers rarely form.
//
//	go test ./internal/listener/handler -run x -fuzz FuzzModbusHandler -fuzztime 60s

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// --- pure decoders ----------------------------------------------------------

func FuzzGuessProtocol(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05})       // TLS
	f.Add([]byte("SSH-2.0-x\r\n"))                    // SSH
	f.Add([]byte("GET / HTTP/1.1\r\n"))               // HTTP
	f.Add([]byte{0x05, 0x01, 0x00})                   // SOCKS5
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08}) // QUIC v1
	f.Add([]byte{})
	known := map[string]bool{
		"": true, "tls": true, "quic": true, "ssh": true, "http": true,
		"socks5": true, "socks4": true, "binary-len-prefixed": true, "text": true, "binary": true,
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if g := guessProtocol(data); !known[g] {
			t.Fatalf("guessProtocol returned an unknown label %q for %x", g, data)
		}
	})
}

func FuzzFirstServerHello(f *testing.F) {
	// A TLS record (type 0x16 handshake) carrying a ServerHello (0x02).
	hs := []byte{0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00}
	rec := append([]byte{0x16, 0x03, 0x03, 0x00, byte(len(hs))}, hs...)
	f.Add(rec)
	f.Add([]byte{0x16, 0x03, 0x03, 0xff, 0xff}) // claims a record bigger than captured
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if out := firstServerHello(data); out != nil && len(out) > len(data) {
			t.Fatalf("firstServerHello returned %d bytes from a %d-byte buffer", len(out), len(data))
		}
	})
}

func FuzzClassifyIEC104Frame(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}) // I-format
	f.Add([]byte{0x01, 0x00, 0x02, 0x00})                                                       // S-format
	f.Add([]byte{0x07, 0x00, 0x00, 0x00})                                                       // U-format (TESTFR)
	f.Add([]byte{0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		m := classifyFrame(data)
		if _, ok := m["control_type"]; !ok {
			t.Fatalf("classifyFrame produced no control_type for %x", data)
		}
	})
}

func FuzzFirstBSONKey(f *testing.F) {
	f.Add([]byte{0x16, 0, 0, 0, 0x02, 'h', 'e', 'l', 'l', 'o', 0})
	f.Add([]byte{0x05, 0, 0, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if k := firstBSONKey(data); len(k) > len(data) {
			t.Fatalf("firstBSONKey returned a %d-byte key from a %d-byte doc", len(k), len(data))
		}
	})
}

func FuzzUUIDString(f *testing.F) {
	f.Add(make([]byte, 16))
	f.Add([]byte("0123456789abcdef0123"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if s := uuidString(data); s != "" && len(s) != 36 {
			t.Fatalf("uuidString returned a non-canonical %d-char string: %q", len(s), s)
		}
	})
}

func FuzzRFBMinor(f *testing.F) {
	f.Add([]byte("RFB 003.008\n"))
	f.Add([]byte("RFB 003.00"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) { _ = rfbMinor(data) })
}

func FuzzAMSNetID(f *testing.F) {
	f.Add([]byte{192, 168, 1, 1, 1, 1})
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, data []byte) { _ = amsNetID(data) })
}

// --- binary handlers driven end-to-end with valid-frame seeds ---------------

// fuzzTCPHandler drives one named TCP handler over an in-memory conn. The
// handler is rebuilt per input so no state is shared across fuzz workers.
func fuzzTCPHandler(f *testing.F, name string, seeds ...[]byte) {
	dir := f.TempDir()
	for _, s := range seeds {
		f.Add(s)
	}
	cfg := config.Listener{ReadTimeout: 200 * time.Millisecond, ReadBytes: 8192}
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := Get(name, fuzzDeps(dir))
		if err != nil {
			t.Skip()
		}
		conn := &fuzzConn{data: data}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = h.Handle(ctx, conn, cfg) // a panic/hang fails the input
	})
}

func FuzzModbusHandler(f *testing.F) {
	fuzzTCPHandler(f, "modbus",
		[]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0a}, // read holding regs
		[]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x00, 0xff, 0x00}, // write single coil
		[]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x10, 0x00, 0x00, 0x00, 0x01}) // write multiple
}

func FuzzS7Handler(f *testing.F) {
	fuzzTCPHandler(f, "s7",
		// TPKT + COTP connection request.
		[]byte{0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00,
			0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02})
}

func FuzzDNP3Handler(f *testing.F) {
	fuzzTCPHandler(f, "dnp3",
		[]byte{0x05, 0x64, 0x05, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func FuzzKerberosHandler(f *testing.F) {
	fuzzTCPHandler(f, "kerberos",
		// 4-byte length prefix + an [APPLICATION 10] (AS-REQ) DER skeleton.
		[]byte{0x00, 0x00, 0x00, 0x0b, 0x6a, 0x09, 0x30, 0x07, 0xa1, 0x03, 0x02, 0x01, 0x05, 0x00, 0x00})
}

func FuzzSOCKSHandler(f *testing.F) {
	fuzzTCPHandler(f, "socks",
		[]byte{0x05, 0x02, 0x00, 0x01}, // SOCKS5 greeting
		append([]byte{0x04, 0x01, 0x01, 0xbb, 0x7f, 0x00, 0x00, 0x01}, []byte("root\x00")...)) // SOCKS4 connect
}
