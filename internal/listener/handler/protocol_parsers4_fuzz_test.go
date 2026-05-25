package handler

// Fourth batch: handler-level fuzzing of more wire protocols, seeded with valid
// frames so mutation reaches the framing + dispatch logic. TCP handlers
// (SMB, Kafka, Cassandra, NATS) are driven over an in-memory conn; UDP handlers
// (CoAP, KNX, SSDP, DHCP, BACnet) over an in-memory packet conn. The generic
// FuzzTCPHandlers/FuzzUDPHandlers only ever feed random bytes; these give the
// fuzzer a real protocol frame to mutate around.
//
//	go test ./internal/listener/handler -run x -fuzz FuzzDHCPHandler -fuzztime 60s

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// fuzzUDPHandler drives one named UDP handler with a single datagram. The
// handler is rebuilt per input so reflection-limiter / honeynet state is never
// shared across fuzz workers.
func fuzzUDPHandler(f *testing.F, name string, seeds ...[]byte) {
	dir := f.TempDir()
	for _, s := range seeds {
		f.Add(s)
	}
	src := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 50000}
	pc := fuzzPacketConn{}
	cfg := config.Listener{ReadTimeout: 200 * time.Millisecond, ReadBytes: 8192}
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := GetUDP(name, fuzzDeps(dir))
		if err != nil {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = h.Handle(ctx, data, src, pc, cfg) // a panic/hang fails the input
	})
}

// --- TCP -------------------------------------------------------------------

func FuzzSMBHandler(f *testing.F) {
	// NetBIOS session header (type 0, 24-bit length 36) + SMB2 magic + body.
	smb := append([]byte{0x00, 0x00, 0x00, 0x24, 0xfe, 'S', 'M', 'B'}, make([]byte, 32)...)
	fuzzTCPHandler(f, "smb", smb)
}

func FuzzKafkaHandler(f *testing.F) {
	fuzzTCPHandler(f, "kafka",
		// size(4) apiKey(2)=18 ApiVersions apiVer(2)=3 corrID(4)=1
		[]byte{0x00, 0x00, 0x00, 0x0a, 0x00, 0x12, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01},
		// apiKey 3 = Metadata
		[]byte{0x00, 0x00, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x09, 0x00, 0x00, 0x00, 0x02})
}

func FuzzCassandraHandler(f *testing.F) {
	fuzzTCPHandler(f, "cassandra",
		[]byte{0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00},                   // v4 OPTIONS
		[]byte{0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x01, 0x00}) // STARTUP-ish
}

func FuzzNATSHandler(f *testing.F) {
	fuzzTCPHandler(f, "nats",
		[]byte("CONNECT {\"verbose\":false,\"name\":\"x\"}\r\nPING\r\nPUB foo 5\r\nhello\r\n"),
		[]byte("SUB inbox 1\r\nPING\r\n"))
}

// --- UDP -------------------------------------------------------------------

func FuzzCoAPHandler(f *testing.F) {
	fuzzUDPHandler(f, "coap",
		[]byte{0x40, 0x01, 0x12, 0x34},                                       // CON GET, no token
		[]byte{0x42, 0x01, 0x12, 0x34, 0xab, 0xcd, 0xb4, 't', 's', 't', 'x'}) // token + Uri-Path option
}

func FuzzKNXHandler(f *testing.F) {
	// SEARCH_REQUEST (0x0201): 6-byte header + 8-byte HPAI; total_len must
	// equal the datagram length (14) or the handler bails early.
	fuzzUDPHandler(f, "knx",
		[]byte{0x06, 0x10, 0x02, 0x01, 0x00, 0x0e, 0x08, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x0e, 0x57})
}

func FuzzSSDPHandler(f *testing.F) {
	fuzzUDPHandler(f, "ssdp",
		[]byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"+
			"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"))
}

func dhcpDiscoverSeed() []byte {
	p := make([]byte, 240)
	p[0] = 1                                                   // op = BOOTREQUEST
	p[1] = 1                                                   // htype = Ethernet
	p[2] = 6                                                   // hlen
	binary.BigEndian.PutUint32(p[4:8], 0x12345678)             // xid
	copy(p[28:34], []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}) // chaddr (MAC)
	copy(p[236:240], []byte{0x63, 0x82, 0x53, 0x63})           // BOOTP magic cookie
	p = append(p, 0x35, 0x01, 0x01)                            // option 53 = DHCP DISCOVER
	p = append(p, 0x37, 0x03, 0x01, 0x03, 0x06)                // option 55 = parameter request list
	p = append(p, 0xff)                                        // end
	return p
}

func FuzzDHCPHandler(f *testing.F) {
	fuzzUDPHandler(f, "dhcp", dhcpDiscoverSeed())
}

func FuzzBACnetHandler(f *testing.F) {
	// BVLC (81) Original-Broadcast-NPDU (0b) len 8 + NPDU (ver 1, ctl 0) +
	// APDU unconfirmed-request Who-Is (10 08).
	fuzzUDPHandler(f, "bacnet",
		[]byte{0x81, 0x0b, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08})
}
