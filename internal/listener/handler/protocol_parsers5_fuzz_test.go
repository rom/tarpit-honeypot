package handler

// Fifth batch: handler-level fuzzing of more UDP discovery/reflector protocols
// and TCP ICS / service protocols, each seeded with a valid frame so mutation
// reaches the framing + dispatch logic. Uses the fuzzTCPHandler / fuzzUDPHandler
// helpers from the earlier protocol fuzz files.
//
//	go test ./internal/listener/handler -run x -fuzz FuzzSNMPHandler -fuzztime 60s

import "testing"

// --- UDP -------------------------------------------------------------------

func FuzzSNMPHandler(f *testing.F) {
	// SNMPv1 GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0), community "public".
	fuzzUDPHandler(f, "snmp",
		[]byte{
			0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
			0xa0, 0x1c, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
			0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
		})
}

func FuzzNTPHandler(f *testing.F) {
	// Mode 3 (client), version 3 request — 48 bytes.
	seed := make([]byte, 48)
	seed[0] = 0x1b
	fuzzUDPHandler(f, "ntp", seed,
		// mode 7 (private) monlist-style request — the classic amplification probe.
		append([]byte{0x17, 0x00, 0x03, 0x2a}, make([]byte, 44)...))
}

func FuzzIPMIHandler(f *testing.F) {
	// RMCP header (version 6, class 7 = IPMI) + an ASF presence-ping-ish body.
	fuzzUDPHandler(f, "ipmi",
		[]byte{0x06, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x20, 0x18, 0xc8})
}

func FuzzRADIUSHandler(f *testing.F) {
	// Access-Request (code 1), id 1, length 20, 16-byte authenticator.
	fuzzUDPHandler(f, "radius",
		append([]byte{0x01, 0x01, 0x00, 0x14}, make([]byte, 16)...))
}

func FuzzSTUNHandler(f *testing.F) {
	// Binding Request: type 0x0001, len 0, magic cookie 2112A442, 12-byte txid.
	fuzzUDPHandler(f, "stun",
		append([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}, make([]byte, 12)...))
}

func FuzzISAKMPHandler(f *testing.F) {
	// IKE header: 8-byte init SPI, 8-byte resp SPI, then version/exchange/length.
	seed := make([]byte, 28)
	seed[16] = 0x01 // next payload (SA)
	seed[17] = 0x10 // version 1.0
	seed[18] = 0x02 // exchange: identity protection (main mode)
	seed[27] = 28   // length (low byte)
	fuzzUDPHandler(f, "isakmp", seed)
}

func FuzzFINSHandler(f *testing.F) {
	// Omron FINS/UDP: 10-byte routing header + command (MRC/SRC). Memory-area read.
	fuzzUDPHandler(f, "fins",
		[]byte{0x80, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x82, 0x00, 0x00, 0x00, 0x01})
}

func FuzzMDNSHandler(f *testing.F) {
	// mDNS query (DNS wire format) for "host.local" A IN, qdcount = 1.
	fuzzUDPHandler(f, "mdns",
		append(
			append([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte{0x04, 'h', 'o', 's', 't', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00}...),
			0x00, 0x01, 0x00, 0x01))
}

// --- TCP -------------------------------------------------------------------

func FuzzMQTTHandler(f *testing.F) {
	// MQTT 3.1.1 CONNECT: proto name "MQTT", level 4, clean session, client id.
	fuzzTCPHandler(f, "mqtt",
		[]byte{0x10, 0x13, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c,
			0x00, 0x07, 'c', 'l', 'i', 'e', 'n', 't', '1'})
}

func FuzzAMQPHandler(f *testing.F) {
	// AMQP 0-9-1 protocol header.
	fuzzTCPHandler(f, "amqp",
		[]byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01})
}

func FuzzDCERPCHandler(f *testing.F) {
	// DCE/RPC bind PDU: 16-byte header (version 5, ptype 11 = bind, LE drep,
	// frag_length 64) + a 48-byte bind body.
	seed := append([]byte{0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
		0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, make([]byte, 48)...)
	fuzzTCPHandler(f, "dcerpc", seed)
}

func FuzzIEC104HandlerTCP(f *testing.F) {
	// IEC 60870-5-104 APDU: start 0x68, length 4, U-format STARTDT activation.
	fuzzTCPHandler(f, "iec104",
		[]byte{0x68, 0x04, 0x07, 0x00, 0x00, 0x00})
}

func FuzzEtherNetIPHandler(f *testing.F) {
	// ENIP encapsulation: RegisterSession (0x0065), 24-byte header + 4-byte data.
	fuzzTCPHandler(f, "ethernetip",
		[]byte{0x65, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00})
}

func FuzzOPCUAHandler(f *testing.F) {
	// OPC-UA HELLO message: "HEL" + final chunk 'F' + msg length + body.
	fuzzTCPHandler(f, "opcua",
		[]byte{'H', 'E', 'L', 'F', 0x1c, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
			0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func FuzzJDWPHandler(f *testing.F) {
	fuzzTCPHandler(f, "jdwp", []byte("JDWP-Handshake"))
}

func FuzzRMIHandler(f *testing.F) {
	// JRMI magic + version 2 + StreamProtocol ('K').
	fuzzTCPHandler(f, "rmi", []byte{'J', 'R', 'M', 'I', 0x00, 0x02, 0x4b})
}

func FuzzADBHandler(f *testing.F) {
	// A well-formed ADB CNXN message built by the handler's own framer.
	fuzzTCPHandler(f, "adb",
		adbMessage("CNXN", 0x01000001, 256*1024, []byte("host::features=shell_v2\x00")),
		adbMessage("OPEN", 1, 0, []byte("shell:id\x00")))
}
