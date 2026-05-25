package handler

// Eighth batch: VoIP signalling and the remaining UDP discovery / name-service
// protocols, seeded with valid frames. TCP: SCCP (Skinny), H.323 (Q.931 over
// TPKT), Asterisk AMI. UDP: SIP, IAX2, CLDAP, LLMNR, NBNS, NetBIOS datagram,
// PROFINET-IO (DCE/RPC), VxWorks WDB-RPC, syslog.
//
//	go test ./internal/listener/handler -run x -fuzz FuzzSIPUDPHandler -fuzztime 60s

import "testing"

// --- TCP VoIP --------------------------------------------------------------

func FuzzSCCPHandler(f *testing.F) {
	// Skinny: dataLength(4 LE) + reserved(4) + messageID(4) — a KeepAlive/Register.
	fuzzTCPHandler(f, "sccp",
		[]byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func FuzzH323Handler(f *testing.F) {
	// TPKT v3 + Q.931 (protocol discriminator 0x08) SETUP-ish.
	fuzzTCPHandler(f, "h323",
		[]byte{0x03, 0x00, 0x00, 0x0a, 0x08, 0x02, 0x00, 0x01, 0x05, 0x04})
}

func FuzzAsteriskAMIHandler(f *testing.F) {
	fuzzTCPHandler(f, "asterisk_ami",
		[]byte("Action: Login\r\nUsername: admin\r\nSecret: secret\r\n\r\n"+
			"Action: Command\r\nCommand: core show version\r\n\r\n"))
}

// --- UDP -------------------------------------------------------------------

func FuzzSIPUDPHandler(f *testing.F) {
	fuzzUDPHandler(f, "sip",
		[]byte("OPTIONS sip:probe@t SIP/2.0\r\nVia: SIP/2.0/UDP h:5060\r\n"+
			"From: <sip:a>;tag=1\r\nTo: <sip:b>\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n\r\n"),
		[]byte("INVITE sip:victim@t SIP/2.0\r\nVia: SIP/2.0/UDP h\r\nCSeq: 1 INVITE\r\n\r\n"))
}

func FuzzIAX2Handler(f *testing.F) {
	// IAX2 full frame (high bit of byte 0 set) + a 12-byte header.
	fuzzUDPHandler(f, "iax2",
		[]byte{0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01})
}

func FuzzCLDAPHandler(f *testing.F) {
	// CLDAP searchRequest: SEQUENCE { messageID INTEGER, [APPLICATION 3] ... }.
	fuzzUDPHandler(f, "cldap",
		[]byte{0x30, 0x07, 0x02, 0x01, 0x01, 0x63, 0x02, 0x04, 0x00})
}

func FuzzLLMNRHandler(f *testing.F) {
	fuzzUDPHandler(f, "llmnr", dnsQuerySeed())
}

func FuzzNBNSHandler(f *testing.F) {
	fuzzUDPHandler(f, "nbns", nbnsQuerySeed())
}

func FuzzNetBIOSDatagramHandler(f *testing.F) {
	// NBT datagram: message type 0x11 (DIRECT_UNIQUE) + flags/IDs.
	fuzzUDPHandler(f, "netbios_dgram",
		append([]byte{0x11, 0x02, 0x80, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x8a}, make([]byte, 16)...))
}

func FuzzPROFINETHandler(f *testing.F) {
	// PROFINET-IO over DCE/RPC v4, request PDU (a connect/IODControl attempt).
	fuzzUDPHandler(f, "profinet",
		append([]byte{0x04, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00}, make([]byte, 32)...))
}

func FuzzWDBRPCHandler(f *testing.F) {
	// VxWorks WDB-RPC: a 4-byte xid is enough to elicit the connect path.
	fuzzUDPHandler(f, "wdbrpc",
		[]byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0x55, 0x55})
}

func FuzzSyslogUDPHandler(f *testing.F) {
	fuzzUDPHandler(f, "syslog_udp",
		[]byte("<34>Oct 11 22:14:15 host su: authentication failure for root"),
		[]byte("<13>plain message"))
}
