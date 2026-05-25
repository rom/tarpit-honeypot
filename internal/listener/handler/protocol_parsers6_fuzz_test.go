package handler

// Sixth batch: handler-level fuzzing of the remaining mainstream services —
// mail/cache/media text protocols, database + routing + ICS binary protocols,
// HTTP-framed management services, and a couple of UDP services. Seeded with
// valid frames via the fuzzTCPHandler / fuzzUDPHandler helpers.
//
//	go test ./internal/listener/handler -run x -fuzz FuzzPostgresHandler -fuzztime 60s

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// --- TCP text / line protocols ---------------------------------------------

func FuzzPOP3Handler(f *testing.F) {
	fuzzTCPHandler(f, "pop3",
		[]byte("USER bob\r\nPASS hunter2\r\nSTAT\r\nLIST\r\nRETR 1\r\nQUIT\r\n"))
}

func FuzzIMAPHandler(f *testing.F) {
	fuzzTCPHandler(f, "imap",
		[]byte("a1 LOGIN bob hunter2\r\na2 SELECT INBOX\r\na3 LIST \"\" *\r\na4 LOGOUT\r\n"),
		[]byte("x1 LOGIN \"u\" \"p\"\r\n"))
}

func FuzzSMTPRecvHandler(f *testing.F) {
	fuzzTCPHandler(f, "smtp_recv",
		[]byte("EHLO probe\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\nhello\r\n.\r\nQUIT\r\n"))
}

func FuzzRedisHandler(f *testing.F) {
	fuzzTCPHandler(f, "redis",
		[]byte("*1\r\n$4\r\nPING\r\n*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n"),
		[]byte("INFO\r\nCONFIG GET dir\r\n"))
}

func FuzzMemcachedHandler(f *testing.F) {
	fuzzTCPHandler(f, "memcached",
		[]byte("version\r\nstats\r\nset k 0 0 3\r\nabc\r\nget k\r\nflush_all\r\nquit\r\n"))
}

func FuzzRTSPHandler(f *testing.F) {
	fuzzTCPHandler(f, "rtsp",
		[]byte("OPTIONS rtsp://h:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"+
			"DESCRIBE rtsp://h/s RTSP/1.0\r\nCSeq: 2\r\n\r\n"))
}

func FuzzGopherHandler(f *testing.F) {
	fuzzTCPHandler(f, "gopher", []byte("/\r\n"), []byte("1/menu\tselector\r\n"))
}

// --- TCP binary protocols ---------------------------------------------------

func pgStartupSeed() []byte {
	params := []byte("user\x00postgres\x00database\x00prod\x00\x00")
	body := append([]byte{0x00, 0x03, 0x00, 0x00}, params...) // protocol 3.0 + params
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(4+len(body))) // length includes itself
	return append(out, body...)
}

func FuzzPostgresHandler(f *testing.F) {
	fuzzTCPHandler(f, "postgres", pgStartupSeed(),
		[]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}) // SSLRequest
}

func mysqlLoginSeed() []byte {
	p := []byte{0x85, 0xa2, 0x1e, 0x00}   // capability flags (PROTOCOL_41 etc.)
	p = append(p, 0x00, 0x00, 0x00, 0x01) // max packet size
	p = append(p, 0x21)                   // charset utf8
	p = append(p, make([]byte, 23)...)    // reserved
	p = append(p, []byte("root\x00")...)  // username
	p = append(p, 0x00)                   // auth-response length 0
	return append([]byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), 0x01}, p...)
}

func FuzzMySQLHandler(f *testing.F) {
	fuzzTCPHandler(f, "mysql", mysqlLoginSeed())
}

func mongoOpMsgSeed() []byte {
	body := []byte{0x00, 0x00, 0x00, 0x00, 0x00}      // flagBits(4) + section kind 0
	body = append(body, 0x05, 0x00, 0x00, 0x00, 0x00) // an empty BSON document
	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:4], uint32(16+len(body))) // msgLen
	binary.LittleEndian.PutUint32(out[4:8], 1)                    // requestID
	binary.LittleEndian.PutUint32(out[12:16], 2013)               // opCode OP_MSG
	return append(out, body...)
}

func FuzzMongoDBHandler(f *testing.F) {
	fuzzTCPHandler(f, "mongodb", mongoOpMsgSeed())
}

func FuzzVNCHandler(f *testing.F) {
	// Client RFB version + a security-type selection + a 16-byte auth response.
	fuzzTCPHandler(f, "vnc",
		append([]byte("RFB 003.008\n"), append([]byte{0x02}, make([]byte, 16)...)...))
}

func bgpOpenSeed() []byte {
	b := bytes.Repeat([]byte{0xff}, 16)                                        // all-ones marker
	body := []byte{0x04, 0xfd, 0xe8, 0x00, 0xb4, 0xc0, 0xa8, 0x01, 0x01, 0x00} // ver/AS/hold/bgpid/optlen
	total := 19 + len(body)
	b = append(b, byte(total>>8), byte(total), 0x01) // length + type OPEN
	return append(b, body...)
}

func FuzzBGPHandler(f *testing.F) {
	fuzzTCPHandler(f, "bgp", bgpOpenSeed())
}

func oracleTNSSeed() []byte {
	desc := []byte("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL)))")
	body := append(make([]byte, 26), desc...) // 26-byte connect fixed block + descriptor
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(8+len(body))) // packet length
	hdr[4] = 0x01                                             // CONNECT
	return append(hdr, body...)
}

func FuzzOracleTNSHandler(f *testing.F) {
	fuzzTCPHandler(f, "oracle_tns", oracleTNSSeed())
}

func FuzzEPMDHandler(f *testing.F) {
	fuzzTCPHandler(f, "epmd",
		[]byte{0x00, 0x01, 0x6e},                              // NAMES_REQ ('n')
		append([]byte{0x00, 0x07, 0x7a}, []byte("mynode")...)) // PORT_PLEASE2_REQ ('z')
}

// --- TCP HTTP-framed services ----------------------------------------------

func FuzzIPPHandler(f *testing.F) {
	// HTTP POST whose body is a minimal IPP Get-Printer-Attributes request.
	fuzzTCPHandler(f, "ipp",
		[]byte("POST /printers/x HTTP/1.1\r\nHost: x\r\nContent-Type: application/ipp\r\n"+
			"Content-Length: 8\r\n\r\n\x02\x00\x00\x0b\x00\x00\x00\x01"))
}

func FuzzWinRMHandler(f *testing.F) {
	fuzzTCPHandler(f, "winrm",
		[]byte("POST /wsman HTTP/1.1\r\nHost: x\r\nAuthorization: Negotiate TlRMTVNTUAABAAAA\r\n"+
			"Content-Type: application/soap+xml\r\nContent-Length: 0\r\n\r\n"))
}

// --- UDP -------------------------------------------------------------------

func FuzzMSSQLBrowserHandler(f *testing.F) {
	fuzzUDPHandler(f, "mssql_browser",
		[]byte{0x02}, // CLNT_BCAST_EX
		[]byte{0x03}, // CLNT_UCAST_EX
		append([]byte{0x04}, []byte("MSSQLSERVER\x00")...)) // CLNT_UCAST_INST
}

func FuzzDNSHandler(f *testing.F) {
	fuzzUDPHandler(f, "dns", dnsQuerySeed())
}
