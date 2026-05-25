package handler

// Ninth batch: the remaining services with real request parsing that aren't yet
// covered by a dedicated target — legacy r-services, RPC/registry/control
// protocols, an AJP/TACACS pair, syslog-over-TCP, Elasticsearch, the TDS
// pre-login, X11/TN3270/SPICE/VMware-authd, and the declarative `scripted`
// engine. Seeded with valid frames via fuzzTCPHandler.
//
//	go test ./internal/listener/handler -run x -fuzz FuzzGitHandler -fuzztime 60s

import "testing"

func FuzzRexecHandler(f *testing.F) {
	fuzzTCPHandler(f, "rexec", []byte("0\x00root\x00toor\x00id\x00"))
}

func FuzzRshHandler(f *testing.F) {
	fuzzTCPHandler(f, "rsh", []byte("0\x00root\x00root\x00id;uname -a\x00"))
}

func FuzzGitHandler(f *testing.F) {
	// git pkt-line: "<4-hex-len>git-upload-pack /repo\0host=...\0".
	fuzzTCPHandler(f, "git", []byte("0032git-upload-pack /repo.git\x00host=example\x00"))
}

func FuzzZookeeperHandler(f *testing.F) {
	fuzzTCPHandler(f, "zookeeper",
		[]byte("ruok"), // four-letter-word command
		append([]byte{0x00, 0x00, 0x00, 0x2c}, make([]byte, 44)...)) // length-prefixed connect
}

func FuzzRPCBindHandler(f *testing.F) {
	// ONC RPC CALL to the portmapper (prog 100000) GETPORT (proc 3).
	fuzzTCPHandler(f, "rpcbind",
		[]byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
			0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func FuzzPPTPHandler(f *testing.F) {
	// PPTP control: length, msg type 1, magic cookie 1A2B3C4D, Start-Control-Conn-Req.
	fuzzTCPHandler(f, "pptp",
		append([]byte{0x00, 0x9c, 0x00, 0x01, 0x1a, 0x2b, 0x3c, 0x4d, 0x00, 0x01, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00}, make([]byte, 140)...))
}

func FuzzAJP13Handler(f *testing.F) {
	// AJP13: magic 0x1234 + length + a CPing (0x0a) packet.
	fuzzTCPHandler(f, "ajp13",
		[]byte{0x12, 0x34, 0x00, 0x01, 0x0a},
		[]byte{0x12, 0x34, 0x00, 0x02, 0x02, 0x02}) // Forward Request prefix
}

func FuzzTACACSHandler(f *testing.F) {
	// TACACS+ header (version 0xc0, type AUTHEN, seq 1) + an 8-byte body.
	fuzzTCPHandler(f, "tacacs",
		[]byte{0xc0, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08,
			0x01, 0x00, 0x01, 0x01, 0x04, 0x04, 0x04, 0x00})
}

func FuzzSyslogTCPHandler(f *testing.F) {
	fuzzTCPHandler(f, "syslog_tcp",
		[]byte("<34>Oct 11 22:14:15 host su: auth failure for root\n"), // non-transparent framing
		[]byte("25 <13>octet-counted message"))                         // RFC 6587 octet-counting
}

func FuzzElasticsearchHandler(f *testing.F) {
	fuzzTCPHandler(f, "elasticsearch",
		[]byte("GET /_cluster/health HTTP/1.1\r\nHost: x\r\n\r\n"),
		[]byte("POST /_search HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}"))
}

func FuzzMSSQLHandler(f *testing.F) {
	// TDS pre-login packet: type 0x12, status EOM, length, then option tokens.
	fuzzTCPHandler(f, "mssql",
		[]byte{0x12, 0x01, 0x00, 0x11, 0x00, 0x00, 0x01, 0x00,
			0x00, 0x00, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff})
}

func FuzzTN3270Handler(f *testing.F) {
	// Telnet IAC negotiation a TN3270 client opens with.
	fuzzTCPHandler(f, "tn3270",
		[]byte{0xff, 0xfd, 0x28, 0xff, 0xfb, 0x18, 0xff, 0xfa, 0x18, 0x00, 'I', 'B', 'M', '-', '3', '2', '7', '8', '-', '2', 0xff, 0xf0})
}

func FuzzX11Handler(f *testing.F) {
	// X11 connection setup: little-endian, protocol 11.0, no authorization.
	fuzzTCPHandler(f, "x11",
		[]byte{0x6c, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func FuzzSpiceHandler(f *testing.F) {
	// SPICE link message: magic "REDQ" + version + size + connection id.
	fuzzTCPHandler(f, "spice",
		append([]byte("REDQ"), []byte{0x02, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...))
}

func FuzzVMwareAuthdHandler(f *testing.F) {
	fuzzTCPHandler(f, "vmware_authd",
		[]byte("USER root\r\nPASS secret\r\nQUIT\r\n"))
}

func FuzzScriptedHandler(f *testing.F) {
	// The fuzzDeps scripted config matches GET (prefix), "admin" (contains),
	// [0-9]{3,} (regex), and a 00ff hex prefix — drive each branch.
	fuzzTCPHandler(f, "scripted",
		[]byte("GET /index\r\n"),
		[]byte("login admin now\r\n"),
		[]byte("value 12345\r\n"),
		[]byte{0x00, 0xff, 0x41, 0x42})
}
