package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// roundtrip drives a banner-mode TCP handler over net.Pipe, returning both
// the captured Result and everything the handler wrote to the client — so a
// test can assert on the wire bytes (INFO output, SUBACK, 401 lines) as well
// as res.Meta. The input should end with a command that makes the handler
// return (QUIT / LOGOUT) so the call doesn't wait out the read timeout.
func roundtrip(t *testing.T, h Handler, input string) (Result, []byte) {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: time.Second, ReadBytes: 4096}
	var res Result
	done := make(chan struct{})
	go func() { defer close(done); res, _ = h.Handle(context.Background(), server, cfg) }()
	var out bytes.Buffer
	rdone := make(chan struct{})
	go func() { defer close(rdone); _, _ = io.Copy(&out, client) }()
	if _, err := io.WriteString(client, input); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not return")
	}
	_ = client.Close()
	<-rdone
	return res, out.Bytes()
}

func TestRedisINFOAndConfig(t *testing.T) {
	_, out := roundtrip(t, &redis{}, "INFO\r\nCONFIG GET dir\r\nQUIT\r\n")
	s := string(out)
	if !strings.Contains(s, "redis_version:") {
		t.Errorf("INFO missing redis_version: %q", s)
	}
	if !strings.Contains(s, "role:master") {
		t.Errorf("INFO missing replication section: %q", s)
	}
	if !strings.Contains(s, "/var/lib/redis") {
		t.Errorf("CONFIG GET dir missing value: %q", s)
	}
}

func TestMemcachedStatsBlock(t *testing.T) {
	_, out := roundtrip(t, &memcached{}, "stats\r\nstats settings\r\nquit\r\n")
	s := string(out)
	for _, want := range []string{"STAT limit_maxbytes", "STAT version", "STAT maxconns"} {
		if !strings.Contains(s, want) {
			t.Errorf("stats output missing %q: %q", want, s)
		}
	}
}

func TestMongoBuildInfo(t *testing.T) {
	doc := bsonDoc(bsonInt32("buildInfo", 1))
	payload := append([]byte{0, 0, 0, 0, 0}, doc...)
	req := append(mongoHeader(int32(16+len(payload)), 7, 0, opMsg), payload...)
	res, out := roundtrip(t, &mongodb{}, string(req))
	if res.Meta["mongo_command"] != "buildInfo" {
		t.Errorf("mongo_command = %v", res.Meta["mongo_command"])
	}
	if !bytes.Contains(out, []byte("7.0.8")) {
		t.Errorf("buildInfo reply missing default version: % x", out)
	}
}

func TestIMAPSASLPlainCapture(t *testing.T) {
	blob := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00s3cret"))
	res := runConn(t, &imap{}, "a1 AUTHENTICATE PLAIN "+blob+"\r\na2 LOGOUT\r\n")
	if res.Meta["auth_user"] != "alice" || res.Meta["auth_pass"] != "s3cret" {
		t.Errorf("imap SASL creds: user=%v pass=%v", res.Meta["auth_user"], res.Meta["auth_pass"])
	}
}

func TestPOP3SASLPlainCapture(t *testing.T) {
	blob := base64.StdEncoding.EncodeToString([]byte("\x00bob\x00hunter2"))
	res := runConn(t, &pop3{}, "AUTH PLAIN "+blob+"\r\nQUIT\r\n")
	if res.Meta["auth_user"] != "bob" || res.Meta["auth_pass"] != "hunter2" {
		t.Errorf("pop3 SASL creds: user=%v pass=%v", res.Meta["auth_user"], res.Meta["auth_pass"])
	}
}

func TestRTSPOptionsPublic(t *testing.T) {
	_, out := roundtrip(t, &rtsp{}, "OPTIONS rtsp://host/cam RTSP/1.0\r\nCSeq: 1\r\n\r\n")
	s := string(out)
	if !strings.HasPrefix(s, "RTSP/1.0 200 OK") {
		t.Errorf("OPTIONS should be 200 OK: %q", s)
	}
	if !strings.Contains(s, "Public:") || !strings.Contains(s, "DESCRIBE") {
		t.Errorf("OPTIONS missing Public methods: %q", s)
	}
}

func TestMQTTSubscribeWildcardFlag(t *testing.T) {
	// CONNECT then SUBSCRIBE to "#" (full data harvest).
	connect := []byte{0x10, 12, 0, 4, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0, 60, 0, 0}
	// SUBSCRIBE: type 0x82, remlen 6 = pktID(0,1) + topic_len(0,1) + '#' + qos(0).
	sub := []byte{0x82, 6, 0, 1, 0, 1, '#', 0x00}
	res, out := roundtrip(t, &mqtt{}, string(connect)+string(sub))
	if !bytes.Contains(out, []byte{0x20, 0x02}) {
		t.Errorf("missing CONNACK: % x", out)
	}
	if !bytes.Contains(out, []byte{0x90}) {
		t.Errorf("missing SUBACK: % x", out)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "mqtt-wildcard-subscribe") {
		t.Errorf("wildcard subscribe not flagged: %v", anoms)
	}
}

func TestTelnetStripsIAC(t *testing.T) {
	// Client sends IAC WILL TERMINAL-TYPE then the username "admin".
	input := string([]byte{0xff, 0xfb, 0x18}) + "admin\r\n" + "secret\r\n"
	res := runConn(t, &telnet{}, input)
	if res.Meta["user_attempt"] != "admin" {
		t.Errorf("IAC bytes leaked into username: %q", res.Meta["user_attempt"])
	}
}

func TestTelnetCapturesOptions(t *testing.T) {
	var in []byte
	// IAC SB TERMINAL-TYPE IS "xterm-256color" IAC SE
	in = append(in, telIAC, telSB, telOptTType, 0x00)
	in = append(in, []byte("xterm-256color")...)
	in = append(in, telIAC, telSE)
	// IAC SB NAWS 0 132 0 43 IAC SE  (132x43 window)
	in = append(in, telIAC, telSB, telOptNAWS, 0x00, 0x84, 0x00, 0x2b, telIAC, telSE)
	// IAC SB NEW-ENVIRON IS VAR "USER" VALUE "root" IAC SE
	in = append(in, telIAC, telSB, telOptNewEnv, 0x00, 0x00)
	in = append(in, []byte("USER")...)
	in = append(in, 0x01)
	in = append(in, []byte("root")...)
	in = append(in, telIAC, telSE)
	// Then the login lines (must still be captured cleanly).
	in = append(in, []byte("admin\r\npw\r\n")...)

	res := runConn(t, &telnet{}, string(in))
	if res.Meta["terminal_type"] != "xterm-256color" {
		t.Errorf("terminal_type = %v; want xterm-256color", res.Meta["terminal_type"])
	}
	if res.Meta["window_size"] != "132x43" {
		t.Errorf("window_size = %v; want 132x43", res.Meta["window_size"])
	}
	env, _ := res.Meta["telnet_env"].(map[string]string)
	if env["USER"] != "root" {
		t.Errorf("telnet_env[USER] = %q; want root (env=%v)", env["USER"], env)
	}
	if res.Meta["user_attempt"] != "admin" {
		t.Errorf("username not captured cleanly with options present: %v", res.Meta["user_attempt"])
	}
}

func TestVNCRfb33Path(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&vnc{}).Handle(context.Background(), server, cfg) }()
	srv := make([]byte, 12)
	_, _ = io.ReadFull(client, srv)
	_, _ = client.Write([]byte("RFB 003.003\n")) // negotiate 3.3
	// In 3.3 the server sends the security type as a 4-byte value.
	sec := make([]byte, 4)
	if _, err := io.ReadFull(client, sec); err != nil {
		t.Fatalf("read security type: %v", err)
	}
	if binary.BigEndian.Uint32(sec) != 2 {
		t.Errorf("RFB 3.3 security type = %d; want 2 (VNC auth)", binary.BigEndian.Uint32(sec))
	}
	_ = client.Close()
	<-done
	if res.Meta["rfb_security"] != "3.3" {
		t.Errorf("rfb_security = %v; want 3.3", res.Meta["rfb_security"])
	}
}

func TestOracleTNSVersionCommand(t *testing.T) {
	desc := "(DESCRIPTION=(CONNECT_DATA=(COMMAND=version)))"
	body := append(make([]byte, 26), []byte(desc)...)
	total := 8 + len(body)
	pkt := make([]byte, total)
	binary.BigEndian.PutUint16(pkt[0:2], uint16(total))
	pkt[4] = tnsConnect
	copy(pkt[8:], body)
	_, out := roundtrip(t, &oracleTNS{}, string(pkt))
	if len(out) < 8 || out[4] != tnsData {
		t.Fatalf("COMMAND=version should yield a DATA packet; got type %d", safeIdx(out, 4))
	}
	if !bytes.Contains(out, []byte("Version 19.0.0.0.0")) {
		t.Errorf("version DATA missing banner: %q", out)
	}
}

func TestWinRMNTLMHarvestsDomainUser(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: time.Second, ReadBytes: 8192}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&winrm{}).Handle(context.Background(), server, cfg) }()

	// First request: NTLMSSP Type 1.
	t1 := append([]byte("NTLMSSP\x00"), 0x01, 0, 0, 0, 0x05, 0x82, 0x08, 0xa2)
	req1 := "POST /wsman HTTP/1.1\r\nHost: x\r\nAuthorization: Negotiate " +
		base64.StdEncoding.EncodeToString(t1) + "\r\n\r\n"
	_, _ = client.Write([]byte(req1))
	// Drain the Type 2 challenge.
	buf := make([]byte, 4096)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = client.Read(buf)

	// Second request: NTLMSSP Type 3 carrying CORP\admin.
	t3 := buildNTLMType3("CORP", "admin")
	req2 := "POST /wsman HTTP/1.1\r\nHost: x\r\nAuthorization: Negotiate " +
		base64.StdEncoding.EncodeToString(t3) + "\r\n\r\n"
	_, _ = client.Write([]byte(req2))
	_, _ = client.Read(buf)
	_ = client.Close()
	<-done

	if res.Meta["ntlm_user"] != "admin" {
		t.Errorf("ntlm_user = %v; want admin", res.Meta["ntlm_user"])
	}
	if res.Meta["ntlm_domain"] != "CORP" {
		t.Errorf("ntlm_domain = %v; want CORP", res.Meta["ntlm_domain"])
	}
}

func TestElasticsearchGroovyCVE(t *testing.T) {
	body := `{"size":1,"script_fields":{"x":{"lang":"groovy","script":"java.lang.Math.class.forName('java.lang.Runtime')"}}}`
	req := "POST /_search HTTP/1.1\r\nHost: es\r\nContent-Length: " +
		itoa(len(body)) + "\r\n\r\n" + body
	res := runConn(t, &elasticsearch{}, req)
	found := false
	for _, id := range res.CVEHits {
		if id == "CVE-2015-1427" {
			found = true
		}
	}
	if !found {
		t.Errorf("Groovy RCE payload not flagged; CVEHits=%v", res.CVEHits)
	}
}

// --- UDP enhancements ---

func TestNTPControlReadvarAnswered(t *testing.T) {
	// mode 6 READVAR (`ntpq -c rv`): now answered (rate-limited, minimal) with
	// the system-variable string, AND still flagged as recon.
	req := make([]byte, 48)
	req[0] = 0x16 // ver=2, mode=6 (control)
	req[1] = 0x02 // opcode 2 = READVAR
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	res, _ := (&ntp{lim: newUDPReflectLimiter()}).Handle(context.Background(), req, src, pc, config.Listener{})
	if len(pc.written) != 1 {
		t.Fatalf("READVAR should be answered once; got %d writes", len(pc.written))
	}
	reply := pc.written[0]
	if reply[1]&0x80 == 0 {
		t.Errorf("control reply missing the response bit: % x", reply[:2])
	}
	if !containsBytes(reply, []byte("version=")) {
		t.Errorf("READVAR reply lacks system variables: %q", reply)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "ntp-control-query") {
		t.Errorf("mode 6 not flagged: %v", anoms)
	}
	if res.Meta["ntp_control"] != "READVAR" {
		t.Errorf("ntp_control = %v; want READVAR", res.Meta["ntp_control"])
	}
}

func TestSIPRegisterChallenges(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5060}
	req := "REGISTER sip:pbx SIP/2.0\r\nVia: SIP/2.0/UDP scanner\r\n" +
		"From: <sip:100@pbx>\r\nTo: <sip:100@pbx>\r\nCall-ID: abc\r\nCSeq: 1 REGISTER\r\n\r\n"
	res, _ := (&sipUDP{}).Handle(context.Background(), []byte(req), src, pc, config.Listener{})
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 reply; got %d", len(pc.written))
	}
	reply := string(pc.written[0])
	if !strings.HasPrefix(reply, "SIP/2.0 401") {
		t.Errorf("REGISTER should be challenged 401: %q", reply)
	}
	if !strings.Contains(reply, "WWW-Authenticate: Digest") {
		t.Errorf("REGISTER 401 missing Digest challenge: %q", reply)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "sip-register-probe") {
		t.Errorf("REGISTER not flagged: %v", anoms)
	}
}

// buildNTLMType3 assembles a minimal NTLMSSP Type 3 carrying a UTF-16LE
// domain + user (unicode flag set), enough for parseNTLMType3 to extract them.
func buildNTLMType3(domain, user string) []byte {
	dom := utf16le(domain)
	usr := utf16le(user)
	nt := make([]byte, 16) // dummy NT response
	const hdr = 64
	ntOff := hdr
	domOff := ntOff + len(nt)
	usrOff := domOff + len(dom)
	total := usrOff + len(usr)

	m := make([]byte, total)
	copy(m, []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(m[8:], 3) // type 3
	secbuf := func(off, l, dataOff int) {
		binary.LittleEndian.PutUint16(m[off:], uint16(l))
		binary.LittleEndian.PutUint16(m[off+2:], uint16(l))
		binary.LittleEndian.PutUint32(m[off+4:], uint32(dataOff))
	}
	secbuf(12, 0, hdr)                                // LM response (empty)
	secbuf(20, len(nt), ntOff)                        // NT response
	secbuf(28, len(dom), domOff)                      // Domain
	secbuf(36, len(usr), usrOff)                      // User
	secbuf(44, 0, hdr)                                // Workstation
	secbuf(52, 0, hdr)                                // Session key
	binary.LittleEndian.PutUint32(m[60:], 0x00000001) // flags: unicode
	copy(m[ntOff:], nt)
	copy(m[domOff:], dom)
	copy(m[usrOff:], usr)
	return m
}

func safeIdx(b []byte, i int) int {
	if i < len(b) {
		return int(b[i])
	}
	return -1
}
