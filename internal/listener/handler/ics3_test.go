package handler

import (
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

func TestVNCAuthFlow(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "vnc", ReadBytes: 0, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&vnc{}).Handle(context.Background(), server, cfg) }()

	// Read server version (12 bytes)
	srv := make([]byte, 12)
	if _, err := io.ReadFull(client, srv); err != nil {
		t.Fatal(err)
	}
	// Send client version
	_, _ = client.Write([]byte("RFB 003.008\n"))
	// Read security types byte
	st := make([]byte, 2)
	_, _ = io.ReadFull(client, st)
	// Pick VNC auth
	_, _ = client.Write([]byte{2})
	// Read challenge
	chal := make([]byte, 16)
	_, _ = io.ReadFull(client, chal)
	// Send fake DES response
	_, _ = client.Write([]byte("AAAAAAAAAAAAAAAA"))
	// Read SecurityResult
	resB := make([]byte, 4)
	_, _ = io.ReadFull(client, resB)

	client.Close()
	<-done
	if res.Meta["client_version"] != "RFB 003.008\n" {
		t.Errorf("client_version = %v", res.Meta["client_version"])
	}
	if res.Meta["security_type_selected"] != uint8(2) {
		t.Errorf("security_type_selected = %v", res.Meta["security_type_selected"])
	}
	if !strings.Contains(res.Meta["auth_response_hex"].(string), "414141") {
		t.Errorf("auth_response_hex should contain 414141 (hex of 'AAA'): %v", res.Meta["auth_response_hex"])
	}
}

func TestSMTPRecvAUTHLogin(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "smtp_recv", ReadBytes: 0, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&smtpRecv{}).Handle(context.Background(), server, cfg) }()
	// Read greeting
	br := readLines(client)
	<-br
	_, _ = client.Write([]byte("EHLO scanner.example\r\n"))
	// EHLO reply = host line + len(defaultSMTPExtensions) extension lines.
	for i := 0; i < 1+len(defaultSMTPExtensions); i++ {
		<-br
	}
	_, _ = client.Write([]byte("AUTH LOGIN\r\n"))
	<-br // 334 Username:
	_, _ = client.Write([]byte(base64.StdEncoding.EncodeToString([]byte("admin")) + "\r\n"))
	<-br // 334 Password:
	_, _ = client.Write([]byte(base64.StdEncoding.EncodeToString([]byte("hunter2")) + "\r\n"))
	<-br // 535
	_, _ = client.Write([]byte("QUIT\r\n"))
	<-br // 221
	client.Close()
	<-done
	if res.Meta["helo"] != "scanner.example" {
		t.Errorf("helo = %v", res.Meta["helo"])
	}
	if res.Meta["auth_mech"] != "LOGIN" {
		t.Errorf("auth_mech = %v", res.Meta["auth_mech"])
	}
	if res.Meta["auth_user"] != "admin" {
		t.Errorf("auth_user = %v", res.Meta["auth_user"])
	}
	if res.Meta["auth_pass"] != "hunter2" {
		t.Errorf("auth_pass = %v", res.Meta["auth_pass"])
	}
}

func readLines(c net.Conn) chan string {
	ch := make(chan string, 16)
	go func() {
		buf := make([]byte, 256)
		acc := ""
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			n, err := c.Read(buf)
			if n > 0 {
				acc += string(buf[:n])
				for {
					if i := strings.Index(acc, "\n"); i >= 0 {
						ch <- acc[:i+1]
						acc = acc[i+1:]
					} else {
						break
					}
				}
			}
			if err != nil {
				close(ch)
				return
			}
		}
	}()
	return ch
}

func TestRedisAUTHCommand(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "redis", ReadBytes: 0, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&redis{}).Handle(context.Background(), server, cfg) }()
	// multi-bulk AUTH foobared
	_, _ = client.Write([]byte("*2\r\n$4\r\nAUTH\r\n$8\r\nfoobared\r\n"))
	// drain reply
	br := make([]byte, 128)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = client.Read(br)
	_, _ = client.Write([]byte("QUIT\r\n"))
	_, _ = client.Read(br)
	client.Close()
	<-done
	if res.Meta["auth_password"] != "foobared" {
		t.Errorf("auth_password = %v", res.Meta["auth_password"])
	}
	if cmds, ok := res.Meta["commands"].([]string); !ok || len(cmds) < 1 || !strings.HasPrefix(cmds[0], "AUTH ") {
		t.Errorf("commands = %v", res.Meta["commands"])
	}
}

func TestLDAPBindCapturesSimpleAuth(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "ldap", ReadBytes: 0, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&ldap{}).Handle(context.Background(), server, cfg) }()

	// SEQUENCE { 02 01 01 (msgID=1), 60 1B (BindRequest, len=27)
	//   02 01 03 (version=3),
	//   04 0F "cn=admin,dc=ex" (bindDN),
	//   80 07 "hunter2" (simple auth)
	// }
	dn := []byte("cn=admin,dc=ex")
	pw := []byte("hunter2")
	bindOp := []byte{0x02, 0x01, 0x03}
	bindOp = append(bindOp, 0x04, byte(len(dn)))
	bindOp = append(bindOp, dn...)
	bindOp = append(bindOp, 0x80, byte(len(pw)))
	bindOp = append(bindOp, pw...)
	msg := []byte{0x02, 0x01, 0x01, 0x60, byte(len(bindOp))}
	msg = append(msg, bindOp...)
	pkt := append([]byte{0x30, byte(len(msg))}, msg...)

	_, _ = client.Write(pkt)
	// drain response
	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = client.Read(buf)
	client.Close()
	<-done
	if res.Meta["bind_dn"] != "cn=admin,dc=ex" {
		t.Errorf("bind_dn = %v", res.Meta["bind_dn"])
	}
	if res.Meta["bind_pw"] != "hunter2" {
		t.Errorf("bind_pw = %v", res.Meta["bind_pw"])
	}
}

func TestPostgresStartupAndPassword(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "postgres", ReadBytes: 0, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&postgres{}).Handle(context.Background(), server, cfg) }()

	// StartupMessage: length(4) + proto(4) + "user\0admin\0database\0prod\0\0"
	params := []byte("user\x00admin\x00database\x00prod\x00\x00")
	body := make([]byte, 4+len(params))
	binary.BigEndian.PutUint32(body[0:4], 0x00030000) // proto 3.0
	copy(body[4:], params)
	startup := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(startup[0:4], uint32(4+len(body)))
	copy(startup[4:], body)
	_, _ = client.Write(startup)

	// Read AuthenticationCleartextPassword (9 bytes: 'R' + len + 3)
	authReq := make([]byte, 9)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, authReq); err != nil {
		t.Fatal(err)
	}
	if authReq[0] != 'R' {
		t.Errorf("expected R; got %x", authReq[0])
	}
	// Send PasswordMessage
	pw := []byte("topsecret\x00")
	pm := make([]byte, 5+len(pw))
	pm[0] = 'p'
	binary.BigEndian.PutUint32(pm[1:5], uint32(4+len(pw)))
	copy(pm[5:], pw)
	_, _ = client.Write(pm)
	// drain error response
	errBuf := make([]byte, 256)
	_, _ = client.Read(errBuf)

	client.Close()
	<-done
	if res.Meta["password"] != "topsecret" {
		t.Errorf("password = %v", res.Meta["password"])
	}
	params2, _ := res.Meta["startup_params"].(map[string]string)
	if params2["user"] != "admin" || params2["database"] != "prod" {
		t.Errorf("startup_params = %v", params2)
	}
}

func TestMySQLHandshakeCapturesUsername(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "mysql", ReadBytes: 0, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&mysql{}).Handle(context.Background(), server, cfg) }()

	// Read server handshake.
	header := make([]byte, 4)
	if _, err := io.ReadFull(client, header); err != nil {
		t.Fatal(err)
	}
	bodyLen := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(client, body); err != nil {
		t.Fatal(err)
	}

	// Send client handshake response with username "rootscanner" and
	// a 20-byte auth response.
	respBody := make([]byte, 0, 64)
	respBody = binary.LittleEndian.AppendUint32(respBody, 0xa68f0001) // client caps
	respBody = binary.LittleEndian.AppendUint32(respBody, 16777216)   // max packet
	respBody = append(respBody, 0x21)                                 // charset
	respBody = append(respBody, make([]byte, 23)...)                  // reserved
	respBody = append(respBody, []byte("rootscanner")...)
	respBody = append(respBody, 0)                   // username NUL
	respBody = append(respBody, 20)                  // auth-response length
	respBody = append(respBody, make([]byte, 20)...) // 20 bytes of fake auth

	respPkt := make([]byte, 4+len(respBody))
	respPkt[0] = byte(len(respBody))
	respPkt[1] = byte(len(respBody) >> 8)
	respPkt[2] = byte(len(respBody) >> 16)
	respPkt[3] = 1
	copy(respPkt[4:], respBody)
	_, _ = client.Write(respPkt)
	// drain error packet
	errBuf := make([]byte, 256)
	_, _ = client.Read(errBuf)
	client.Close()
	<-done
	if res.Meta["username"] != "rootscanner" {
		t.Errorf("username = %v", res.Meta["username"])
	}
}

func TestIPMIPresencePongReply(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	// Build RMCP Presence Ping.
	pkt := []byte{
		0x06, 0x00, 0xff, 0x06, // RMCP: ver, reserved, seq, class=ASF
		0x00, 0x00, 0x11, 0xbe, // IANA = 4542
		0x80, 0x42, // msg_type=PingMsg=0x80, tag=0x42
		0x00, 0x00, // reserved, data_len
	}
	res, _ := (&ipmi{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 Pong; got %d", len(pc.written))
	}
	pong := pc.written[0]
	if pong[8] != 0x40 {
		t.Errorf("Pong msg_type should be 0x40; got %x", pong[8])
	}
	if pong[9] != 0x42 {
		t.Errorf("Pong tag must echo Ping tag; got %x", pong[9])
	}
	if res.Meta["asf_msg"] != "presence_ping" {
		t.Errorf("asf_msg = %v", res.Meta["asf_msg"])
	}
}
