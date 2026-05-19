package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// TestSyslogTCPAcceptsNewlineFraming verifies the non-transparent
// framing path (most common for syslog-ng / rsyslog with TLS off).
func TestSyslogTCPAcceptsNewlineFraming(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "syslog_tcp", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&syslogTCP{}).Handle(context.Background(), server, cfg) }()
	_, _ = client.Write([]byte("<30>Jan  1 00:00:00 host app: hi from syslog\n"))
	_, _ = client.Write([]byte("<30>Jan  1 00:00:01 host app: second line\n"))
	client.Close()
	<-done
	msgs, ok := res.Meta["messages"].([]string)
	if !ok || len(msgs) != 2 {
		t.Fatalf("expected 2 messages; got %v", res.Meta["messages"])
	}
	if !strings.Contains(msgs[0], "hi from syslog") {
		t.Errorf("first message wrong: %q", msgs[0])
	}
}

func TestSyslogUDPParsesPRI(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 514}
	res, _ := (&syslogUDP{}).Handle(context.Background(),
		[]byte("<165>Oct 11 22:14:15 host app[123]: payload"),
		src, pc, config.Listener{})
	if res.Meta["pri"] != 165 {
		t.Errorf("pri = %v; want 165", res.Meta["pri"])
	}
	if res.Meta["facility"] != 20 {
		t.Errorf("facility = %v; want 20", res.Meta["facility"])
	}
	if res.Meta["sev"] != 5 {
		t.Errorf("sev = %v; want 5", res.Meta["sev"])
	}
}

func TestRADIUSAccessRequestCapturesUsername(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1812}
	// Build a minimal Access-Request: code=1, id=42, length=29,
	// auth(16) zeros, then attr 1 (User-Name) "admin".
	pkt := []byte{1, 42, 0, 0}
	binary.BigEndian.PutUint16(pkt[2:4], 27)
	pkt = append(pkt, make([]byte, 16)...) // authenticator
	pkt = append(pkt, 1, byte(2+len("admin")))
	pkt = append(pkt, []byte("admin")...)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	res, _ := (&radius{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if res.Meta["user_name"] != "admin" {
		t.Errorf("user_name = %v; want admin", res.Meta["user_name"])
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 Access-Reject reply; got %d", len(pc.written))
	}
	if pc.written[0][0] != 3 {
		t.Errorf("reply code = %d; want 3 (Access-Reject)", pc.written[0][0])
	}
}

func TestSIPRepliesWith200OK(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5060}
	req := "OPTIONS sip:1000@1.2.3.4 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP scanner\r\n" +
		"From: <sip:scanner@example>\r\n" +
		"To: <sip:1000@1.2.3.4>\r\n" +
		"Call-ID: cafe\r\n" +
		"CSeq: 1 OPTIONS\r\n\r\n"
	res, _ := (&sipUDP{}).Handle(context.Background(), []byte(req), src, pc, config.Listener{})
	if res.Meta["method"] != "OPTIONS" {
		t.Errorf("method = %v", res.Meta["method"])
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 reply; got %d", len(pc.written))
	}
	if !strings.HasPrefix(string(pc.written[0]), "SIP/2.0 200 OK") {
		t.Errorf("reply doesn't start with 200 OK: %q", pc.written[0][:30])
	}
}

func TestSSDPMSearchProvokesReply(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1900}
	req := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: upnp:rootdevice\r\n\r\n"
	res, _ := (&ssdp{}).Handle(context.Background(), []byte(req), src, pc, config.Listener{})
	if res.Meta["st"] != "upnp:rootdevice" {
		t.Errorf("st meta wrong: %v", res.Meta["st"])
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected reply; got %d writes", len(pc.written))
	}
}

func TestDockerAPIPingReturnsOK(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "dockerapi", ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = (&dockerapi{}).Handle(context.Background(), server, cfg) }()
	_, _ = client.Write([]byte("GET /_ping HTTP/1.1\r\nHost: docker\r\n\r\n"))
	buf := make([]byte, 1024)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	client.Close()
	<-done
	resp := string(buf[:n])
	if !strings.HasPrefix(resp, "HTTP/1.1 200 OK") {
		t.Errorf("expected 200 OK on /_ping; got %q", resp[:30])
	}
	if !strings.Contains(resp, "Server: Docker/") {
		t.Errorf("Server header missing: %q", resp)
	}
}

func TestLLMNRPoisonReply(t *testing.T) {
	pc := &fakePacketConn{laddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 50), Port: 5355}}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 7), Port: 50000}
	// LLMNR query for "wpad" — the classic poisoning target.
	pkt := []byte{0xab, 0xcd, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		4, 'w', 'p', 'a', 'd', 0,
		0, 1, 0, 1}
	res, _ := (&llmnr{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if res.Meta["qname"] != "wpad" {
		t.Errorf("qname = %v; want wpad", res.Meta["qname"])
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected poisoning reply; got %d writes", len(pc.written))
	}
}

func TestFINSCPURead(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9600}
	// FINS header + MRC=0x05 SRC=0x01 (CPU_UNIT_DATA_READ)
	pkt := []byte{0x80, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x05, 0x01}
	res, _ := (&fins{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if res.Meta["mrc"] != byte(0x05) {
		t.Errorf("mrc = %v; want 0x05", res.Meta["mrc"])
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 reply; got %d", len(pc.written))
	}
	reply := pc.written[0]
	if reply[0] != 0xC0 {
		t.Errorf("response ICF should be 0xC0; got %x", reply[0])
	}
}

func TestMELSECCPUResponse(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "melsec", ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = (&melsec{}).Handle(context.Background(), server, cfg) }()

	// 3E request: subhdr=0x5000 (LE: 0x00 0x50), network=0, PC=0xFF,
	// module_io=0x03FF (LE), station=0, data_len=6 (LE), cpu_timer=10,
	// command=0x0101 (LE), sub=0.
	req := []byte{0x00, 0x50, 0x00, 0xFF, 0xFF, 0x03, 0x00, 0x06, 0x00, 0x0A, 0x00}
	req = append(req, 0x01, 0x01, 0x00, 0x00) // command + sub
	_, _ = client.Write(req)
	// Response header is 9 bytes: subhdr(2) + 5 echoed + data_len(2).
	hdr := make([]byte, 9)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	respLen := binary.LittleEndian.Uint16(hdr[7:9])
	body := make([]byte, respLen)
	_, _ = io.ReadFull(client, body)
	client.Close()
	<-done
	if binary.LittleEndian.Uint16(hdr[0:2]) != 0xD000 {
		t.Errorf("response subhdr = %x; want 0xD000", hdr[0:2])
	}
	if !strings.Contains(string(body), "Q03UDVCPU") {
		t.Errorf("model string missing: %q", body)
	}
}
