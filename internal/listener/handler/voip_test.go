package handler

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestSIPRegisterCapturesUser(t *testing.T) {
	req := []byte("REGISTER sip:pbx.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 1.2.3.4:5060;branch=z9hG4bKabc\r\n" +
		"From: <sip:1001@pbx.example.com>;tag=xyz\r\n" +
		"To: <sip:1001@pbx.example.com>\r\n" +
		"Call-ID: callid123\r\nCSeq: 1 REGISTER\r\n\r\n")
	res, reply := runDevsvc(t, &sipTCP{}, req)
	if !strings.HasPrefix(string(reply), "SIP/2.0 401") {
		t.Errorf("reply = %q; want 401", reply)
	}
	if res.Meta["sip_user"] != "1001" {
		t.Errorf("sip_user = %v; want 1001", res.Meta["sip_user"])
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "sip-register-probe") {
		t.Errorf("anomalies = %v; want sip-register-probe", anoms)
	}
}

func TestSIPInviteCapturesDest(t *testing.T) {
	req := []byte("INVITE sip:0049900123456@pbx SIP/2.0\r\n" +
		"From: <sip:attacker@x>;tag=t\r\nTo: <sip:0049900123456@pbx>\r\n" +
		"Call-ID: c\r\nCSeq: 1 INVITE\r\n\r\n")
	res, _ := runDevsvc(t, &sipTCP{}, req)
	if res.Meta["sip_dest"] != "0049900123456" {
		t.Errorf("sip_dest = %v; want the dialed number", res.Meta["sip_dest"])
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "sip-invite-attempt") {
		t.Errorf("anomalies = %v; want sip-invite-attempt", anoms)
	}
}

func TestSCCPRegister(t *testing.T) {
	req := make([]byte, 28)
	req[0] = 20   // length
	req[8] = 0x01 // message id: RegisterMessage
	copy(req[12:27], "SEP001122334455")
	res, reply := runDevsvc(t, &sccp{}, req)
	if len(reply) == 0 {
		t.Errorf("expected a RegisterAck")
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "sccp-register") {
		t.Errorf("anomalies = %v; want sccp-register", anoms)
	}
}

func TestH323Setup(t *testing.T) {
	req := []byte{0x03, 0x00, 0x00, 0x0a, 0x08, 0x02, 0x12, 0x34, 0x05, 0x04}
	res, reply := runDevsvc(t, &h323{}, req)
	if len(reply) < 4 || reply[0] != 0x03 {
		t.Errorf("reply = %v; want a TPKT frame", reply)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "h323-setup") {
		t.Errorf("anomalies = %v; want h323-setup", anoms)
	}
}

func TestAsteriskAMILoginCapturesCreds(t *testing.T) {
	req := []byte("Action: Login\r\nUsername: admin\r\nSecret: amp111\r\n\r\n")
	res, banner := runServerFirst(t, &asteriskAMI{}, req)
	if !strings.Contains(string(banner), "Asterisk Call Manager") {
		t.Errorf("banner = %q; want the AMI greeting", banner)
	}
	if res.Meta["ami_username"] != "admin" || res.Meta["ami_secret"] != "amp111" {
		t.Errorf("creds not captured: %v", res.Meta)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "ami-login") {
		t.Errorf("anomalies = %v; want ami-login", anoms)
	}
}

func TestIAX2DetectionNoReply(t *testing.T) {
	pc := &capPC{}
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 4), Port: 4569}
	res, _ := (&iax2{}).Handle(context.Background(), []byte{0x80, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, src, pc, config.Listener{})
	if len(pc.wrote) != 0 {
		t.Errorf("iax2 must not reply (reflection-safe); wrote %v", pc.wrote)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "iax2-probe") {
		t.Errorf("anomalies = %v; want iax2-probe", anoms)
	}
}
