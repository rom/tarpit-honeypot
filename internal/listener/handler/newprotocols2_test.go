package handler

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// MSSQL: a TDS PRELOGIN should get a PRELOGIN response advertising a
// 15.0 version.
func TestMSSQLPreLogin(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "mssql", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&mssql{id: identity.New("x")}).Handle(context.Background(), server, cfg)
	}()
	// Minimal PRELOGIN: header type 0x12, EOM, length 8 + 1-byte body.
	pkt := []byte{0x12, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0xFF}
	_, _ = client.Write(pkt)
	hdr := make([]byte, 8)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[0] != tdsResponse {
		t.Errorf("response type = %x; want 0x04", hdr[0])
	}
	respLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	body := make([]byte, respLen-8)
	_, _ = io.ReadFull(client, body)
	client.Close()
	<-done
	if res.Meta["tds_packet_type"] != byte(tdsPreLogin) {
		t.Errorf("did not record prelogin type: %v", res.Meta["tds_packet_type"])
	}
	sv, _ := res.Meta["server_version"].(string)
	if !strings.HasPrefix(sv, "15.0.") {
		t.Errorf("server_version = %q; want 15.0.x", sv)
	}
	// VERSION token (0x00) should be the first option byte.
	if len(body) == 0 || body[0] != 0x00 {
		t.Errorf("first option token = %v; want VERSION(0)", body)
	}
}

// Oracle TNS: a CONNECT packet with a service name should be captured
// and answered with a REFUSE.
func TestOracleTNSConnect(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "oracle_tns", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&oracleTNS{}).Handle(context.Background(), server, cfg)
	}()
	desc := "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCLPDB1)))"
	body := append(make([]byte, 26), []byte(desc)...) // 26-byte fixed connect header + descriptor
	total := 8 + len(body)
	pkt := make([]byte, total)
	binary.BigEndian.PutUint16(pkt[0:2], uint16(total))
	pkt[4] = tnsConnect
	copy(pkt[8:], body)
	_, _ = client.Write(pkt)

	hdr := make([]byte, 8)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	client.Close()
	<-done
	if hdr[4] != tnsRefuse {
		t.Errorf("response type = %d; want REFUSE(4)", hdr[4])
	}
	if res.Meta["service_name"] != "ORCLPDB1" {
		t.Errorf("service_name = %v; want ORCLPDB1", res.Meta["service_name"])
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "oracle-tns-probe") {
		t.Errorf("anomalies = %v; want oracle-tns-probe", anoms)
	}
}

// Intel AMT: a GET / should return a 401 Digest with the AMT Server
// header — the CVE-2017-5689 fingerprint.
func TestIntelAMTDigest401(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "intel_amt", ReadBytes: 2048, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&mgmtWeb{kind: "intel_amt"}).Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	resp := readAllFromConn(client, 2*time.Second)
	client.Close()
	<-done
	if !strings.HasPrefix(resp, "HTTP/1.1 401") {
		t.Errorf("status = %q; want 401", trunc(resp, 40))
	}
	if !strings.Contains(resp, "Intel(R) Active Management Technology") {
		t.Errorf("AMT Server header missing: %q", trunc(resp, 200))
	}
	if !strings.Contains(resp, "WWW-Authenticate: Digest") {
		t.Errorf("Digest challenge missing: %q", trunc(resp, 200))
	}
}

// iDRAC basic-auth credential capture.
func TestIDRACBasicAuthCapture(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "idrac", ReadBytes: 2048, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&mgmtWeb{kind: "idrac"}).Handle(context.Background(), server, cfg)
	}()
	// root:calvin is the iDRAC default — base64("root:calvin").
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic cm9vdDpjYWx2aW4=\r\n\r\n"))
	_ = readAllFromConn(client, 2*time.Second)
	client.Close()
	<-done
	if res.Meta["basic_user"] != "root" || res.Meta["basic_pass"] != "calvin" {
		t.Errorf("creds not captured: user=%v pass=%v", res.Meta["basic_user"], res.Meta["basic_pass"])
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "idrac-login-attempt") {
		t.Errorf("anomalies = %v; want idrac-login-attempt", anoms)
	}
	if !containsStr(anoms, "default-credential-attempt") {
		t.Errorf("root/calvin should flag default-credential-attempt: %v", anoms)
	}
}

// OpenVPN HARD_RESET_CLIENT should get a HARD_RESET_SERVER reply.
func TestOpenVPNReset(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "openvpn", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&openvpn{}).Handle(context.Background(), server, cfg)
	}()
	// opcode 7 (P_CONTROL_HARD_RESET_CLIENT_V2) << 3 = 0x38, + 8-byte session id.
	pkt := append([]byte{0x38}, make([]byte, 8)...)
	frame := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(pkt)))
	copy(frame[2:], pkt)
	_, _ = client.Write(frame)
	resp := make([]byte, 2)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadFull(client, resp)
	client.Close()
	<-done
	if res.Meta["openvpn_reset"] != true {
		t.Errorf("did not record openvpn_reset: %v", res.Meta)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "openvpn-probe") {
		t.Errorf("anomalies = %v; want openvpn-probe", anoms)
	}
}

func TestDecodeBasic(t *testing.T) {
	u, p, ok := decodeBasic("Basic cm9vdDpjYWx2aW4=")
	if !ok || u != "root" || p != "calvin" {
		t.Errorf("decodeBasic = %q,%q,%v", u, p, ok)
	}
	if _, _, ok := decodeBasic("Digest foo"); ok {
		t.Errorf("non-Basic should not decode")
	}
}

var _ = bufio.NewReader
var _ = net.IPv4zero
