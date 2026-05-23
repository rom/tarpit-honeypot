package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestADBConnectReplies(t *testing.T) {
	req := adbMessage("CNXN", 0x01000001, 256*1024, []byte("host::features=cmd,shell_v2\x00"))
	res, reply := runDevsvc(t, &adb{}, req)
	if len(reply) < 4 || string(reply[0:4]) != "CNXN" {
		t.Errorf("reply = %v; want a CNXN device banner", reply)
	}
	if res.Meta["adb_client_banner"] == nil {
		t.Errorf("client banner not captured: %v", res.Meta)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "adb-connect") {
		t.Errorf("anomalies = %v; want adb-connect", anoms)
	}
}

func TestADBShellOpenFlagged(t *testing.T) {
	req := adbMessage("OPEN", 1, 0, []byte("shell:id\x00"))
	res, _ := runDevsvc(t, &adb{}, req)
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "adb-shell-open") {
		t.Errorf("anomalies = %v; want adb-shell-open", anoms)
	}
}

func TestAJP13ForwardRequest(t *testing.T) {
	req := []byte{0x12, 0x34, 0x00, 0x02, 0x02, 0x02} // magic, len 2, prefix 2 (forward request)
	res, reply := runDevsvc(t, &ajp13{}, req)
	if len(reply) < 5 || reply[0] != 0x41 || reply[1] != 0x42 {
		t.Errorf("reply = %v; want an AJP container response (A B ...)", reply)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "ajp-forward-request") {
		t.Errorf("anomalies = %v; want ajp-forward-request", anoms)
	}
}

func TestEPMDNamesEnumerated(t *testing.T) {
	req := []byte{0x00, 0x01, 110} // length 1, op NAMES_REQ
	res, reply := runDevsvc(t, &epmd{}, req)
	if len(reply) < 4 || binary.BigEndian.Uint32(reply[0:4]) != 4369 {
		t.Errorf("reply = %v; want a NAMES response starting with the epmd port", reply)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "epmd-names") {
		t.Errorf("anomalies = %v; want epmd-names", anoms)
	}
}

func TestTACACSAuthStartFlagged(t *testing.T) {
	req := make([]byte, 12)
	req[0] = 0xc1 // version
	req[1] = 0x01 // type AUTHEN
	req[2] = 0x01 // seq
	binary.BigEndian.PutUint32(req[4:8], 0xdeadbeef)
	binary.BigEndian.PutUint32(req[8:12], 0) // body length
	res, reply := runDevsvc(t, &tacacs{}, req)
	if len(reply) < 12 || reply[1] != 0x01 {
		t.Errorf("reply = %v; want a TACACS+ AUTHEN reply", reply)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "tacacs-auth-start") {
		t.Errorf("anomalies = %v; want tacacs-auth-start", anoms)
	}
}

func TestMSSQLBrowserResponse(t *testing.T) {
	pc := &capPC{}
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 51000}
	res, _ := (&mssqlBrowser{lim: newUDPReflectLimiter()}).Handle(context.Background(),
		[]byte{0x02}, src, pc, config.Listener{})
	if len(pc.wrote) < 3 || pc.wrote[0] != 0x05 {
		t.Errorf("ssrp response = %v; want SVR_RESP (0x05 ...)", pc.wrote)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "mssql-browser-query") {
		t.Errorf("anomalies = %v; want mssql-browser-query", anoms)
	}
}
