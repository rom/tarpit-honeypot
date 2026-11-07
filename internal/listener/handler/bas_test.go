package handler

import (
	"strings"
	"testing"
)

func basAnoms(res Result) []string {
	a, _ := res.Meta["anomalies"].([]string)
	return a
}

func TestNiagaraPlatformProbe(t *testing.T) {
	res, reply := runDevsvc(t, &niagaraPlatform{}, []byte("fox a 1 -1 fox hello\n{}\n;;\n"))
	if !containsStr(basAnoms(res), "niagara-platform-probe") {
		t.Errorf("want niagara-platform-probe anomaly, got %v", basAnoms(res))
	}
	if !strings.Contains(string(reply), "fox hello") {
		t.Errorf("want fox hello banner, got %q", reply)
	}
	if res.Meta["niagara_phase"] != "fox-hello" {
		t.Errorf("niagara_phase = %v want fox-hello", res.Meta["niagara_phase"])
	}
}

func TestOBIXWriteFlagged(t *testing.T) {
	res, reply := runDevsvc(t, &obix{}, []byte("PUT /obix/config/AHU1/setpoint/ HTTP/1.1\r\nHost: bms\r\n\r\n<real val=\"85\"/>"))
	if !containsStr(basAnoms(res), "bas-point-write") {
		t.Errorf("PUT to oBIX should flag bas-point-write, got %v", basAnoms(res))
	}
	if !strings.Contains(string(reply), "obix:Lobby") {
		t.Errorf("want oBIX lobby reply, got %q", reply)
	}
	// A plain GET is a probe, not a write.
	res2, _ := runDevsvc(t, &obix{}, []byte("GET /obix/ HTTP/1.1\r\nHost: bms\r\n\r\n"))
	if containsStr(basAnoms(res2), "bas-point-write") {
		t.Error("GET must not flag a write")
	}
	if !containsStr(basAnoms(res2), "obix-probe") {
		t.Error("GET should still be an obix-probe")
	}
}

func TestEnoceanCommonCommand(t *testing.T) {
	// ESP3: sync=0x55, dataLen=0x0001, optLen=0, type=5 (COMMON_COMMAND), crc8h, data=0x03(CO_WR...), crc8d
	frame := []byte{0x55, 0x00, 0x01, 0x00, 0x05, 0x00, 0x03, 0x00}
	res, reply := runDevsvc(t, &enocean{}, frame)
	if res.Meta["esp3_framed"] != true {
		t.Errorf("esp3_framed not set: %v", res.Meta)
	}
	if res.Meta["esp3_packet_type"] != "COMMON_COMMAND" {
		t.Errorf("esp3_packet_type = %v want COMMON_COMMAND", res.Meta["esp3_packet_type"])
	}
	if !containsStr(basAnoms(res), "bas-point-write") {
		t.Errorf("COMMON_COMMAND should flag bas-point-write, got %v", basAnoms(res))
	}
	if len(reply) == 0 || reply[0] != 0x55 {
		t.Errorf("want ESP3 response, got %v", reply)
	}
}
