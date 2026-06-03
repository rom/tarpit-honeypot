package handler

import (
	"context"
	"net"
	"testing"
)

func TestTriStationProbe(t *testing.T) {
	// msg type 0x05 = download-program (the TRITON reprogramming path).
	res, err := (&tristation{lim: newUDPReflectLimiter()}).Handle(context.Background(),
		[]byte{0x05, 0x00, 0x12, 0x34, 0x00, 0x00}, &net.UDPAddr{}, &fakePacketConn{}, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if !hasAnomaly(res, "ics-tristation-probe") || !hasAnomaly(res, "ics-safety-controller-manipulation") {
		t.Errorf("tristation flags missing: %v", res.Meta["anomalies"])
	}
	if res.Meta["ts_msg"] != "download-program" {
		t.Errorf("ts_msg = %v", res.Meta["ts_msg"])
	}
}

func TestROCPlusLogin(t *testing.T) {
	client, server := loopbackPair(t)
	// dst_unit, dst_group, src_unit, src_group, opcode=17 (login), len
	if _, err := client.Write([]byte{1, 2, 240, 240, 17, 0}); err != nil {
		t.Fatal(err)
	}
	res, _ := (&rocPlus{}).Handle(context.Background(), server, smallSvcCfg())
	if !hasAnomaly(res, "ics-roc-plus-command") || !hasAnomaly(res, "ics-roc-plus-login") {
		t.Errorf("roc_plus flags missing: %v", res.Meta["anomalies"])
	}
	if res.Meta["roc_opcode"] != byte(17) {
		t.Errorf("roc_opcode = %v", res.Meta["roc_opcode"])
	}
}

func TestCrimsonProbe(t *testing.T) {
	client, server := loopbackPair(t)
	if _, err := client.Write([]byte("\x00\x01hello")); err != nil {
		t.Fatal(err)
	}
	res, _ := (&crimson{}).Handle(context.Background(), server, smallSvcCfg())
	if !hasAnomaly(res, "ics-crimson-probe") {
		t.Errorf("crimson flag missing: %v", res.Meta["anomalies"])
	}
}
