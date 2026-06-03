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

func TestGEEGDProbe(t *testing.T) {
	// pdu_type=0 (data), request_id, producer id 10.0.0.5 at offset 8.
	pkt := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 10, 0, 0, 5}
	res, err := (&geEGD{}).Handle(context.Background(), pkt, &net.UDPAddr{}, &fakePacketConn{}, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if !hasAnomaly(res, "ics-ge-egd-probe") {
		t.Errorf("ge_egd flag missing: %v", res.Meta["anomalies"])
	}
	if res.Meta["egd_pdu"] != "data" {
		t.Errorf("egd_pdu = %v", res.Meta["egd_pdu"])
	}
	if res.Meta["egd_producer_id"] != "10.0.0.5" {
		t.Errorf("egd_producer_id = %v", res.Meta["egd_producer_id"])
	}
	// EGD is capture-only: it must never write a reply (no reflection).
	if res.BannerSent != "" {
		t.Errorf("ge_egd must not reply, got %q", res.BannerSent)
	}
}

func TestBSAPProbeReflectionSafe(t *testing.T) {
	req := []byte{0x34, 0x12, 0x01, 0x00, 0xAA, 0xBB}
	fpc := &fakePacketConn{}
	res, err := (&bsap{lim: newUDPReflectLimiter()}).Handle(context.Background(),
		req, &net.UDPAddr{}, fpc, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if !hasAnomaly(res, "ics-bsap-probe") {
		t.Errorf("bsap flag missing: %v", res.Meta["anomalies"])
	}
	// Any reply must be no larger than the request (no amplification).
	for _, w := range fpc.written {
		if len(w) > len(req) {
			t.Errorf("bsap reply %d bytes > request %d bytes (amplification)", len(w), len(req))
		}
	}
}

func TestLonTalkProbe(t *testing.T) {
	// version=1, packet_type=0x03 (device-registration).
	pkt := []byte{0x01, 0x03, 0x00, 0x10}
	res, err := (&lonTalk{}).Handle(context.Background(), pkt, &net.UDPAddr{}, &fakePacketConn{}, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if !hasAnomaly(res, "ics-lontalk-probe") {
		t.Errorf("lontalk flag missing: %v", res.Meta["anomalies"])
	}
	if res.Meta["lon_pdu"] != "device-registration" {
		t.Errorf("lon_pdu = %v", res.Meta["lon_pdu"])
	}
	if res.BannerSent != "" {
		t.Errorf("lontalk must not reply, got %q", res.BannerSent)
	}
}
