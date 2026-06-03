package handler

import (
	"context"
	"net"
	"testing"
)

// Enrichments to ten existing protocol handlers: each adds deeper decoding /
// higher-signal anomaly detection. These tests pin the new behavior.

func udpResult(t *testing.T, h UDPHandler, pkt []byte) Result {
	t.Helper()
	res, err := h.Handle(context.Background(), pkt, &net.UDPAddr{}, &fakePacketConn{}, smallSvcCfg())
	if err != nil {
		t.Fatalf("%s: %v", h.Name(), err)
	}
	return res
}

func TestNTPModeDecode(t *testing.T) {
	// mode 7 (private), request code 42 = REQ_MON_GETLIST (monlist amplifier).
	pkt := make([]byte, 48)
	pkt[0] = 0x17 // version 2, mode 7
	pkt[3] = 42
	res := udpResult(t, &ntp{}, pkt)
	if !hasAnomaly(res, "ntp-monlist-amplification") || res.Meta["ntp_request"] != "REQ_MON_GETLIST" {
		t.Errorf("ntp mode7 decode: %v / %v", res.Meta["anomalies"], res.Meta["ntp_request"])
	}
}

func TestTFTPFirmwarePushAndTraversal(t *testing.T) {
	// WRQ (opcode 2) for firmware.bin = firmware push.
	pkt := append([]byte{0x00, 0x02}, []byte("firmware.bin\x00octet\x00")...)
	res := udpResult(t, &tftp{}, pkt)
	if !hasAnomaly(res, "tftp-write-attempt") || !hasAnomaly(res, "tftp-firmware-push") {
		t.Errorf("tftp firmware push: %v", res.Meta["anomalies"])
	}
	// RRQ (opcode 1) with traversal.
	pkt2 := append([]byte{0x00, 0x01}, []byte("../../etc/passwd\x00octet\x00")...)
	res2 := udpResult(t, &tftp{}, pkt2)
	if !hasAnomaly(res2, "tftp-path-traversal") {
		t.Errorf("tftp traversal: %v", res2.Meta["anomalies"])
	}
}

func TestIPMICipherZero(t *testing.T) {
	// RMCP (0x06) + IPMI class (0x07), RMCP+ auth type (0x06), payload type
	// 0x10 (Open Session Request), authentication algorithm 0 at offset 33.
	pkt := make([]byte, 40)
	pkt[0] = 0x06
	pkt[3] = 0x07
	pkt[4] = 0x06
	pkt[5] = 0x10
	pkt[33] = 0x00
	res := udpResult(t, &ipmi{}, pkt)
	if !hasAnomaly(res, "ipmi-2.0-rmcp-plus") || !hasAnomaly(res, "ipmi-cipher-zero-auth-bypass") {
		t.Errorf("ipmi cipher zero: %v", res.Meta["anomalies"])
	}
}

func TestSSDPAllAmplification(t *testing.T) {
	req := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
	res := udpResult(t, &ssdp{lim: newUDPReflectLimiter()}, []byte(req))
	if !hasAnomaly(res, "ssdp-all-amplification") {
		t.Errorf("ssdp:all not flagged: %v", res.Meta["anomalies"])
	}
}

func TestBACnetReinitializeFlagged(t *testing.T) {
	// BVLC(0x81) Original-Unicast(0x0a) len, NPDU(ver=1,ctl=0), APDU confirmed
	// (type 0x00) max-segs, invoke-id, service 0x14 (ReinitializeDevice).
	pkt := []byte{0x81, 0x0a, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x01, 0x14}
	res := udpResult(t, &bacnet{}, pkt)
	if !hasAnomaly(res, "bacnet-reinitialize-device") {
		t.Errorf("bacnet reinitialize: %v", res.Meta["anomalies"])
	}
}

func TestDNSAnyAmplification(t *testing.T) {
	got := dnsQueryAnomalies("isc.org", 255, 30)
	if !containsStr(got, "dns-any-amplification") {
		t.Errorf("dns ANY not flagged: %v", got)
	}
}

func TestMDNSServiceType(t *testing.T) {
	if got := mdnsServiceType("_ssh._tcp.local"); got != "_ssh._tcp" {
		t.Errorf("mdnsServiceType = %q", got)
	}
	if got := mdnsServiceType("host.local"); got != "" {
		t.Errorf("mdnsServiceType(non-service) = %q", got)
	}
}

func TestSIPAuthUser(t *testing.T) {
	if got := sipAuthUser(`Digest username="1001", realm="asterisk", nonce="x"`); got != "1001" {
		t.Errorf("sipAuthUser = %q", got)
	}
}
