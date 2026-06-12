package handler

import (
	"context"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// --- OT:ICEFALL active detections ---

// ProConOS DOWNLOAD opcode -> unauthenticated logic upload (CVE-2022-31801).
func TestProConOSLogicDownloadCVE(t *testing.T) {
	res, _ := roundtrip(t, &proconos{}, string([]byte{0x01, 0x07})) // opcode 0x07 = download
	if !hasAnom(res, "cve:CVE-2022-31801") || !cveHit(res, "CVE-2022-31801") {
		t.Errorf("ProConOS logic download not flagged: anomalies=%v cves=%v", res.Meta["anomalies"], res.CVEHits)
	}
	if !hasAnom(res, "ics-plc-write") {
		t.Errorf("ProConOS download missing ics-plc-write")
	}
}

// FINS PROGRAM AREA WRITE (MRC 0x03 / SRC 0x07) -> logic download (CVE-2022-31207).
func TestFINSProgramWriteCVE(t *testing.T) {
	payload := make([]byte, 12)
	payload[10] = 0x03 // MRC PROGRAM AREA
	payload[11] = 0x07 // SRC WRITE
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 90), Port: 9600}
	res, _ := (&fins{}).Handle(context.Background(), payload, src, &fakePacketConn{}, config.Listener{})
	if !hasAnom(res, "cve:CVE-2022-31207") || !cveHit(res, "CVE-2022-31207") {
		t.Errorf("FINS program-area write not flagged: anomalies=%v cves=%v", res.Meta["anomalies"], res.CVEHits)
	}
}

// A PROGRAM AREA READ (SRC 0x06) is logic exfil, not the download CVE.
func TestFINSProgramReadNotDownloadCVE(t *testing.T) {
	payload := make([]byte, 12)
	payload[10] = 0x03 // MRC PROGRAM AREA
	payload[11] = 0x06 // SRC READ
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 90), Port: 9600}
	res, _ := (&fins{}).Handle(context.Background(), payload, src, &fakePacketConn{}, config.Listener{})
	if hasAnom(res, "cve:CVE-2022-31207") {
		t.Errorf("FINS program-area READ wrongly flagged as the logic-download CVE")
	}
	if !hasAnom(res, "ics-plc-program-access") {
		t.Errorf("FINS program-area read missing ics-plc-program-access")
	}
}
