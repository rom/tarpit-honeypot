package handler

import (
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// c37118Frame builds a C37.118.2 frame: SYNC + framesize + idcode + soc +
// fracsec + body + CRC.
func c37118Frame(ftype byte, idcode uint16, body []byte) []byte {
	f := make([]byte, 14+len(body)+2)
	f[0] = 0xAA
	f[1] = (ftype << 4) | 0x01
	binary.BigEndian.PutUint16(f[2:4], uint16(len(f)))
	binary.BigEndian.PutUint16(f[4:6], idcode)
	copy(f[14:], body)
	binary.BigEndian.PutUint16(f[len(f)-2:], crcCCITT(f[:len(f)-2]))
	return f
}

func TestC37118CommandTurnOff(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "c37118", ReadTimeout: time.Second}
	// COMMAND frame (type 4) carrying CMD=1 (turn off transmission).
	cmd := []byte{0x00, 0x01}
	pkt := c37118Frame(4, 7734, cmd)

	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&c37118{}).Handle(context.Background(), server, cfg) }()
	if _, err := client.Write(pkt); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(out)
	client.Close()
	<-done
	if n < 2 || out[0] != 0xAA {
		t.Errorf("reply not a C37.118 frame: % x", out[:n])
	}
	if res.Meta["c37118_command"] != "turn-off-transmission" {
		t.Errorf("command = %v; want turn-off-transmission", res.Meta["c37118_command"])
	}
	if !hasAnom(res, "ics-pmu-command") {
		t.Errorf("turn-off not flagged as a PMU command: %v", res.Meta["anomalies"])
	}
}

func TestOSDPOutputControlFlagged(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "osdp", ReadTimeout: time.Second}
	// SOM, ADDR=0, LEN(2), CTRL=0 (checksum), CMD=osdp_OUT, data, checksum.
	pkt := []byte{0x53, 0x00, 0x08, 0x00, 0x00, osdpOUT, 0x00, 0x01}
	pkt = append(pkt, osdpChecksum(pkt))

	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&osdp{}).Handle(context.Background(), server, cfg) }()
	if _, err := client.Write(pkt); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(out)
	client.Close()
	<-done
	if n < 6 || out[0] != 0x53 {
		t.Errorf("reply not an OSDP frame: % x", out[:n])
	}
	if res.Meta["osdp_command"] != "osdp_OUT" {
		t.Errorf("command = %v; want osdp_OUT", res.Meta["osdp_command"])
	}
	if !hasAnom(res, "ics-actuator-command") {
		t.Errorf("osdp_OUT not flagged as actuation: %v", res.Meta["anomalies"])
	}
}

func TestOSDPIDReturnsPDID(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "osdp", ReadTimeout: time.Second}
	pkt := []byte{0x53, 0x00, 0x06, 0x00, 0x00, osdpID}
	pkt = append(pkt, osdpChecksum(pkt))

	done := make(chan struct{})
	go func() { defer close(done); _, _ = (&osdp{}).Handle(context.Background(), server, cfg) }()
	_, _ = client.Write(pkt)
	out := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(out)
	client.Close()
	<-done
	// Reply code sits at offset 5; osdp_PDID = 0x45.
	if n < 6 || out[5] != osdpPDID {
		t.Errorf("expected osdp_PDID reply; got % x", out[:n])
	}
}

func TestFocasReturnsModel(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "focas", ReadTimeout: time.Second}

	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&focas{}).Handle(context.Background(), server, cfg) }()
	_, _ = client.Write([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
	out := make([]byte, 128)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = io.ReadAtLeast(client, out, 18)
	client.Close()
	<-done
	if res.Meta["focas_model"] == nil {
		t.Errorf("no model captured: %v", res.Meta)
	}
	if !hasAnom(res, "ics-device-enumeration") {
		t.Errorf("focas probe not flagged: %v", res.Meta["anomalies"])
	}
}

func TestProconosDownloadFlagged(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "proconos", ReadTimeout: time.Second}

	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&proconos{}).Handle(context.Background(), server, cfg) }()
	_, _ = client.Write([]byte{0x01, 0x06, 0x00, 0x00}) // opcode 0x06 = download
	out := make([]byte, 32)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = client.Read(out)
	client.Close()
	<-done
	if !hasAnom(res, "ics-plc-write") {
		t.Errorf("proconos download not flagged as plc-write: %v", res.Meta["anomalies"])
	}
	if !hasAnom(res, "ics-plc-program-access") {
		t.Errorf("proconos probe not flagged: %v", res.Meta["anomalies"])
	}
}
