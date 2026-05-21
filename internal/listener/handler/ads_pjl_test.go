package handler

import (
	"context"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestPJLInfoID(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second, ReadBytes: 4096}
	resC := make(chan Result, 1)
	go func() { r, _ := (&pjl{}).Handle(context.Background(), server, cfg); resC <- r }()
	_, _ = client.Write([]byte("\x1b%-12345X@PJL INFO ID\r\n"))
	buf := make([]byte, 512)
	n, _ := client.Read(buf)
	_ = client.Close()
	r := <-resC
	if !strings.Contains(string(buf[:n]), "HP LaserJet") {
		t.Errorf("PJL INFO ID response missing model: %q", string(buf[:n]))
	}
	if anoms, _ := r.Meta["anomalies"].([]string); !containsStr(anoms, "pjl-command") {
		t.Errorf("not flagged pjl-command: %v", r.Meta["anomalies"])
	}
}

func TestPJLRdymsgDefacement(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&pjl{}).Handle(context.Background(), server, cfg); resC <- r }()
	_, _ = client.Write([]byte("@PJL RDYMSG DISPLAY=\"HACKED\"\r\n"))
	time.Sleep(20 * time.Millisecond)
	_ = client.Close()
	r := <-resC
	if anoms, _ := r.Meta["anomalies"].([]string); !containsStr(anoms, "printer-rdymsg-set") {
		t.Errorf("RDYMSG defacement not flagged: %v", r.Meta["anomalies"])
	}
}

func TestADSReadDeviceInfo(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&ads{}).Handle(context.Background(), server, cfg); resC <- r }()

	ams := make([]byte, 32)
	// target/source AmsNetId+port left zero except a recognizable target.
	copy(ams[0:6], []byte{192, 168, 0, 1, 1, 1})
	binary.LittleEndian.PutUint16(ams[16:18], adsReadDeviceInfo)
	binary.LittleEndian.PutUint16(ams[18:20], 0x0004) // ADS command
	binary.LittleEndian.PutUint32(ams[28:32], 1)      // invokeId
	frame := make([]byte, 6+len(ams))
	binary.LittleEndian.PutUint32(frame[2:6], uint32(len(ams)))
	copy(frame[6:], ams)
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}

	hdr := make([]byte, 6)
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	plen := binary.LittleEndian.Uint32(hdr[2:6])
	resp := make([]byte, plen)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	r := <-resC
	if binary.LittleEndian.Uint16(resp[16:18]) != adsReadDeviceInfo {
		t.Errorf("response cmdId wrong: %x", resp[16:18])
	}
	if resp[18]&0x01 == 0 {
		t.Errorf("response flag bit not set: %x", resp[18:20])
	}
	if !strings.Contains(string(resp[32:]), "TwinCAT") {
		t.Errorf("device info missing TwinCAT: % x", resp[32:])
	}
	if r.Meta["ads_command"] != "ReadDeviceInfo" {
		t.Errorf("ads_command = %v", r.Meta["ads_command"])
	}
	if anoms, _ := r.Meta["anomalies"].([]string); !containsStr(anoms, "ics-ads-probe") {
		t.Errorf("not flagged ics-ads-probe: %v", r.Meta["anomalies"])
	}
}
