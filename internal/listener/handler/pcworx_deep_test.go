package handler

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func drivePcworx(t *testing.T, req []byte) Result {
	t.Helper()
	return driveDrain(t, func(c net.Conn) Result {
		res, _ := (&pcworx{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, req)
}

func TestPcworxWrite(t *testing.T) {
	req := append([]byte{0x01, 0x01, 0x00, 0x10}, []byte("WriteVariable Q0.0")...)
	r := drivePcworx(t, req)
	if !hasAnom(r, "ics-plc-write") {
		t.Errorf("write not flagged: %v", r.Meta["anomalies"])
	}
	if !hasAnom(r, "cve:CVE-2016-8367") {
		t.Errorf("ILC unauth CVE not attributed: %v", r.Meta["anomalies"])
	}
}

func TestPcworxStop(t *testing.T) {
	req := append([]byte{0x01, 0x05, 0x00, 0x08}, []byte("StopPLC")...)
	r := drivePcworx(t, req)
	if !hasAnom(r, "ics-plc-mode-change") {
		t.Errorf("stop not flagged: %v", r.Meta["anomalies"])
	}
}
