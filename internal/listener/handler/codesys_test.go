package handler

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func driveCodesys(t *testing.T, req []byte) Result {
	t.Helper()
	return driveDrain(t, func(c net.Conn) Result {
		res, _ := (&codesys{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, req)
}

func TestCodesysFileTransfer(t *testing.T) {
	req := append([]byte{0xC5, 0x01, 0x00, 0x10}, []byte("CmpFileTransfer download app.app")...)
	r := driveCodesys(t, req)
	if !hasAnom(r, "ics-plc-program-access") {
		t.Errorf("file transfer not flagged: %v", r.Meta["anomalies"])
	}
	if !hasAnom(r, "cve:CVE-2022-31806") {
		t.Errorf("CODESYS no-auth CVE not attributed: %v", r.Meta["anomalies"])
	}
}

func TestCodesysLogin(t *testing.T) {
	req := append([]byte{0xC5, 0x01, 0x00, 0x08}, []byte("CmpUserMgr login admin")...)
	r := driveCodesys(t, req)
	if !hasAnom(r, "ics-codesys-login") {
		t.Errorf("login not flagged: %v", r.Meta["anomalies"])
	}
	if !hasAnom(r, "cve:CVE-2022-31802") {
		t.Errorf("gateway auth-bypass CVE not attributed: %v", r.Meta["anomalies"])
	}
}

func TestCodesysStopApp(t *testing.T) {
	req := append([]byte{0xC5, 0x01, 0x00, 0x08}, []byte("CmpApp stopapp")...)
	r := driveCodesys(t, req)
	if !hasAnom(r, "ics-plc-mode-change") {
		t.Errorf("stop-app not flagged as mode change: %v", r.Meta["anomalies"])
	}
}
