package handler

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func driveMGCP(t *testing.T, payload string) (Result, *fakePacketConn) {
	t.Helper()
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 2427}
	res, _ := (&mgcp{}).Handle(context.Background(), []byte(payload), src, pc, config.Listener{})
	return res, pc
}

// AUEP (AuditEndpoint) is gateway enumeration; it gets a 200 echoing the
// transaction id and is flagged as recon.
func TestMGCPAuditEndpoint(t *testing.T) {
	res, pc := driveMGCP(t, "AUEP 1234 *@gw.example.net MGCP 1.0\r\nF: A,M\r\n")
	if res.Meta["mgcp_command"] != "AuditEndpoint" {
		t.Errorf("command = %v; want AuditEndpoint", res.Meta["mgcp_command"])
	}
	if !hasAnom(res, "mgcp-audit") {
		t.Errorf("audit not flagged: %v", res.Meta["anomalies"])
	}
	if len(pc.written) == 0 || !strings.HasPrefix(string(pc.written[0]), "200 1234 OK") {
		t.Errorf("unexpected MGCP response: %q", pc.written)
	}
}

// CRCX (CreateConnection) is the toll-fraud / call-setup primitive; the reply
// carries SDP.
func TestMGCPCreateConnection(t *testing.T) {
	res, pc := driveMGCP(t, "CRCX 9999 aaln/1@gw MGCP 1.0\r\nC: A3C47F21\r\nM: sendrecv\r\n")
	if !hasAnom(res, "mgcp-create-connection") {
		t.Errorf("CRCX not flagged: %v", res.Meta["anomalies"])
	}
	if len(pc.written) == 0 || !bytes.Contains(pc.written[0], []byte("v=0")) {
		t.Errorf("CRCX response missing SDP: %q", pc.written)
	}
}

// A non-MGCP datagram is ignored (no reply — no reflection).
func TestMGCPNonMGCP(t *testing.T) {
	res, pc := driveMGCP(t, "GET / HTTP/1.1\r\n")
	if res.Meta["non_mgcp"] != true {
		t.Errorf("non-MGCP not detected: %v", res.Meta)
	}
	if len(pc.written) != 0 {
		t.Errorf("non-MGCP datagram should not be answered: %q", pc.written)
	}
}
