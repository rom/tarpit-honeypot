package handler

import (
	"context"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// ipmiRMCPPlus builds an RMCP+ (IPMI 2.0) packet with the given payload type.
func ipmiRMCPPlus(payloadType byte, extra int) []byte {
	p := make([]byte, 6+extra)
	p[0] = 0x06        // RMCP version
	p[3] = 0x07        // class = IPMI
	p[4] = 0x06        // auth type = RMCP+
	p[5] = payloadType // low 6 bits = payload type
	return p
}

func TestIPMIRAKPHashDisclosure(t *testing.T) {
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 80), Port: 623}
	// RAKP Message 1 (payload type 0x12).
	res, _ := (&ipmi{}).Handle(context.Background(), ipmiRMCPPlus(0x12, 32), src, &fakePacketConn{}, config.Listener{})
	if !hasAnom(res, "ipmi-rakp-hash-disclosure") || !hasAnom(res, "cve:CVE-2013-4786") {
		t.Errorf("RAKP hash disclosure not flagged: %v", res.Meta["anomalies"])
	}
}
