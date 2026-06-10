package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// chronyReq builds a chrony cmdmon CMD_REQUEST datagram for the given command.
func chronyReq(command uint16, bodyLen int) []byte {
	b := make([]byte, 20+bodyLen)
	b[0] = chronyProtoVersion
	b[1] = chronyPktCmdRequest
	binary.BigEndian.PutUint16(b[4:6], command)
	binary.BigEndian.PutUint32(b[8:12], 0xdeadbeef) // sequence
	return b
}

func TestChronydClassifiesAndReplies(t *testing.T) {
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 50000}
	cases := []struct {
		name    string
		cmd     uint16
		class   string
		anomaly string
	}{
		{"tracking", chronyReqTracking, "recon", "chrony-cmdmon-recon"},
		{"settime", chronyReqSettime, "clock-manipulation", "chrony-clock-manipulation"},
		{"add_server", chronyReqAddServer, "source-manipulation", "chrony-source-manipulation"},
		{"cmdallow", chronyReqCmdAllowAll, "access-control", "chrony-access-control-change"},
		{"shutdown", chronyReqShutdown, "service-control", "chrony-service-control"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc := &fakePacketConn{}
			h := &chronyd{lim: newUDPReflectLimiter()}
			res, _ := h.Handle(context.Background(), chronyReq(tc.cmd, 0), src, pc, config.Listener{})
			if res.Meta["chrony_command_class"] != tc.class {
				t.Errorf("class = %v; want %v", res.Meta["chrony_command_class"], tc.class)
			}
			if !hasAnom(res, tc.anomaly) {
				t.Errorf("missing anomaly %q: %v", tc.anomaly, res.Meta["anomalies"])
			}
			if !hasAnom(res, "chrony-cmdmon-probe") {
				t.Errorf("missing base probe marker")
			}
			// A reply (NoHostAccess) is emitted, smaller than/equal to the request.
			if len(pc.written) != 1 {
				t.Fatalf("expected 1 reply; got %d", len(pc.written))
			}
			if got := pc.written[0]; got[1] != chronyPktCmdReply {
				t.Errorf("reply pkt_type = %d; want CMD_REPLY", got[1])
			}
		})
	}
}

func TestChronydMalformedShortPacket(t *testing.T) {
	pc := &fakePacketConn{}
	h := &chronyd{lim: newUDPReflectLimiter()}
	res, _ := h.Handle(context.Background(), []byte{0x06, 0x01, 0x00}, &net.UDPAddr{}, pc, config.Listener{})
	if !hasAnom(res, "chrony-cmdmon-malformed") || !hasAnom(res, "cve:CVE-2012-4503") {
		t.Errorf("short packet should flag malformed + CVE-2012-4503: %v", res.Meta["anomalies"])
	}
	if len(pc.written) != 0 {
		t.Errorf("malformed short packet must not be answered")
	}
}

func TestChronydSubnetsOverflowCVE(t *testing.T) {
	pc := &fakePacketConn{}
	h := &chronyd{lim: newUDPReflectLimiter()}
	res, _ := h.Handle(context.Background(), chronyReq(chronyReqSubnetsAccessed, 400), &net.UDPAddr{}, pc, config.Listener{})
	if !hasAnom(res, "cve:CVE-2012-4502") {
		t.Errorf("oversized subnets_accessed should flag CVE-2012-4502: %v", res.Meta["anomalies"])
	}
}

func TestChronydAmplifierSuppressed(t *testing.T) {
	defer SetReplyPolicy("full", false)
	SetReplyPolicy("full", true) // suppress reflector replies
	pc := &fakePacketConn{}
	h := &chronyd{lim: newUDPReflectLimiter()}
	res, _ := h.Handle(context.Background(), chronyReq(chronyReqTracking, 0), &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7)}, pc, config.Listener{})
	if len(pc.written) != 0 {
		t.Errorf("reply must be suppressed under no-amplifier policy")
	}
	if res.Meta["amplifier_suppressed"] != true {
		t.Errorf("expected amplifier_suppressed meta: %v", res.Meta)
	}
}
