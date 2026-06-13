package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// ethercatFrame builds an EtherCAT-over-UDP frame with one datagram: cmd +
// dlen bytes of (zero) data + a 2-byte working counter.
func ethercatFrame(cmd byte, dlen int) []byte {
	dg := make([]byte, 10+dlen+2)
	dg[0] = cmd
	binary.LittleEndian.PutUint16(dg[6:8], uint16(dlen)) // len+flags
	frame := make([]byte, 2+len(dg))
	binary.LittleEndian.PutUint16(frame[0:2], uint16(len(dg))|(0x1<<12)) // length | type=1
	copy(frame[2:], dg)
	return frame
}

func driveEtherCAT(t *testing.T, frame []byte) (Result, *fakePacketConn) {
	t.Helper()
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 34980}
	res, _ := (&ethercat{}).Handle(context.Background(), frame, src, pc, config.Listener{})
	return res, pc
}

// A logical-read (LRD) is process-data access; the reply carries a non-zero
// working counter and filled data.
func TestEtherCATRead(t *testing.T) {
	res, pc := driveEtherCAT(t, ethercatFrame(10, 8)) // LRD, 8 data bytes
	if res.Meta["ethercat_cmd"] != "LRD" {
		t.Errorf("cmd = %v; want LRD", res.Meta["ethercat_cmd"])
	}
	if !hasAnom(res, "ics-process-data-access") {
		t.Errorf("read not flagged: %v", res.Meta["anomalies"])
	}
	if len(pc.written) == 0 {
		t.Fatalf("no reply written")
	}
	resp := pc.written[0]
	wkc := binary.LittleEndian.Uint16(resp[len(resp)-2:])
	if wkc == 0 {
		t.Errorf("working counter not incremented in reply")
	}
}

// A logical-write (LWR) is control manipulation.
func TestEtherCATWrite(t *testing.T) {
	res, _ := driveEtherCAT(t, ethercatFrame(11, 4)) // LWR
	if !hasAnom(res, "ics-plc-write") {
		t.Errorf("write not flagged: %v", res.Meta["anomalies"])
	}
}

// A non-EtherCAT frame type is ignored without a reply (no reflection).
func TestEtherCATNonEtherCAT(t *testing.T) {
	frame := []byte{0x00, 0x00} // type 0
	res, pc := driveEtherCAT(t, frame)
	if _, ok := res.Meta["non_ethercat_type"]; !ok {
		t.Errorf("non-EtherCAT type not detected: %v", res.Meta)
	}
	if len(pc.written) != 0 {
		t.Errorf("non-EtherCAT frame should not be answered")
	}
}
