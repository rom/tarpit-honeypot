package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestFinsTCPWriteFlagged(t *testing.T) {
	req := append([]byte{}, "FINS"...)
	req = binary.BigEndian.AppendUint32(req, 20) // length
	req = binary.BigEndian.AppendUint32(req, 2)  // command: FINS frame send
	req = binary.BigEndian.AppendUint32(req, 0)  // error
	frame := make([]byte, 12)                    // 10-byte FINS header + MRC/SRC
	frame[10], frame[11] = 0x01, 0x02            // Memory Area Write
	req = append(req, frame...)
	res, reply := runDevsvc(t, &finsTCP{}, req)
	if len(reply) < 4 || string(reply[0:4]) != "FINS" {
		t.Errorf("reply = %v; want a FINS frame", reply)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "fins-tcp-write-attempt") {
		t.Errorf("anomalies = %v; want fins-tcp-write-attempt", anoms)
	}
}

func TestSecsSelectAndProgramSend(t *testing.T) {
	// Select.req -> Select.rsp (stype 2).
	sel := binary.BigEndian.AppendUint32(nil, 10)
	sel = append(sel, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01)
	_, reply := runDevsvc(t, &secsGEM{}, sel)
	if len(reply) < 14 || reply[9] != 0x02 {
		t.Errorf("reply = %v; want HSMS Select.rsp (stype 2)", reply)
	}
	// S7F3 process-program send -> secs-program-send.
	data := binary.BigEndian.AppendUint32(nil, 10)
	data = append(data, 0x00, 0x01, 0x87, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02) // stream 7, func 3, stype 0
	res, _ := runDevsvc(t, &secsGEM{}, data)
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "secs-program-send") {
		t.Errorf("anomalies = %v; want secs-program-send", anoms)
	}
}

func TestPcomIDAndWrite(t *testing.T) {
	res, reply := runDevsvc(t, &pcom{}, []byte("/00ID\r"))
	if len(reply) == 0 {
		t.Errorf("expected a PCOM identification reply")
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "pcom-probe") {
		t.Errorf("anomalies = %v; want pcom-probe", anoms)
	}
	resW, _ := runDevsvc(t, &pcom{}, []byte("/00SB 1 0\r"))
	aw, _ := resW.Meta["anomalies"].([]string)
	if !containsStr(aw, "pcom-write-attempt") {
		t.Errorf("anomalies = %v; want pcom-write-attempt", aw)
	}
}

func TestProfinetDetectionNoReply(t *testing.T) {
	pc := &capPC{}
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 49152}
	res, _ := (&profinet{}).Handle(context.Background(), []byte{0x04, 0x00, 0x20, 0x00}, src, pc, config.Listener{})
	if len(pc.wrote) != 0 {
		t.Errorf("profinet must not reply (reflection-safe); wrote %v", pc.wrote)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "profinet-connect") {
		t.Errorf("anomalies = %v; want profinet-connect", anoms)
	}
}

func TestWdbrpcConnectReplies(t *testing.T) {
	pc := &capPC{}
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 8), Port: 50000}
	res, _ := (&wdbrpc{lim: newUDPReflectLimiter()}).Handle(context.Background(),
		[]byte{0x00, 0x00, 0x00, 0x01, 0x55, 0x66}, src, pc, config.Listener{})
	if len(pc.wrote) == 0 {
		t.Errorf("expected a bounded WDB reply")
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "wdbrpc-connect") {
		t.Errorf("anomalies = %v; want wdbrpc-connect", anoms)
	}
}
