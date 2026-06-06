package handler

import (
	"encoding/binary"
	"testing"
)

func wdbCall(proc uint32) []byte {
	b := make([]byte, 24)
	binary.BigEndian.PutUint32(b[0:4], 0xCAFE0001)   // xid
	binary.BigEndian.PutUint32(b[4:8], 0)            // msg_type = call
	binary.BigEndian.PutUint32(b[8:12], 2)           // rpcvers
	binary.BigEndian.PutUint32(b[12:16], 0x55555555) // WDBPROG
	binary.BigEndian.PutUint32(b[16:20], 1)          // vers
	binary.BigEndian.PutUint32(b[20:24], proc)       // proc
	return b
}

func TestWDBMemoryAccess(t *testing.T) {
	r := udpResult(t, &wdbrpc{lim: newUDPReflectLimiter()}, wdbCall(0x42))
	if r.Meta["wdb_program"] != "WDBPROG" {
		t.Errorf("wdb_program = %v", r.Meta["wdb_program"])
	}
	if !hasAnomaly(r, "wdbrpc-mem-access") {
		t.Errorf("memory access not flagged: %v", r.Meta["anomalies"])
	}
	if !hasAnomaly(r, "cve:CVE-2010-2965") {
		t.Errorf("WDB agent CVE not attributed: %v", r.Meta["anomalies"])
	}
}

func TestWDBFunctionCallRCE(t *testing.T) {
	r := udpResult(t, &wdbrpc{lim: newUDPReflectLimiter()}, wdbCall(0x65))
	if !hasAnomaly(r, "wdbrpc-rce") {
		t.Errorf("func-call RCE not flagged: %v", r.Meta["anomalies"])
	}
}

func TestWDBUrgent11(t *testing.T) {
	big := append(wdbCall(1), make([]byte, 1500)...)
	r := udpResult(t, &wdbrpc{lim: newUDPReflectLimiter()}, big)
	if !hasAnomaly(r, "wdbrpc-urgent11") {
		t.Errorf("URGENT/11 oversized not flagged: %v", r.Meta["anomalies"])
	}
	if !hasAnomaly(r, "cve:CVE-2019-12256") {
		t.Errorf("URGENT/11 CVE not attributed: %v", r.Meta["anomalies"])
	}
}
