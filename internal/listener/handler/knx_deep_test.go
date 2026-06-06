package handler

import "testing"

// knxTunnel builds a TUNNELLING_REQUEST carrying an L_Data.req cEMI with the
// given APCI low byte / high bits.
func knxTunnel(apciHi, apciLo byte) []byte {
	f := []byte{
		0x06, 0x10, 0x04, 0x20, 0x00, 0x15, // header (total 21)
		0x04, 0x01, 0x00, 0x00, // connection header
		0x11, 0x00, 0xBC, 0xE0, 0x11, 0x01, 0x08, 0x01, 0x01, apciHi, apciLo,
	}
	return f
}

func TestKNXGroupValueWrite(t *testing.T) {
	r := udpResult(t, &knx{lim: newUDPReflectLimiter()}, knxTunnel(0x00, 0x80))
	if !hasAnomaly(r, "knx-bus-write") {
		t.Errorf("GroupValueWrite not flagged: %v", r.Meta["anomalies"])
	}
	if r.Meta["knx_apci"] != "A_GroupValue_Write" {
		t.Errorf("apci = %v", r.Meta["knx_apci"])
	}
	if r.Meta["knx_dst"] != "1/0/1" {
		t.Errorf("knx_dst = %v, want 1/0/1", r.Meta["knx_dst"])
	}
}

func TestKNXMemoryWriteAndRestart(t *testing.T) {
	r := udpResult(t, &knx{lim: newUDPReflectLimiter()}, knxTunnel(0x02, 0x80))
	if !hasAnomaly(r, "knx-memory-write") {
		t.Errorf("A_Memory_Write not flagged: %v", r.Meta["anomalies"])
	}
	r = udpResult(t, &knx{lim: newUDPReflectLimiter()}, knxTunnel(0x03, 0x80))
	if !hasAnomaly(r, "knx-device-restart") {
		t.Errorf("A_Restart not flagged: %v", r.Meta["anomalies"])
	}
}
