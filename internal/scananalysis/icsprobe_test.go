package scananalysis

import "testing"

// modbusADU builds a Modbus/TCP frame: MBAP header + PDU bytes.
func modbusADU(unit byte, pdu ...byte) []byte {
	out := []byte{0x00, 0x01, 0x00, 0x00, 0x00, byte(1 + len(pdu)), unit}
	return append(out, pdu...)
}

func TestClassifyModbusDeviceID(t *testing.T) {
	// Read Device Identification: function 0x2B, MEI type 0x0E.
	v := ClassifyPayload(modbusADU(1, 0x2b, 0x0e, 0x01, 0x00), "modbus")
	if v.NSEScript != "modbus-device-id" {
		t.Errorf("NSEScript = %q; want modbus-device-id", v.NSEScript)
	}
	if !v.VersionProbe {
		t.Error("device-id probe should be a version probe")
	}
}

func TestClassifyModbusReportServerID(t *testing.T) {
	v := ClassifyPayload(modbusADU(1, 0x11), "modbus")
	if v.NSEScript != "modbus-discover" {
		t.Errorf("NSEScript = %q; want modbus-discover", v.NSEScript)
	}
}

func TestClassifyModbusMetasploitDetect(t *testing.T) {
	// Read Exception Status (0x07) is Metasploit modbus_detect's liveness probe.
	v := ClassifyPayload(modbusADU(1, 0x07), "modbus")
	if v.Tool != "metasploit" {
		t.Errorf("Tool = %q; want metasploit", v.Tool)
	}
	if v.NSEScript != "modbus-detect" {
		t.Errorf("NSEScript = %q; want modbus-detect", v.NSEScript)
	}
}

func TestClassifyModbusIgnoresNonProbe(t *testing.T) {
	// A plain Read Holding Registers (0x03) is normal traffic, not a recon
	// identity probe — it must not be tagged as an NSE script.
	v := ClassifyPayload(modbusADU(1, 0x03, 0x00, 0x00, 0x00, 0x0a), "modbus")
	if v.NSEScript != "" {
		t.Errorf("NSEScript = %q; want empty for a normal read", v.NSEScript)
	}
}

func TestClassifyS7Info(t *testing.T) {
	// TPKT(0x03 0x00 len) + COTP CR (PDU type 0xE0).
	pkt := []byte{0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00}
	v := ClassifyPayload(pkt, "s7")
	if v.NSEScript != "s7-info" {
		t.Errorf("NSEScript = %q; want s7-info", v.NSEScript)
	}
	if !v.VersionProbe {
		t.Error("s7 COTP CR should be a version probe")
	}
}

func TestClassifyENIPInfo(t *testing.T) {
	// ENIP ListIdentity command 0x0063 (little-endian on the wire: 0x63 0x00).
	pkt := []byte{0x63, 0x00, 0x00, 0x00}
	v := ClassifyPayload(pkt, "ethernetip")
	if v.NSEScript != "enip-info" {
		t.Errorf("NSEScript = %q; want enip-info", v.NSEScript)
	}
}

func TestClassifyFoxInfo(t *testing.T) {
	v := ClassifyPayload([]byte("fox a 1 -1 fox hello\n"), "fox")
	if v.NSEScript != "fox-info" {
		t.Errorf("NSEScript = %q; want fox-info", v.NSEScript)
	}
}

func TestClassifyICSProbeWrongHandlerNoMatch(t *testing.T) {
	// The Modbus device-id byte pattern must not match on an unrelated handler.
	v := ClassifyPayload(modbusADU(1, 0x2b, 0x0e), "http")
	if v.NSEScript == "modbus-device-id" {
		t.Error("modbus probe matched on a non-modbus handler")
	}
}
