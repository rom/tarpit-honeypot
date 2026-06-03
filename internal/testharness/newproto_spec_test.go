package testharness

import "testing"

// The newly-added UDP protocol handlers must carry mis-implementation coverage
// in the harness so a config that names them gets a "catches the misframe" case
// asserting the right anomaly.
func TestNewProtocolSpecsHaveMisimpl(t *testing.T) {
	want := map[string]string{
		"modbus_udp": "ics-modbus-write",
		"slmp":       "ics-plc-write",
		"dnp3_udp":   "ics-dnp3-control",
		"enip_udp":   "ics-device-enumeration",
		"mqtt_sn":    "iot-mqtt-sn-publish",
		"slp":        "amplification-probe",
	}
	for handler, anomaly := range want {
		sp, ok := specs[handler]
		if !ok {
			t.Errorf("no protocol spec for new handler %q", handler)
			continue
		}
		found := false
		for _, m := range sp.Misimpl {
			if m.Anomaly == anomaly {
				found = true
			}
		}
		if !found {
			t.Errorf("spec %q: no misimpl case expecting anomaly %q", handler, anomaly)
		}
	}
}
