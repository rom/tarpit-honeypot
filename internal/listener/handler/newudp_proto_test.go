package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
)

// All 25 newly-added UDP protocol handlers are capture-only: none may ever
// write a reply (UDP source addresses are spoofable, so any reply is a
// potential amplification/reflection vector). This test drives each one
// through GetUDP and asserts (a) it is registered, (b) it records the payload,
// and (c) it writes nothing to the PacketConn.
func TestNewUDPHandlersAreReflectionSafe(t *testing.T) {
	names := []string{
		// general infra
		"wsdiscovery", "memcached_udp", "natpmp", "ubiquiti", "wireguard",
		"openvpn_udp", "l2tp", "rip", "steam", "sentinel_hasp",
		// IoT
		"mqtt_sn", "tplink_kasa", "tuya", "miio", "lwm2m",
		// IIoT
		"modbus_udp", "enip_udp", "opcua_pubsub", "dds_rtps", "hartip_udp",
		// OT / building automation
		"crestron", "pjlink", "cbus", "dnp3_udp", "saia_sbus",
		// batch 2 — general infra
		"slp", "xdmcp", "db_lsp", "kerberos_udp", "lantronix_disc",
		"pcanywhere_stat", "gamespy", "db2_disc", "bt_dht", "rdp_udp",
		// batch 2 — IoT
		"matter", "wiz", "yeelight", "dahua_disc", "hikvision_sadp",
		// batch 2 — IIoT
		"powerlink", "slmp", "cip_io", "ff_hse", "ads_udp",
		// batch 2 — OT / building automation
		"pcom_udp", "synchrophasor", "loxone", "amx_netlinx", "vantage",
	}
	// A 64-byte buffer with a few recognizable bytes; enough to exercise the
	// header decoders without tripping any reply path (there is none).
	pkt := make([]byte, 64)
	for i := range pkt {
		pkt[i] = byte(i)
	}
	for _, n := range names {
		h, err := GetUDP(n, Deps{})
		if err != nil {
			t.Errorf("GetUDP(%q) not registered: %v", n, err)
			continue
		}
		fpc := &fakePacketConn{}
		res, err := h.Handle(context.Background(), pkt, &net.UDPAddr{}, fpc, smallSvcCfg())
		if err != nil {
			t.Errorf("%s: Handle error: %v", n, err)
		}
		if len(fpc.written) != 0 {
			t.Errorf("%s: wrote %d datagram(s) — capture-only handlers must never reply", n, len(fpc.written))
		}
		if res.Payload == nil {
			t.Errorf("%s: did not capture the payload", n)
		}
	}
}

func TestTPLinkKasaDecrypt(t *testing.T) {
	// Encrypt a JSON command with the Kasa autokey XOR and verify we recover it.
	plain := `{"system":{"set_relay_state":{"state":1}}}`
	enc := kasaEncrypt([]byte(plain))
	res, err := (&tplinkKasa{}).Handle(context.Background(), enc, &net.UDPAddr{}, &fakePacketConn{}, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if !hasAnomaly(res, "iot-tplink-kasa-probe") || !hasAnomaly(res, "iot-actuation-attempt") {
		t.Errorf("kasa flags missing: %v", res.Meta["anomalies"])
	}
	if got, _ := res.Meta["kasa_json"].(string); got != plain {
		t.Errorf("kasa_json = %q, want %q", got, plain)
	}
}

func kasaEncrypt(b []byte) []byte {
	out := make([]byte, len(b))
	key := byte(171)
	for i, c := range b {
		out[i] = c ^ key
		key = out[i]
	}
	return out
}

func TestModbusUDPWriteFlagged(t *testing.T) {
	// MBAP (txn=1, proto=0, len=6, unit=1) + FC 0x10 (write multiple registers).
	pkt := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x10, 0x00, 0x00}
	res, err := (&modbusUDP{}).Handle(context.Background(), pkt, &net.UDPAddr{}, &fakePacketConn{}, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if !hasAnomaly(res, "ics-modbus-write") {
		t.Errorf("modbus_udp write flag missing: %v", res.Meta["anomalies"])
	}
}

func TestENIPListIdentityFlagged(t *testing.T) {
	pkt := make([]byte, 24)
	binary.LittleEndian.PutUint16(pkt[0:2], 0x0063) // ListIdentity
	res, err := (&enipUDP{}).Handle(context.Background(), pkt, &net.UDPAddr{}, &fakePacketConn{}, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if !hasAnomaly(res, "ics-device-enumeration") || !hasAnomaly(res, "amplification-probe") {
		t.Errorf("enip flags missing: %v", res.Meta["anomalies"])
	}
	if res.Meta["enip_command"] != "ListIdentity" {
		t.Errorf("enip_command = %v", res.Meta["enip_command"])
	}
}

func TestDNP3UDPControlFlagged(t *testing.T) {
	// 0x0564 start, len, control with function 3 (unconfirmed user data).
	pkt := []byte{0x05, 0x64, 0x14, 0xc3, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00}
	res, err := (&dnp3UDP{}).Handle(context.Background(), pkt, &net.UDPAddr{}, &fakePacketConn{}, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if !hasAnomaly(res, "ics-dnp3-control") {
		t.Errorf("dnp3_udp control flag missing: %v", res.Meta["anomalies"])
	}
}

func TestDDSRTPSDecoded(t *testing.T) {
	pkt := append([]byte("RTPS"), 0x02, 0x03, 0x01, 0x0f)
	pkt = append(pkt, make([]byte, 16)...)
	res, err := (&ddsRTPS{}).Handle(context.Background(), pkt, &net.UDPAddr{}, &fakePacketConn{}, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if !hasAnomaly(res, "ics-data-bus-discovery") {
		t.Errorf("dds flag missing: %v", res.Meta["anomalies"])
	}
	if res.Meta["rtps_version"] != "2.3" {
		t.Errorf("rtps_version = %v", res.Meta["rtps_version"])
	}
}

func TestSLMPWriteFlagged(t *testing.T) {
	// SLMP 3E request (0x5400), command 0x1401 (Write) at offset 11 (LE).
	pkt := []byte{0x54, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x14}
	res, err := (&slmp{}).Handle(context.Background(), pkt, &net.UDPAddr{}, &fakePacketConn{}, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if !hasAnomaly(res, "ics-plc-write") {
		t.Errorf("slmp write flag missing: %v", res.Meta["anomalies"])
	}
}

func TestKerberosUDPASReq(t *testing.T) {
	pkt := append([]byte{0x6a}, []byte("EXAMPLE.COM")...)
	res, err := (&kerberosUDP{}).Handle(context.Background(), pkt, &net.UDPAddr{}, &fakePacketConn{}, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["krb_msg"] != "AS-REQ" || !hasAnomaly(res, "kerberos-pre-auth-probe") {
		t.Errorf("kerberos AS-REQ: %v / %v", res.Meta["krb_msg"], res.Meta["anomalies"])
	}
}

func TestWizActuationFlagged(t *testing.T) {
	pkt := []byte(`{"method":"setPilot","params":{"state":true}}`)
	res, err := (&wiz{}).Handle(context.Background(), pkt, &net.UDPAddr{}, &fakePacketConn{}, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["wiz_method"] != "setPilot" || !hasAnomaly(res, "iot-actuation-attempt") {
		t.Errorf("wiz: %v / %v", res.Meta["wiz_method"], res.Meta["anomalies"])
	}
}
