package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Consumer / smart-home IoT UDP protocol responders. All capture-only — these
// LAN protocols are spoofable and several are obfuscated rather than
// authenticated, so the honeypot records + decodes the probe and flags it but
// never replies (no reflection surface).
//
//   - mqtt_sn:      MQTT-SN, MQTT for Sensor Networks (UDP 1884)
//   - tplink_kasa:  TP-Link Kasa smart-plug/bulb LAN protocol (UDP 9999)
//   - tuya:         Tuya smart-home device LAN protocol (UDP 6667)
//   - miio:         Xiaomi mihome / miIO protocol (UDP 54321)
//   - lwm2m:        OMA LwM2M device management over CoAP (UDP 5683/5684)

// mqttSN (MQTT-SN, UDP 1884).
type mqttSN struct{}

func (m *mqttSN) Name() string { return "mqtt_sn" }

func (m *mqttSN) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iot-mqtt-sn-probe")
	if len(payload) < 2 {
		res.Meta["short_packet"] = true
		return res, nil
	}
	// length byte (or 0x01 + 2-byte length), then msg type.
	mt := payload[1]
	if payload[0] == 0x01 && len(payload) >= 4 {
		mt = payload[3]
	}
	res.Meta["mqttsn_msg_type"] = mt
	res.Meta["mqttsn_msg"] = mqttSNMsgName(mt)
	if mt == 0x04 { // PUBLISH
		flagAnomaly(&res, "iot-mqtt-sn-publish")
	}
	return res, nil
}

func mqttSNMsgName(t byte) string {
	switch t {
	case 0x00:
		return "ADVERTISE"
	case 0x01:
		return "SEARCHGW"
	case 0x04:
		return "CONNECT"
	case 0x0C:
		return "PUBLISH"
	case 0x12:
		return "SUBSCRIBE"
	}
	return "type-" + strconv.Itoa(int(t))
}

// tplinkKasa (TP-Link Kasa, UDP 9999). Kasa "encrypts" its JSON with a trivial
// autokey XOR (seed 171); we decrypt it so the probed command/credentials are
// captured in clear. Decryption is local-only; nothing is executed or replied.
type tplinkKasa struct{}

func (t *tplinkKasa) Name() string { return "tplink_kasa" }

func (t *tplinkKasa) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iot-tplink-kasa-probe")
	if len(payload) == 0 {
		return res, nil
	}
	dec := kasaDecrypt(payload)
	if strings.Contains(dec, "{") {
		res.Meta["kasa_json"] = safe.SanitizeForLog(clipStr(dec, 1024))
		if indexFold(dec, "system") >= 0 || indexFold(dec, "get_sysinfo") >= 0 {
			res.Meta["kasa_cmd"] = "get_sysinfo"
		}
		if indexFold(dec, "set_relay_state") >= 0 {
			flagAnomaly(&res, "iot-actuation-attempt")
		}
	}
	return res, nil
}

// kasaDecrypt applies TP-Link's autokey-XOR (initial key 171, key = prev byte).
func kasaDecrypt(b []byte) string {
	out := make([]byte, len(b))
	key := byte(171)
	for i, c := range b {
		out[i] = c ^ key
		key = c
	}
	return string(out)
}

// tuya (Tuya LAN protocol, UDP 6667). Frames start with the magic 0x000055AA;
// the body is AES-encrypted, so we capture the framing + command word.
type tuya struct{}

func (t *tuya) Name() string { return "tuya" }

func (t *tuya) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iot-tuya-probe")
	if len(payload) >= 12 && binary.BigEndian.Uint32(payload[0:4]) == 0x000055AA {
		res.Meta["tuya_seq"] = binary.BigEndian.Uint32(payload[4:8])
		res.Meta["tuya_command"] = binary.BigEndian.Uint32(payload[8:12])
	}
	return res, nil
}

// miio (Xiaomi miIO, UDP 54321). The 32-byte header carries a magic (0x2131),
// device id, stamp and an MD5 token-checksum; the body is AES-CBC. We decode
// the header so device-enumeration / token-probing is logged.
type miio struct{}

func (m *miio) Name() string { return "miio" }

func (m *miio) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iot-miio-probe")
	if len(payload) >= 32 && binary.BigEndian.Uint16(payload[0:2]) == 0x2131 {
		res.Meta["miio_length"] = binary.BigEndian.Uint16(payload[2:4])
		res.Meta["miio_device_id"] = binary.BigEndian.Uint32(payload[8:12])
		res.Meta["miio_stamp"] = binary.BigEndian.Uint32(payload[12:16])
		// A "hello" handshake is all 0xff in the device-id/stamp/token region.
		if payload[4] == 0xff && payload[5] == 0xff {
			res.Meta["miio_msg"] = "hello"
		}
	}
	return res, nil
}

// lwm2m (OMA LwM2M over CoAP, UDP 5683/5684). LwM2M rides CoAP; we decode the
// CoAP header and surface the Register ("/rd") / bootstrap intent.
type lwm2m struct{}

func (l *lwm2m) Name() string { return "lwm2m" }

func (l *lwm2m) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iot-lwm2m-probe")
	if len(payload) < 4 {
		res.Meta["short_packet"] = true
		return res, nil
	}
	res.Meta["coap_version"] = payload[0] >> 6
	code := payload[1]
	res.Meta["coap_code"] = strconv.Itoa(int(code>>5)) + "." + leadingZero(int(code&0x1f))
	body := string(payload)
	switch {
	case indexFold(body, "rd") >= 0 && (code>>5) == 0x02: // POST /rd
		res.Meta["lwm2m_op"] = "register"
	case indexFold(body, "bs") >= 0:
		res.Meta["lwm2m_op"] = "bootstrap"
	}
	return res, nil
}

func leadingZero(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}
