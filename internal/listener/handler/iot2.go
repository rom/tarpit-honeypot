package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Second IoT batch — smart-home + IP-camera LAN protocols. Capture-only.
//
//   matter (5540), wiz (38899), yeelight (1982),
//   dahua_disc (37810), hikvision_sadp (37020)

// matter — Matter / CHIP smart-home (UDP 5540). Decodes the message header
// flags; a probe is smart-home fabric reconnaissance.
type matter struct{}

func (m *matter) Name() string { return "matter" }

func (m *matter) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iot-matter-probe")
	if len(payload) >= 8 {
		res.Meta["matter_flags"] = payload[0]
		res.Meta["matter_session_id"] = binary.LittleEndian.Uint16(payload[1:3])
	}
	return res, nil
}

// wiz — WiZ smart-bulb LAN control (UDP 38899). Plain-JSON method calls; a
// setPilot/setState from an untrusted source is an actuation attempt.
type wiz struct{}

func (w *wiz) Name() string { return "wiz" }

func (w *wiz) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iot-wiz-probe")
	body := string(payload)
	if m := jsonMethod(body); m != "" {
		res.Meta["wiz_method"] = m
		if m == "setPilot" || m == "setState" {
			flagAnomaly(&res, "iot-actuation-attempt")
		}
	}
	if strings.Contains(body, "{") {
		res.Meta["wiz_json"] = safe.SanitizeForLog(clipStr(body, 512))
	}
	return res, nil
}

// yeelight — Yeelight discovery/control (UDP 1982). SSDP-style search + JSON
// control; flags a set_* control method.
type yeelight struct{}

func (y *yeelight) Name() string { return "yeelight" }

func (y *yeelight) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iot-yeelight-probe")
	body := string(payload)
	if hasPrefixFold(body, "M-SEARCH") {
		res.Meta["yeelight_msg"] = "discover"
	}
	if m := jsonMethod(body); m != "" {
		res.Meta["yeelight_method"] = m
		if strings.HasPrefix(m, "set_") || m == "start_cf" {
			flagAnomaly(&res, "iot-actuation-attempt")
		}
	}
	return res, nil
}

// dahuaDisc — Dahua IP-camera / NVR discovery (UDP 37810). The DHIP/JSON multicast
// probe enumerates Dahua devices (a heavily-exploited camera family).
type dahuaDisc struct{}

func (d *dahuaDisc) Name() string { return "dahua_disc" }

func (d *dahuaDisc) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iot-dahua-discovery-probe")
	flagAnomaly(&res, "device-discovery-probe")
	if m := jsonMethod(string(payload)); m != "" {
		res.Meta["dahua_method"] = m
	}
	return res, nil
}

// hikvisionSADP — Hikvision SADP device discovery (UDP 37020). The XML probe
// enumerates Hikvision cameras/NVRs (another mass-exploited camera family).
type hikvisionSADP struct{}

func (h *hikvisionSADP) Name() string { return "hikvision_sadp" }

func (h *hikvisionSADP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iot-hikvision-sadp-probe")
	flagAnomaly(&res, "device-discovery-probe")
	body := string(payload)
	if indexFold(body, "<probe") >= 0 || indexFold(body, "<Uuid") >= 0 {
		res.Meta["sadp_probe"] = true
	}
	if t := xmlTagValue(body, "MAC"); t != "" {
		res.Meta["sadp_mac"] = safe.SanitizeForLog(clipStr(t, 64))
	}
	return res, nil
}

// jsonMethod extracts the value of a top-level "method" field from a small JSON
// blob ({"method":"x", …}); "" if not present.
func jsonMethod(body string) string {
	i := indexFold(body, "\"method\"")
	if i < 0 {
		return ""
	}
	rest := body[i+8:]
	c := strings.IndexByte(rest, ':')
	if c < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[c+1:])
	rest = strings.TrimPrefix(rest, "\"")
	if j := strings.IndexAny(rest, "\","); j >= 0 {
		return rest[:j]
	}
	return ""
}
