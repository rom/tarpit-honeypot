package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// OT / building-automation UDP protocol responders. Capture + decode + flag;
// capture-only (no reply) so none can amplify.
//
//   - crestron:   Crestron control-system discovery (UDP 41794)
//   - pjlink:     PJLink projector / AV control (UDP 4352)
//   - cbus:       Clipsal C-Bus lighting / building automation (UDP 20023)
//   - dnp3_udp:   DNP3 over UDP — utility SCADA (UDP 20000)
//   - saia_sbus:  Saia Ether-S-Bus PCD controllers (UDP 5050)

// crestron (Crestron discovery, UDP 41794). Crestron control processors answer
// a broadcast discovery used to enumerate AV / room-automation gear.
type crestron struct{}

func (c *crestron) Name() string { return "crestron" }

func (c *crestron) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ba-crestron-discovery-probe")
	body := string(payload)
	if indexFold(body, "crestron") >= 0 {
		res.Meta["crestron_marker"] = true
	}
	// The discovery payload often embeds the requester hostname as ASCII.
	if printable := asciiRun(payload); printable != "" {
		res.Meta["crestron_text"] = safe.SanitizeForLog(clipStr(printable, 128))
	}
	return res, nil
}

// pjlink (PJLink, UDP 4352 search / TCP 4352 control). The PJLink "SRCH"
// class-2 discovery broadcast enumerates networked projectors.
type pjlink struct{}

func (p *pjlink) Name() string { return "pjlink" }

func (p *pjlink) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ba-pjlink-probe")
	body := strings.TrimSpace(string(payload))
	switch {
	case hasPrefixFold(body, "%2SRCH"):
		res.Meta["pjlink_cmd"] = "search"
	case hasPrefixFold(body, "%1POWR"), hasPrefixFold(body, "%2POWR"):
		res.Meta["pjlink_cmd"] = "power"
		flagAnomaly(&res, "ba-projector-control")
	case hasPrefixFold(body, "%1AVMT"), hasPrefixFold(body, "%2AVMT"):
		// AV-mute blanks the projector (availability tampering in a venue/AV room).
		res.Meta["pjlink_cmd"] = "avmute"
		flagAnomaly(&res, "ba-projector-control")
	case hasPrefixFold(body, "%1INPT"), hasPrefixFold(body, "%2INPT"):
		// Input switch changes what the projector displays.
		res.Meta["pjlink_cmd"] = "input"
		flagAnomaly(&res, "ba-projector-control")
	}
	return res, nil
}

// cbus (Clipsal C-Bus over IP, UDP 20023). C-Bus PCI commands toggle lighting /
// HVAC groups; we capture the framing and flag a write to a group address.
type cbus struct{}

func (c *cbus) Name() string { return "cbus" }

func (c *cbus) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ba-cbus-probe")
	body := string(payload)
	if printable := asciiRun(payload); printable != "" {
		res.Meta["cbus_text"] = safe.SanitizeForLog(clipStr(printable, 128))
	}
	// A point-to-multipoint lighting command (0x05 app, group on/off) is an
	// actuation attempt.
	if indexFold(body, "0538") >= 0 || strings.HasPrefix(body, "\\05") {
		flagAnomaly(&res, "ba-lighting-control")
	}
	return res, nil
}

// dnp3UDP (DNP3 over UDP, UDP 20000). Same data-link frame as DNP3/TCP: the
// 0x0564 start bytes, then length, control, dst, src. A control-function from
// an untrusted source is a utility-SCADA manipulation attempt.
type dnp3UDP struct{}

func (d *dnp3UDP) Name() string { return "dnp3_udp" }

func (d *dnp3UDP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ics-dnp3-udp-probe")
	if len(payload) >= 10 && payload[0] == 0x05 && payload[1] == 0x64 {
		res.Meta["dnp3_length"] = payload[2]
		ctrl := payload[3]
		res.Meta["dnp3_control"] = ctrl
		res.Meta["dnp3_dst"] = binary.LittleEndian.Uint16(payload[4:6])
		res.Meta["dnp3_src"] = binary.LittleEndian.Uint16(payload[6:8])
		fc := ctrl & 0x0f
		res.Meta["dnp3_function"] = fc
		// DL function 3 = unconfirmed-user-data carrying app-layer control.
		if fc == 0x03 || fc == 0x04 {
			flagAnomaly(&res, "ics-dnp3-control")
		}
	}
	return res, nil
}

// saiaSBus (Saia Ether-S-Bus, UDP 5050). Saia Burgess PCD building/industrial
// controllers; the frame carries a length, version, protocol and attribute.
type saiaSBus struct{}

func (s *saiaSBus) Name() string { return "saia_sbus" }

func (s *saiaSBus) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ics-saia-sbus-probe")
	if len(payload) >= 11 {
		res.Meta["sbus_length"] = binary.BigEndian.Uint32(payload[0:4])
		res.Meta["sbus_version"] = payload[4]
		res.Meta["sbus_protocol"] = payload[5]
		res.Meta["sbus_attribute"] = payload[6]
		// attribute 0x00 = request; command byte follows the address.
		if payload[6] == 0x00 && len(payload) >= 11 {
			res.Meta["sbus_command"] = payload[10]
			// write/run/restart commands manipulate the PCD.
			switch payload[10] {
			case 0x0e, 0x0f, 0x14, 0x15, 0x16:
				flagAnomaly(&res, "ics-saia-control")
			}
		}
	}
	return res, nil
}

// asciiRun returns the longest run of printable ASCII in b (min length 3),
// used to surface the human-readable hostname/text some discovery probes carry.
func asciiRun(b []byte) string {
	best, cur := "", strings.Builder{}
	flush := func() {
		if cur.Len() > len(best) {
			best = cur.String()
		}
		cur.Reset()
	}
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			cur.WriteByte(c)
		} else {
			flush()
		}
	}
	flush()
	if len(best) < 3 {
		return ""
	}
	return best
}
