package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// Second IIoT batch — additional industrial transports / discovery. Capture-only.
//
//   powerlink (3819), slmp (5007), cip_io (2222), ff_hse (1089), ads_udp (48899)

// powerlink — Ethernet POWERLINK (UDP 3819). Decodes the message type; SoC/PReq
// frames drive real-time motion, so a probe is industrial-bus reconnaissance.
type powerlink struct{}

func (p *powerlink) Name() string { return "powerlink" }

func (p *powerlink) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iiot-powerlink-probe")
	if len(payload) >= 3 {
		mt := payload[2] & 0x3f
		res.Meta["epl_message_type"] = mt
		switch mt {
		case 0x01:
			res.Meta["epl_msg"] = "SoC"
		case 0x03:
			res.Meta["epl_msg"] = "PReq"
		case 0x06:
			res.Meta["epl_msg"] = "ASnd"
		}
	}
	return res, nil
}

// slmp — Mitsubishi SLMP / MELSEC over UDP (UDP 5007). A Write/Run command from
// an untrusted source is a PLC manipulation attempt.
type slmp struct{}

func (s *slmp) Name() string { return "slmp" }

func (s *slmp) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iiot-slmp-probe")
	// SLMP 3E frame: subheader 0x5400 (request), then network/PC/unit, then a
	// 2-byte command at offset 11.
	if len(payload) >= 13 && binary.BigEndian.Uint16(payload[0:2]) == 0x5400 {
		cmd := binary.LittleEndian.Uint16(payload[11:13])
		res.Meta["slmp_command"] = "0x" + strconv.FormatInt(int64(cmd), 16)
		switch cmd {
		case 0x1401: // Write
			flagAnomaly(&res, "ics-plc-write")
		case 0x1001, 0x1002: // Remote Run / Stop
			flagAnomaly(&res, "ics-plc-mode-change")
		}
	}
	return res, nil
}

// cipIO — EtherNet/IP Class-1 cyclic I/O over UDP (UDP 2222). Carries the
// real-time I/O (process image) between scanner and adapter — observing it is
// industrial-process reconnaissance.
type cipIO struct{}

func (c *cipIO) Name() string { return "cip_io" }

func (c *cipIO) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iiot-cip-io-probe")
	if len(payload) >= 2 {
		res.Meta["cip_item_count"] = binary.LittleEndian.Uint16(payload[0:2])
	}
	flagAnomaly(&res, "ics-process-data-access")
	return res, nil
}

// ffHSE — Foundation Fieldbus HSE (UDP 1089). Process-automation fieldbus over
// Ethernet; decodes the FDA header version/type.
type ffHSE struct{}

func (f *ffHSE) Name() string { return "ff_hse" }

func (f *ffHSE) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iiot-fieldbus-hse-probe")
	if len(payload) >= 2 {
		res.Meta["ffhse_version"] = payload[0]
		res.Meta["ffhse_type"] = payload[1]
	}
	return res, nil
}

// adsUDP — Beckhoff ADS over UDP (UDP 48899). The discovery/identify request
// enumerates TwinCAT runtimes (AMS NetId); a probe is engineering recon.
type adsUDP struct{}

func (a *adsUDP) Name() string { return "ads_udp" }

func (a *adsUDP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iiot-ads-udp-probe")
	// ADS UDP discovery header: magic 0x71146603 (little-endian) then a command.
	if len(payload) >= 8 && binary.LittleEndian.Uint32(payload[0:4]) == 0x71146603 {
		res.Meta["ads_command"] = binary.LittleEndian.Uint32(payload[4:8])
		flagAnomaly(&res, "ics-device-enumeration")
	}
	return res, nil
}
