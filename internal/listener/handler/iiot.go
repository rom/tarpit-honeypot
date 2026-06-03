package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// Industrial-IoT UDP protocol responders — the UDP transports/discovery layers
// of common IIoT stacks whose TCP sides may already be modeled (modbus, opcua,
// ethernetip, hartip). Capture + decode + flag; replies are either omitted
// (capture-only) or strictly bounded + globally rate-limited so the sensor can
// never amplify.
//
//   - modbus_udp:    Modbus over UDP (UDP 502)
//   - enip_udp:      EtherNet/IP CIP discovery — ListIdentity (UDP 44818)
//   - opcua_pubsub:  OPC UA PubSub over UDP (UDP 4840)
//   - dds_rtps:      DDS/RTPS — OMG Data Distribution Service (UDP 7400+)
//   - hartip_udp:    HART-IP over UDP (UDP 5094)

// modbusUDP (Modbus/UDP, UDP 502). Same MBAP+PDU as Modbus/TCP. A write-class
// function code from an untrusted source is an actuation attempt.
type modbusUDP struct{}

func (m *modbusUDP) Name() string { return "modbus_udp" }

func (m *modbusUDP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iiot-modbus-udp-probe")
	if len(payload) >= 8 {
		res.Meta["mbap_txn"] = binary.BigEndian.Uint16(payload[0:2])
		res.Meta["mbap_unit"] = payload[6]
		fc := payload[7]
		res.Meta["modbus_function"] = fc
		switch fc {
		case 0x05, 0x06, 0x0f, 0x10:
			flagAnomaly(&res, "ics-modbus-write")
		case 0x08:
			flagAnomaly(&res, "ics-modbus-diagnostic")
		}
	}
	return res, nil
}

// enipUDP (EtherNet/IP CIP discovery, UDP 44818). The ListIdentity (0x0063)
// command is the unauthenticated discovery that enumerates Allen-Bradley /
// Rockwell PLCs — and a known amplification vector, so capture-only.
type enipUDP struct{}

func (e *enipUDP) Name() string { return "enip_udp" }

func (e *enipUDP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iiot-enip-discovery-probe")
	if len(payload) >= 2 {
		cmd := binary.LittleEndian.Uint16(payload[0:2])
		res.Meta["enip_command"] = enipCmdName(cmd)
		if cmd == 0x0063 || cmd == 0x0004 { // ListIdentity / ListServices
			flagAnomaly(&res, "ics-device-enumeration")
			flagAnomaly(&res, "amplification-probe")
		}
	}
	return res, nil
}

func enipCmdName(c uint16) string {
	switch c {
	case 0x0004:
		return "ListServices"
	case 0x0063:
		return "ListIdentity"
	case 0x0064:
		return "ListInterfaces"
	case 0x0065:
		return "RegisterSession"
	}
	return "0x" + strconv.FormatInt(int64(c), 16)
}

// opcuaPubSub (OPC UA PubSub over UDP, UDP 4840). UADP network messages start
// with a version/flags byte; we surface the publisher id so subscriber spoofing
// / data-injection recon is logged.
type opcuaPubSub struct{}

func (o *opcuaPubSub) Name() string { return "opcua_pubsub" }

func (o *opcuaPubSub) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iiot-opcua-pubsub-probe")
	if len(payload) >= 1 {
		ver := payload[0] & 0x0f
		res.Meta["uadp_version"] = ver
		flags := payload[0] >> 4
		res.Meta["uadp_flags"] = flags
		// PublisherId present (flag bit) — record the leading bytes of it.
		if flags&0x01 != 0 && len(payload) >= 3 {
			res.Meta["uadp_publisher_id"] = binary.LittleEndian.Uint16(payload[1:3])
		}
	}
	return res, nil
}

// ddsRTPS (DDS/RTPS, UDP 7400+). RTPS messages (used by ROS 2 and industrial
// data buses) begin with the magic "RTPS". A participant-discovery probe maps
// the data bus; we decode the version + guidPrefix vendor.
type ddsRTPS struct{}

func (d *ddsRTPS) Name() string { return "dds_rtps" }

func (d *ddsRTPS) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iiot-dds-rtps-probe")
	if len(payload) >= 8 && string(payload[0:4]) == "RTPS" {
		res.Meta["rtps_version"] = strconv.Itoa(int(payload[4])) + "." + strconv.Itoa(int(payload[5]))
		res.Meta["rtps_vendor"] = "0x" + strconv.FormatInt(int64(binary.BigEndian.Uint16(payload[6:8])), 16)
		flagAnomaly(&res, "ics-data-bus-discovery")
	}
	return res, nil
}

// hartIPUDP (HART-IP over UDP, UDP 5094). HART-IP can run on UDP as well as
// TCP; the 8-byte header carries version, message type and id.
type hartIPUDP struct{}

func (h *hartIPUDP) Name() string { return "hartip_udp" }

func (h *hartIPUDP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "iiot-hartip-probe")
	if len(payload) >= 5 {
		res.Meta["hartip_version"] = payload[0]
		res.Meta["hartip_msg_type"] = payload[1]
		res.Meta["hartip_msg_id"] = payload[2]
		if payload[1] == 0 { // request
			flagAnomaly(&res, "ics-field-device-probe")
		}
	}
	return res, nil
}
