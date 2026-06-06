package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// knx implements just enough of KNXnet/IP (default UDP 3671) to fool a
// building-automation scanner. The protocol is the IP-tunnel for KNX
// home/building bus traffic and shows up in Shodan as a flagship "IoT
// in real buildings" target.
//
// Frame layout, all big-endian:
//
//	byte 0   = header length (always 0x06)
//	byte 1   = protocol version (always 0x10 = 1.0)
//	bytes 2..3 = service identifier (e.g. 0x0201 SEARCH_REQUEST,
//	             0x0203 DESCRIPTION_REQUEST, 0x0205 CONNECT_REQUEST)
//	bytes 4..5 = total frame length
//	then service-dependent body.
//
// The most common scan probe is SEARCH_REQUEST (0x0201) with a HPAI of
// the responder's UDP endpoint in the body. We reply with
// SEARCH_RESPONSE (0x0202) advertising a believable "MDT KNX IP Router"
// device.
type knx struct{ lim *udpReflectLimiter }

func (k *knx) Name() string { return "knx" }

const (
	knxSvcSearchRequest      = 0x0201
	knxSvcSearchResponse     = 0x0202
	knxSvcDescriptionRequest = 0x0203
	knxSvcDescriptionRsp     = 0x0204
	knxSvcConnectRequest     = 0x0205
	knxSvcConnectResponse    = 0x0206
)

func (k *knx) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	if len(payload) < 6 {
		res.Meta["short"] = true
		return res, nil
	}
	if payload[0] != 0x06 || payload[1] != 0x10 {
		res.Meta["non_knx"] = true
		return res, nil
	}
	svc := binary.BigEndian.Uint16(payload[2:4])
	total := binary.BigEndian.Uint16(payload[4:6])
	res.Meta["service"] = svc
	res.Meta["total_len"] = total

	// Reject packets whose declared total length doesn't match the datagram
	// (a minimal/malformed probe used purely for reflection).
	if int(total) != len(payload) {
		res.Meta["bad_total_len"] = total
		_ = cfg
		return res, nil
	}

	var reply []byte
	var banner string
	switch svc {
	case knxSvcSearchRequest:
		res.Meta["op"] = "SEARCH_REQUEST"
		// A real SEARCH_REQUEST is 14 bytes (6-byte header + 8-byte HPAI).
		if len(payload) >= 14 {
			reply = k.buildSearchResponse(src, pc)
			banner = "knx SEARCH_RESPONSE"
		}
	case knxSvcDescriptionRequest:
		res.Meta["op"] = "DESCRIPTION_REQUEST"
		if len(payload) >= 14 {
			reply = k.buildDescriptionResponse()
			banner = "knx DESCRIPTION_RESPONSE"
		}
	case knxSvcConnectRequest:
		res.Meta["op"] = "CONNECT_REQUEST"
		flagAnomaly(&res, "knx-tunnel-connect")
		setIfEmpty(res.Meta, "intent", "KNXnet/IP CONNECT — opening a tunnel to the building bus")
		// Reply with status=0x24 (no more connections) so the scanner
		// records a live device but we don't get tied up in a tunnel.
		reply = k.buildConnectError()
		banner = "knx CONNECT_RESPONSE err=0x24"
	case 0x0420: // TUNNELLING_REQUEST — cEMI after the 4-byte connection header
		res.Meta["op"] = "TUNNELLING_REQUEST"
		knxClassifyCEMI(payload, 10, false, &res)
	case 0x0530: // ROUTING_INDICATION — multicast cEMI, no connection header
		res.Meta["op"] = "ROUTING_INDICATION"
		knxClassifyCEMI(payload, 6, true, &res)
	case 0x0310: // DEVICE_CONFIGURATION_REQUEST — device management (property r/w)
		res.Meta["op"] = "DEVICE_CONFIGURATION_REQUEST"
		flagAnomaly(&res, "knx-device-mgmt")
		setIfEmpty(res.Meta, "intent", "KNXnet/IP device configuration — property read/write (management)")
	default:
		res.Meta["op"] = "other"
	}
	if len(reply) > 0 {
		// Global rate-limit so a spoofed-source SEARCH flood can't reflect
		// amplified bandwidth at a forged victim.
		if !k.lim.allow() {
			res.Meta["rate_limited"] = true
		} else if _, err := pc.WriteTo(reply, src); err != nil {
			res.Meta["write_err"] = err.Error()
		} else {
			res.BannerSent = banner
		}
	}
	_ = cfg
	return res, nil
}

// knxClassifyCEMI parses the cEMI L_Data frame carried in a TUNNELLING_REQUEST
// or ROUTING_INDICATION and classifies the application-layer service (APCI):
// GroupValue read/write (drive lights/HVAC/actuators), A_Memory_Write and
// property/key/restart management (firmware/config tampering, the KNX
// "backdoor" surface). cemiOff is where the cEMI frame starts; routing marks a
// multicast ROUTING_INDICATION (no tunnel needed).
//
// cEMI L_Data: msg_code(1) | add_info_len(1) | ctrl1(1) ctrl2(1) |
//
//	src(2) | dst(2) | npdu_len(1) | tpci(1) apci...
func knxClassifyCEMI(payload []byte, cemiOff int, routing bool, res *Result) {
	if len(payload) < cemiOff+1 {
		return
	}
	msgCode := payload[cemiOff]
	res.Meta["cemi_msg_code"] = fmtByte(msgCode)
	// Only L_Data frames (req 0x11 / ind 0x29 / con 0x2E) carry an APCI.
	if msgCode != 0x11 && msgCode != 0x29 && msgCode != 0x2E {
		return
	}
	addInfo := int(payload[cemiOff+1])
	p := cemiOff + 2 + addInfo // skip msg_code, add_info_len, additional info
	if len(payload) < p+8 {
		return
	}
	src := binary.BigEndian.Uint16(payload[p+2 : p+4])
	dst := binary.BigEndian.Uint16(payload[p+4 : p+6])
	res.Meta["knx_src"] = knxIndAddr(src)
	res.Meta["knx_dst"] = knxGroupAddr(dst)
	// npdu_len at p+6; TPCI/APCI at p+7..p+8 (10-bit APCI).
	if len(payload) < p+9 {
		return
	}
	apci := (uint16(payload[p+7]&0x03) << 8) | uint16(payload[p+8])
	apci &= 0x03C0 // top 4 APCI bits select the service group
	res.Meta["knx_apci"] = knxAPCIName(apci)
	switch apci {
	case 0x0000: // A_GroupValue_Read
		flagAnomaly(res, "knx-bus-read")
		setIfEmpty(res.Meta, "intent", "KNX GroupValueRead — reading bus state (sensor/actuator values)")
	case 0x0080: // A_GroupValue_Write — drive lights/HVAC/actuators
		flagAnomaly(res, "knx-bus-write")
		res.Meta["intent"] = "KNX GroupValueWrite — driving the building bus (lights/HVAC/actuators)"
		if routing {
			flagAnomaly(res, "knx-routing-injection")
		}
	case 0x0280: // A_Memory_Write — write device memory (firmware/config)
		flagAnomaly(res, "knx-memory-write")
		res.Meta["intent"] = "KNX A_Memory_Write — writing device memory (firmware/config tampering)"
	case 0x0380: // A_Restart — restart the device
		flagAnomaly(res, "knx-device-restart")
		res.Meta["intent"] = "KNX A_Restart — restarting a bus device"
	case 0x00C0, 0x0100: // IndividualAddress write/read — re-addressing
		flagAnomaly(res, "knx-programming")
		setIfEmpty(res.Meta, "intent", "KNX device programming — individual-address (re)assignment")
	case 0x03C0: // property/key/authorize management services
		flagAnomaly(res, "knx-programming")
		setIfEmpty(res.Meta, "intent", "KNX management — property/key/authorize (device programming)")
	}
}

// knxIndAddr formats a KNX individual address (area.line.device).
func knxIndAddr(a uint16) string {
	return itoa(int(a>>12)) + "." + itoa(int(a>>8&0xF)) + "." + itoa(int(a&0xFF))
}

// knxGroupAddr formats a KNX 3-level group address (main/middle/sub).
func knxGroupAddr(a uint16) string {
	return itoa(int(a>>11)) + "/" + itoa(int(a>>8&0x7)) + "/" + itoa(int(a&0xFF))
}

func knxAPCIName(apci uint16) string {
	switch apci {
	case 0x0000:
		return "A_GroupValue_Read"
	case 0x0040:
		return "A_GroupValue_Response"
	case 0x0080:
		return "A_GroupValue_Write"
	case 0x00C0:
		return "A_IndividualAddress_Write"
	case 0x0100:
		return "A_IndividualAddress_Read"
	case 0x0200:
		return "A_Memory_Read"
	case 0x0280:
		return "A_Memory_Write"
	case 0x0300:
		return "A_DeviceDescriptor_Read"
	case 0x0380:
		return "A_Restart"
	case 0x03C0:
		return "A_Management"
	}
	return "apci-0x" + fmtByteU16(apci)
}

// dibDevice + dibSupp form the body advertised in both SEARCH_RESPONSE
// and DESCRIPTION_RESPONSE.
func (k *knx) deviceDIB() []byte {
	// DIB Device Information (54 bytes):
	//   length=0x36, type=0x01, medium=0x02 (TP1), status=0x01,
	//   knx_addr=0x0000 (1.1.0 ignored), proj_id=0, serial(6),
	//   multicast_ip(4)=224.0.23.12, mac(6), friendly_name(30).
	dib := make([]byte, 54)
	dib[0] = 0x36
	dib[1] = 0x01
	dib[2] = 0x02
	dib[3] = 0x01
	binary.BigEndian.PutUint16(dib[4:6], 0x1101) // 1.1.1
	binary.BigEndian.PutUint16(dib[6:8], 0x0000) // project id
	copy(dib[8:14], []byte{0x00, 0x83, 0x10, 0x4f, 0x44, 0x6e})
	dib[14] = 224
	dib[15] = 0
	dib[16] = 23
	dib[17] = 12
	copy(dib[18:24], []byte{0xcc, 0x1b, 0xe0, 0xa1, 0xb2, 0xc3})
	name := "MDT KNX IP Router"
	copy(dib[24:54], []byte(name))
	return dib
}

func (k *knx) suppDIB() []byte {
	// DIB Supported Service Families. 1 byte len, 1 byte type=0x02,
	// then pairs of (family_id, version). Advertise CORE, DEV_MGMT,
	// TUNNELLING, ROUTING.
	body := []byte{0x02, 0x01, 0x03, 0x01, 0x04, 0x01, 0x05, 0x01}
	out := make([]byte, 2+len(body))
	out[0] = byte(2 + len(body))
	out[1] = 0x02
	copy(out[2:], body)
	return out
}

func (k *knx) buildSearchResponse(src net.Addr, pc net.PacketConn) []byte {
	// HPAI: 8 bytes (len=0x08, proto=0x01 UDP, ip(4), port(2)).
	hpai := make([]byte, 8)
	hpai[0] = 0x08
	hpai[1] = 0x01
	if la, ok := pc.LocalAddr().(*net.UDPAddr); ok && la != nil {
		// KNXnet/IP HPAI carries a fixed 4-byte IPv4 address — the protocol has
		// no IPv6 form. When bound on a v6 address we leave the IP field as
		// 0.0.0.0, which is the KNXnet/IP "route-back" convention ("reply to the
		// sender's address") — the correct spec behavior, not a truncated v6.
		if ip := la.IP.To4(); ip != nil {
			copy(hpai[2:6], ip)
		}
		binary.BigEndian.PutUint16(hpai[6:8], uint16(la.Port))
	}
	body := append([]byte{}, hpai...)
	body = append(body, k.deviceDIB()...)
	body = append(body, k.suppDIB()...)
	return k.frame(knxSvcSearchResponse, body)
}

func (k *knx) buildDescriptionResponse() []byte {
	body := append([]byte{}, k.deviceDIB()...)
	body = append(body, k.suppDIB()...)
	return k.frame(knxSvcDescriptionRsp, body)
}

// CONNECT_RESPONSE with status=0x24 ("no more connections") — common
// real-device response when the connection table is full. Looks live
// but doesn't open a tunnel.
func (k *knx) buildConnectError() []byte {
	body := []byte{
		0x00,       // communication channel id
		0x24,       // status: no more connections
		0x08, 0x01, // HPAI len + proto
		0, 0, 0, 0, // ip 0.0.0.0 (filled below)
		0, 0, // port 0
		0x04, 0x04, 0x02, 0x00, // CRD for TUNNEL_CONNECTION
	}
	return k.frame(knxSvcConnectResponse, body)
}

func (k *knx) frame(svc uint16, body []byte) []byte {
	total := 6 + len(body)
	out := make([]byte, 6+len(body))
	out[0] = 0x06
	out[1] = 0x10
	binary.BigEndian.PutUint16(out[2:4], svc)
	binary.BigEndian.PutUint16(out[4:6], uint16(total))
	copy(out[6:], body)
	return out
}
