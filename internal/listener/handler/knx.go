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
		// Reply with status=0x24 (no more connections) so the scanner
		// records a live device but we don't get tied up in a tunnel.
		reply = k.buildConnectError()
		banner = "knx CONNECT_RESPONSE err=0x24"
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
		ip := la.IP.To4()
		if ip != nil {
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
