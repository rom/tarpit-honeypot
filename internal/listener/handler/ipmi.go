package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type ipmi struct{}

func (i *ipmi) Name() string { return "ipmi" }

// IPMI / RMCP+ over UDP (port 623). Two relevant packet shapes:
//
//  1. RMCP Presence Ping (legacy ASF) — RMCP header + ASF message:
//     version=0x06 reserved=0 seq=0xff class=0x06 (ASF)
//     iana(4) msg_type(1)=0x80 msg_tag(1) reserved(1) data_len(1)
//     We answer with a Presence Pong announcing supported entities.
//
//  2. RMCP+ Open Session Request — IPMI v2 session establishment.
//     We capture the auth/integrity/conf payload types requested and
//     emit a low-effort RAKP-style reject. (Full RMCP+ requires
//     keying material; out of scope.)
func (i *ipmi) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...)}
	if len(payload) < 4 {
		res.Meta = map[string]any{"short_packet": true}
		return res, nil
	}
	if payload[0] != 0x06 {
		res.Meta = map[string]any{"non_rmcp_version": payload[0]}
		return res, nil
	}
	class := payload[3]
	res.Meta = map[string]any{
		"rmcp_class": rmcpClassName(class),
	}

	switch class & 0x1F {
	case 0x06: // ASF
		if len(payload) >= 12 && payload[8] == 0x80 {
			// Presence Ping. Build Presence Pong.
			tag := payload[9]
			pong := make([]byte, 28)
			pong[0] = 0x06                              // version
			pong[2] = payload[2]                        // seq
			pong[3] = 0x06                              // ASF class
			binary.BigEndian.PutUint32(pong[4:8], 4542) // IANA enterprise
			pong[8] = 0x40                              // Presence Pong
			pong[9] = tag
			pong[10] = 0                                  // reserved
			pong[11] = 16                                 // data length
			binary.BigEndian.PutUint32(pong[12:16], 4542) // OEM IANA
			// supported entities: IPMI (1.5/2.0)
			pong[16] = 0x81
			// supported interactions: none
			// rest zero
			if _, err := pc.WriteTo(pong, src); err != nil {
				res.Meta["write_err"] = err.Error()
			}
			res.BannerSent = "ipmi Presence Pong"
			res.Meta["asf_msg"] = "presence_ping"
			return res, nil
		}
	case 0x07: // IPMI
		res.Meta["asf_msg"] = "ipmi-class"
		// Most scanners follow up with RMCP+ Open Session Request; we don't
		// reply with valid keying material but log what they asked for.
		if len(payload) >= 12 {
			// RMCP+ session header starts after the 4-byte RMCP header.
			authType := payload[4]
			res.Meta["auth_type"] = authType
		}
	}
	return res, nil
}

func rmcpClassName(c byte) string {
	switch c & 0x1F {
	case 0x06:
		return "ASF"
	case 0x07:
		return "IPMI"
	case 0x08:
		return "OEM"
	}
	return ""
}
