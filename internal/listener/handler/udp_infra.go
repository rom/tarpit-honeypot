package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Additional general UDP infrastructure / networking protocol responders.
//
// Every handler here is CAPTURE-ONLY: it records + decodes the datagram and
// flags the probe, but never writes a reply. That is deliberate — most of
// these (memcached, NAT-PMP, Ubiquiti discovery, Steam A2S, Sentinel HASP,
// WS-Discovery) are textbook UDP *amplification* vectors, and UDP source
// addresses are spoofable, so a honeypot that answered them would become a
// DDoS reflector. We still get the high-signal detection from logging the
// probe. None of these handlers ever calls pc.WriteTo.

// wsDiscovery — WS-Discovery (UDP 3702), the SOAP-over-UDP probe ONVIF IP
// cameras, network printers and Windows devices answer. A known reflection
// vector, so capture-only.
type wsDiscovery struct{}

func (w *wsDiscovery) Name() string { return "wsdiscovery" }

func (w *wsDiscovery) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "device-discovery-probe")
	body := string(payload)
	if idx := indexFold(body, "<wsd:probe"); idx >= 0 || indexFold(body, "probe") >= 0 {
		res.Meta["wsd_action"] = "Probe"
	}
	if t := xmlTagValue(body, "Types"); t != "" {
		res.Meta["wsd_types"] = safe.SanitizeForLog(clipStr(t, 256))
	}
	return res, nil
}

// memcachedUDP — memcached UDP (UDP 11211). The protocol behind some of the
// largest amplification DDoS on record (51000x). Capture-only, always.
type memcachedUDP struct{}

func (m *memcachedUDP) Name() string { return "memcached_udp" }

func (m *memcachedUDP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "memcached-udp-probe")
	// memcached UDP frame: 8-byte header (req id, seq, n_datagrams, reserved)
	// then an ASCII command. "stats"/"get" with a spoofable source = reflection.
	if len(payload) >= 8 {
		res.Meta["mc_request_id"] = int(binary.BigEndian.Uint16(payload[0:2]))
		cmd := string(payload[8:])
		res.Meta["mc_command"] = safe.SanitizeForLog(clipStr(firstToken(cmd), 64))
		if hasPrefixFold(cmd, "stats") || hasPrefixFold(cmd, "get ") {
			flagAnomaly(&res, "amplification-probe")
		}
	}
	return res, nil
}

// natPMP — NAT-PMP / Port Control Protocol (UDP 5351). Reflection vector;
// capture-only.
type natPMP struct{}

func (n *natPMP) Name() string { return "natpmp" }

func (n *natPMP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "natpmp-probe")
	if len(payload) >= 2 {
		res.Meta["natpmp_version"] = payload[0]
		res.Meta["natpmp_opcode"] = payload[1]
		if payload[0] == 2 {
			res.Meta["natpmp_proto"] = "pcp"
		}
		flagAnomaly(&res, "amplification-probe")
	}
	return res, nil
}

// ubiquiti — Ubiquiti device-discovery (UDP 10001). The UBNT "ping" reflection
// vector abused against UniFi/airOS gear. Capture-only.
type ubiquiti struct{}

func (u *ubiquiti) Name() string { return "ubiquiti" }

func (u *ubiquiti) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ubiquiti-discovery-probe")
	// UBNT discovery frame: version, cmd, then TLV records.
	if len(payload) >= 2 {
		res.Meta["ubnt_version"] = payload[0]
		res.Meta["ubnt_cmd"] = payload[1]
		flagAnomaly(&res, "amplification-probe")
	}
	return res, nil
}

// wireGuard — WireGuard (UDP 51820). We decode the handshake message type so a
// scan for VPN endpoints is logged; capture-only (and we couldn't complete the
// Noise handshake anyway).
type wireGuard struct{}

func (w *wireGuard) Name() string { return "wireguard" }

func (w *wireGuard) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "wireguard-probe")
	if len(payload) >= 4 {
		switch payload[0] {
		case 1:
			res.Meta["wg_msg"] = "handshake-initiation"
		case 2:
			res.Meta["wg_msg"] = "handshake-response"
		case 4:
			res.Meta["wg_msg"] = "transport-data"
		default:
			res.Meta["wg_msg"] = "type-" + strconv.Itoa(int(payload[0]))
		}
	}
	return res, nil
}

// openvpnUDP — OpenVPN over UDP (UDP 1194). Decodes the opcode/key-id byte.
type openvpnUDP struct{}

func (o *openvpnUDP) Name() string { return "openvpn_udp" }

func (o *openvpnUDP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "openvpn-probe")
	if len(payload) >= 1 {
		op := payload[0] >> 3 // top 5 bits = opcode
		res.Meta["ovpn_opcode"] = op
		if op == 7 || op == 8 { // P_CONTROL_HARD_RESET_CLIENT_V2 / V3
			res.Meta["ovpn_msg"] = "client-reset"
		}
	}
	return res, nil
}

// l2tp — L2TP (UDP 1701). Decodes the control-message flag.
type l2tp struct{}

func (l *l2tp) Name() string { return "l2tp" }

func (l *l2tp) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "l2tp-probe")
	if len(payload) >= 2 {
		flags := binary.BigEndian.Uint16(payload[0:2])
		res.Meta["l2tp_version"] = flags & 0x0f
		res.Meta["l2tp_control"] = flags&0x8000 != 0
	}
	return res, nil
}

// rip — Routing Information Protocol v1/v2 (UDP 520). A RIP request from an
// untrusted source is a routing-poisoning / reconnaissance attempt.
type rip struct{}

func (r *rip) Name() string { return "rip" }

func (r *rip) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "rip-probe")
	if len(payload) >= 4 {
		res.Meta["rip_command"] = payload[0]
		res.Meta["rip_version"] = payload[1]
		if payload[0] == 1 { // request
			flagAnomaly(&res, "routing-recon")
		}
		if payload[0] == 2 { // response — a poisoning attempt
			flagAnomaly(&res, "rip-route-injection")
		}
	}
	return res, nil
}

// steamA2S — Source/Steam A2S server query (UDP 27015). The A2S_INFO query is
// a popular reflection vector; capture-only.
type steamA2S struct{}

func (s *steamA2S) Name() string { return "steam" }

func (s *steamA2S) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "steam-a2s-probe")
	// A2S queries are prefixed with 0xFFFFFFFF then a request byte.
	if len(payload) >= 5 && binary.BigEndian.Uint32(payload[0:4]) == 0xFFFFFFFF {
		switch payload[4] {
		case 'T':
			res.Meta["a2s_query"] = "A2S_INFO"
		case 'U':
			res.Meta["a2s_query"] = "A2S_PLAYER"
		case 'V':
			res.Meta["a2s_query"] = "A2S_RULES"
		}
		flagAnomaly(&res, "amplification-probe")
	}
	return res, nil
}

// sentinelHASP — SafeNet/Gemalto Sentinel HASP license manager (UDP 1947).
// A well-known amplification vector and an ICS/engineering-station tell
// (Sentinel docks license many industrial / CAD suites). Capture-only.
type sentinelHASP struct{}

func (s *sentinelHASP) Name() string { return "sentinel_hasp" }

func (s *sentinelHASP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "sentinel-hasp-probe")
	if hasPrefixFold(string(payload), "GET /") || indexFold(string(payload), "hasp") >= 0 {
		res.Meta["hasp_http"] = true
	}
	flagAnomaly(&res, "amplification-probe")
	return res, nil
}
