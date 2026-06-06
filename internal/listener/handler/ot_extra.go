package handler

import (
	"bufio"
	"context"
	"net"
	"strconv"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Additional OT/ICS protocol responders.
//
//   - tristation: Triconex TriStation / TSAA (UDP 1502) — the safety-controller
//     protocol abused by the TRITON / TRISIS ICS malware. A probe here is a very
//     high-signal event (someone fingerprinting a Safety Instrumented System).
//   - roc_plus:   Emerson ROC Plus (TCP 4000) — gas/oil flow-computer RTUs.
//   - crimson:    Red Lion Crimson (TCP 789) — HMI / data-station management.
//   - ge_egd:     GE Ethernet Global Data (UDP 18246) — PACSystems / 90-30 / 90-70
//     PLC producer/consumer data exchange.
//   - bsap:       Bristol/Emerson BSAP-IP (UDP 1234) — ControlWave / Bristol RTU
//     SCADA polling.
//   - lontalk:    Echelon LonTalk / LonWorks-IP, CEA-852 (UDP 1628) — building /
//     industrial control networking.
//
// All are detection + capture only; nothing is controlled, and every UDP one is
// strictly bounded + rate-limited so it can never become a reflection vector.

// tristation (Triconex TSAA, UDP 1502).
type tristation struct{ lim *udpReflectLimiter }

func (t *tristation) Name() string { return "tristation" }

func (t *tristation) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	if len(payload) < 4 {
		res.Meta["short_packet"] = true
		return res, nil
	}
	mt := payload[0]
	res.Meta["ts_msg_type"] = mt
	res.Meta["ts_msg"] = tristationMsgName(mt)
	flagAnomaly(&res, "ics-tristation-probe")
	res.Meta["intent"] = "Triconex TriStation probe — Safety Instrumented System fingerprinting (TRITON surface)"
	// Program-download / control-program messages are the TRITON reprogramming
	// path — flag them as a (would-be) safety-controller manipulation attempt.
	if mt == 0x05 || mt == 0x0a || mt == 0x0d {
		flagAnomaly(&res, "ics-safety-controller-manipulation")
		res.Meta["intent"] = "Triconex " + tristationMsgName(mt) + " — safety-controller reprogramming (TRITON/TRISIS path)"
	}
	// A minimal, bounded, rate-limited ack so a probe gets a plausible reply.
	// reply <= request length guarantees no amplification.
	if t.lim.allow() {
		reply := []byte{0x06, 0x00, payload[2], payload[3]}
		if len(reply) <= len(payload) {
			if _, err := pc.WriteTo(reply, src); err == nil {
				res.BannerSent = "tristation ack"
			}
		}
	}
	_ = cfg
	return res, nil
}

func tristationMsgName(t byte) string {
	switch t {
	case 0x01:
		return "connect"
	case 0x02:
		return "disconnect"
	case 0x03:
		return "get-cp-status"
	case 0x05:
		return "download-program"
	case 0x0a:
		return "execute-control-program"
	case 0x0d:
		return "set-program"
	}
	return "type-" + strconv.Itoa(int(t))
}

// rocPlus (Emerson ROC Plus, TCP 4000).
type rocPlus struct{}

func (r *rocPlus) Name() string { return "roc_plus" }

func (r *rocPlus) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	buf := make([]byte, 256)
	n, _ := br.Read(buf)
	if n <= 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}
	req := buf[:n]
	res.Payload = append([]byte(nil), req...)
	flagAnomaly(&res, "ics-roc-plus-command")
	res.Meta["intent"] = "Emerson ROC Plus command — gas/oil flow-computer RTU access"
	// ROC Plus header: dst_unit, dst_group, src_unit, src_group, opcode, len...
	if n >= 6 {
		res.Meta["roc_dst_unit"] = req[0]
		res.Meta["roc_dst_group"] = req[1]
		res.Meta["roc_opcode"] = req[4]
		// opcode 17 = login / opcode 24 = read parameters: credential / config theft.
		switch req[4] {
		case 17: // login
			flagAnomaly(&res, "ics-roc-plus-login")
			res.Meta["intent"] = "Emerson ROC Plus login — flow-computer credential attempt"
		case 24, 25: // parameter read (config / measurement theft)
			res.Meta["intent"] = "Emerson ROC Plus parameter read — exfiltrating RTU config/measurements"
		case 16, 26: // parameter / opcode write (configuration change)
			flagAnomaly(&res, "ics-plc-write")
			res.Meta["intent"] = "Emerson ROC Plus parameter write — changing RTU configuration"
		}
	}
	// Minimal echo-style ack (swap the addressing, opcode 255 = error/ack),
	// bounded to the header so a scanner sees a live RTU.
	if n >= 6 {
		ack := []byte{req[2], req[3], req[0], req[1], 255, 0}
		_, _ = conn.Write(ack)
		res.BannerSent = "roc-plus ack"
	}
	return res, nil
}

// crimson (Red Lion Crimson management, TCP 789).
type crimson struct{}

func (c *crimson) Name() string { return "crimson" }

func (c *crimson) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	buf := make([]byte, 256)
	n, _ := br.Read(buf)
	if n <= 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}
	res.Payload = append([]byte(nil), buf[:n]...)
	res.Meta["crimson_request"] = safe.SanitizeForLog(string(buf[:n]))
	flagAnomaly(&res, "ics-crimson-probe")
	res.Meta["intent"] = "Red Lion Crimson management probe — HMI / data-station access attempt"
	// Crimson management opens with a small framed request; answer with a short
	// "G3" identity reply so a Red Lion-aware scanner believes it found a panel.
	_, _ = conn.Write([]byte{0x47, 0x33, 0x00, 0x01}) // "G3" + minimal status
	res.BannerSent = "crimson g3"
	return res, nil
}

// geEGD (GE Ethernet Global Data, UDP 18246).
//
// EGD is a producer/consumer broadcast protocol GE PLCs (PACSystems RX3i/RX7i,
// Series 90-30/90-70) use to publish process data on a fixed period. Each packet
// opens with a small header: pdu_type, request_id, producer_id (4-byte IP-ish),
// exchange_id, timestamps, status. We capture + decode the header and flag the
// probe. EGD is normally one-way (no reply), so this handler is capture-only —
// the safest possible posture and a clean signal that someone is enumerating GE
// control traffic. Never amplifies because it never writes back.
type geEGD struct{}

func (g *geEGD) Name() string { return "ge_egd" }

func (g *geEGD) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	flagAnomaly(&res, "ics-ge-egd-probe")
	res.Meta["intent"] = "GE EGD probe — enumerating GE PACSystems producer/consumer data exchange"
	if len(payload) < 8 {
		res.Meta["short_packet"] = true
		return res, nil
	}
	pdu := payload[0]
	res.Meta["egd_pdu_type"] = pdu
	res.Meta["egd_pdu"] = geEGDPDUName(pdu)
	res.Meta["egd_request_id"] = int(payload[2]) | int(payload[3])<<8
	// producer id is a 4-byte node identifier (commonly the producer's IP).
	if len(payload) >= 12 {
		res.Meta["egd_producer_id"] = net.IP(payload[8:12]).String()
	}
	return res, nil
}

func geEGDPDUName(t byte) string {
	switch t {
	case 0:
		return "data"
	case 1:
		return "ack"
	case 2:
		return "request"
	}
	return "type-" + strconv.Itoa(int(t))
}

// bsap (Bristol/Emerson BSAP-IP, UDP 1234).
//
// BSAP (Bristol Standard Asynchronous Protocol) over IP is the polling protocol
// for Bristol / Emerson ControlWave and Bristol RTUs. We capture the request,
// decode the local-address / node fields, flag it, and emit a single minimal,
// bounded, rate-limited response so a SCADA-aware scanner sees a live node. The
// reply is shorter than the request and globally rate-limited, so it can never
// be used to amplify.
type bsap struct{ lim *udpReflectLimiter }

func (b *bsap) Name() string { return "bsap" }

func (b *bsap) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	flagAnomaly(&res, "ics-bsap-probe")
	res.Meta["intent"] = "BSAP-IP probe — Bristol/Emerson ControlWave RTU SCADA polling"
	if len(payload) < 4 {
		res.Meta["short_packet"] = true
		return res, nil
	}
	// BSAP-IP header (little-endian): serial, num_msgs, then local/SDLC fields.
	res.Meta["bsap_serial"] = int(payload[0]) | int(payload[1])<<8
	res.Meta["bsap_num_messages"] = payload[2]
	res.Meta["bsap_func"] = payload[3]
	// Bounded ack (echo the serial, flip to a 1-message response). Length 4 <=
	// any accepted request (>=4), so no amplification; rate-limited globally.
	if b.lim.allow() {
		reply := []byte{payload[0], payload[1], 0x01, 0x00}
		if len(reply) <= len(payload) {
			if _, err := pc.WriteTo(reply, src); err == nil {
				res.BannerSent = "bsap ack"
			}
		}
	}
	return res, nil
}

// lonTalk (Echelon LonTalk / LonWorks-IP CEA-852, UDP 1628).
//
// LonWorks/IP (ANSI/CEA-852) tunnels CEA-709.1 control-network packets over UDP
// for building automation and industrial control. We capture + decode the data-
// packet header and flag the probe. Like EGD this is capture-only: CEA-852 data
// packets are config-server-mediated and replying blind to a spoofable source
// would risk turning the sensor into a reflector, so it never writes back.
type lonTalk struct{}

func (l *lonTalk) Name() string { return "lontalk" }

func (l *lonTalk) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	flagAnomaly(&res, "ics-lontalk-probe")
	res.Meta["intent"] = "LonTalk/IP probe — Echelon building/industrial control-network enumeration"
	if len(payload) < 4 {
		res.Meta["short_packet"] = true
		return res, nil
	}
	// CEA-852 header: version, packet_type, then length / extended fields.
	res.Meta["lon_version"] = payload[0]
	res.Meta["lon_packet_type"] = payload[1]
	res.Meta["lon_pdu"] = lonPacketName(payload[1])
	return res, nil
}

func lonPacketName(t byte) string {
	switch t {
	case 0x01:
		return "data"
	case 0x03:
		return "device-registration"
	case 0x04:
		return "device-config-request"
	case 0x63:
		return "channel-membership"
	}
	return "type-" + strconv.Itoa(int(t))
}
