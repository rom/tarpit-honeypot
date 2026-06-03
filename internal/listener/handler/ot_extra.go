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
//
// All are detection + capture only; nothing is controlled, and the UDP one is
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
	// Program-download / control-program messages are the TRITON reprogramming
	// path — flag them as a (would-be) safety-controller manipulation attempt.
	if mt == 0x05 || mt == 0x0a || mt == 0x0d {
		flagAnomaly(&res, "ics-safety-controller-manipulation")
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
	// ROC Plus header: dst_unit, dst_group, src_unit, src_group, opcode, len...
	if n >= 6 {
		res.Meta["roc_dst_unit"] = req[0]
		res.Meta["roc_dst_group"] = req[1]
		res.Meta["roc_opcode"] = req[4]
		// opcode 17 = login / opcode 24 = read parameters: credential / config theft.
		if req[4] == 17 {
			flagAnomaly(&res, "ics-roc-plus-login")
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
	// Crimson management opens with a small framed request; answer with a short
	// "G3" identity reply so a Red Lion-aware scanner believes it found a panel.
	_, _ = conn.Write([]byte{0x47, 0x33, 0x00, 0x01}) // "G3" + minimal status
	res.BannerSent = "crimson g3"
	return res, nil
}
