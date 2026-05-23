package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// bgpH emulates a BGP speaker (TCP 179). A BGP message is a 19-byte header
// (16 bytes of 0xFF marker, 2-byte length, 1-byte type) followed by the
// body; type 1 is OPEN. An external peer trying to OPEN a session against
// a honeypot is high-signal routing-infrastructure reconnaissance / a
// hijack attempt, so we capture the peer's AS + hold time and reply with a
// NOTIFICATION (we never establish the session).
type bgpH struct{}

func (bgpH) Name() string { return "bgp" }

func (bgpH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	hdr := make([]byte, 19)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta["read_err"] = "short"
		return res, nil
	}
	res.Payload = append([]byte(nil), hdr...)
	// Validate the all-ones marker.
	for _, b := range hdr[:16] {
		if b != 0xFF {
			res.Meta["non_bgp"] = true
			return res, nil
		}
	}
	total := int(binary.BigEndian.Uint16(hdr[16:18]))
	msgType := hdr[18]
	res.Meta["bgp_type"] = bgpTypeName(msgType)

	if total > 19 && total <= 4096 {
		body := make([]byte, total-19)
		if _, err := io.ReadFull(conn, body); err == nil {
			res.Payload = append(res.Payload, body...)
			// OPEN body: version(1) myAS(2) holdtime(2) bgpID(4) optlen(1) ...
			if msgType == 1 && len(body) >= 9 {
				res.Meta["bgp_peer_as"] = int(binary.BigEndian.Uint16(body[1:3]))
				res.Meta["bgp_hold_time"] = int(binary.BigEndian.Uint16(body[3:5]))
				res.Meta["bgp_router_id"] = net.IP(body[5:9]).String()
			}
		}
	}
	if msgType == 1 {
		flagAnomaly(&res, "bgp-open-attempt")
	} else {
		flagAnomaly(&res, "bgp-probe")
	}

	// Reply with a NOTIFICATION (type 3): marker + len(21) + type + errcode
	// (6 = Cease) + subcode(0). We never bring the session up.
	notif := make([]byte, 21)
	for i := 0; i < 16; i++ {
		notif[i] = 0xFF
	}
	binary.BigEndian.PutUint16(notif[16:18], 21)
	notif[18] = 3 // NOTIFICATION
	notif[19] = 6 // Cease
	notif[20] = 0
	if _, err := conn.Write(notif); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "bgp notification (cease)"
	return res, nil
}

func bgpTypeName(t byte) string {
	switch t {
	case 1:
		return "OPEN"
	case 2:
		return "UPDATE"
	case 3:
		return "NOTIFICATION"
	case 4:
		return "KEEPALIVE"
	}
	return "unknown"
}
