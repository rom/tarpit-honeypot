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
				res.Meta["bgp_version"] = int(body[0])
				res.Meta["bgp_peer_as"] = int(binary.BigEndian.Uint16(body[1:3]))
				res.Meta["bgp_hold_time"] = int(binary.BigEndian.Uint16(body[3:5]))
				res.Meta["bgp_router_id"] = net.IP(body[5:9]).String()
				if as4, mp := bgpOpenCaps(body[9:]); as4 > 0 || mp {
					if as4 > 0 {
						res.Meta["bgp_peer_as4"] = int(as4) // real ASN when peer-as is AS_TRANS(23456)
					}
					res.Meta["bgp_multiprotocol"] = mp
				}
			}
			// UPDATE body: withdrawn-routes-len(2) + withdrawn + total-path-attr-
			// len(2) + attrs + NLRI. NLRI present = the peer is announcing routes,
			// i.e. a prefix-hijack / route-injection attempt against our "router".
			if msgType == 2 && len(body) >= 4 {
				wlen := int(binary.BigEndian.Uint16(body[0:2]))
				if 2+wlen+2 <= len(body) {
					palen := int(binary.BigEndian.Uint16(body[2+wlen : 2+wlen+2]))
					if nlri := 2 + wlen + 2 + palen; nlri < len(body) {
						res.Meta["bgp_nlri_bytes"] = len(body) - nlri
						flagAnomaly(&res, "bgp-route-injection")
					}
					if wlen > 0 {
						flagAnomaly(&res, "bgp-route-withdrawal")
					}
				}
			}
		}
	}
	switch msgType {
	case 1:
		flagAnomaly(&res, "bgp-open-attempt")
		res.Meta["intent"] = "BGP OPEN — unsolicited peering attempt (route-hijack / infrastructure recon)"
	case 2:
		res.Meta["intent"] = "BGP UPDATE — route announcement/withdrawal injected into our speaker (prefix hijack)"
	default:
		flagAnomaly(&res, "bgp-probe")
		res.Meta["intent"] = "BGP " + bgpTypeName(msgType) + " probe"
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

// bgpOpenCaps parses the OPEN optional-parameters block (starting at the
// 1-byte optional-parameters length) for the 4-octet-ASN capability (code 65,
// the real ASN when the 2-byte myAS is AS_TRANS / 23456) and the multiprotocol
// capability (code 1). Best-effort; bounds-checked.
func bgpOpenCaps(b []byte) (as4 uint32, multiproto bool) {
	if len(b) < 1 {
		return 0, false
	}
	optLen := int(b[0])
	if 1+optLen > len(b) {
		optLen = len(b) - 1
	}
	p := b[1 : 1+optLen]
	for len(p) >= 2 {
		ptype, plen := p[0], int(p[1])
		if 2+plen > len(p) {
			break
		}
		val := p[2 : 2+plen]
		if ptype == 2 { // Capabilities optional parameter
			c := val
			for len(c) >= 2 {
				code, clen := c[0], int(c[1])
				if 2+clen > len(c) {
					break
				}
				cv := c[2 : 2+clen]
				switch {
				case code == 65 && len(cv) >= 4:
					as4 = binary.BigEndian.Uint32(cv[:4])
				case code == 1:
					multiproto = true
				}
				c = c[2+clen:]
			}
		}
		p = p[2+plen:]
	}
	return as4, multiproto
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
