package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// radius parses RADIUS Access-Request packets (RFC 2865, UDP port
// 1812). Packet structure:
//
//   code(1) | identifier(1) | length(2) | authenticator(16) | attrs...
//
// We capture the client's User-Name (attr type 1) and the
// User-Password (attr type 2 — RC4-XORed against MD5(secret||auth),
// which we can't decrypt without the shared secret, but we record
// the raw bytes). Reply with Access-Reject so the client knows to
// stop.
type radius struct{}

func (r *radius) Name() string { return "radius" }

func (r *radius) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...)}
	if len(payload) < 20 {
		res.Meta = map[string]any{"short_packet": true}
		return res, nil
	}
	code := payload[0]
	id := payload[1]
	length := binary.BigEndian.Uint16(payload[2:4])
	res.Meta = map[string]any{
		"code":      radiusCodeName(code),
		"identifier": id,
		"length":    length,
	}
	if code != 1 { // Access-Request
		return res, nil
	}
	// Bound length against the actual datagram size before slicing.
	// length is attacker-controlled (the wire-level RADIUS length field);
	// a value < 20 makes payload[20:length] panic with low > high, and
	// a value > len(payload) panics with high > len.
	if int(length) < 20 || int(length) > len(payload) {
		res.Meta["bad_length"] = length
		return res, nil
	}
	// Walk attribute list.
	attrs := payload[20:length]
	for p := 0; p+2 <= len(attrs); {
		t := attrs[p]
		l := int(attrs[p+1])
		if l < 2 || p+l > len(attrs) {
			break
		}
		v := attrs[p+2 : p+l]
		switch t {
		case 1:
			res.Meta["user_name"] = string(v)
		case 2:
			res.Meta["user_password_encrypted_hex"] = byteToHex(v)
		case 4:
			if len(v) == 4 {
				res.Meta["nas_ip"] = net.IP(v).String()
			}
		case 32:
			res.Meta["nas_identifier"] = string(v)
		}
		p += l
	}
	// Reply Access-Reject (code=3) so the client gives up. Length=20
	// (header only), authenticator copies the request authenticator
	// modulo the spec's response-auth computation (which would need
	// the shared secret to be exact). Most clients accept the reply.
	resp := make([]byte, 20)
	resp[0] = 3
	resp[1] = id
	binary.BigEndian.PutUint16(resp[2:4], 20)
	copy(resp[4:20], payload[4:20])
	if _, err := pc.WriteTo(resp, src); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "radius Access-Reject"
	_ = cfg
	return res, nil
}

func radiusCodeName(c byte) string {
	switch c {
	case 1:
		return "Access-Request"
	case 2:
		return "Access-Accept"
	case 3:
		return "Access-Reject"
	case 4:
		return "Accounting-Request"
	case 5:
		return "Accounting-Response"
	case 11:
		return "Access-Challenge"
	}
	return ""
}
