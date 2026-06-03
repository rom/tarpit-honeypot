package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// coap is the UDP CoAP receiver (RFC 7252, default port 5683). CoAP is
// HTTP-shaped for constrained devices — most IoT discovery scans send
// a GET /.well-known/core to enumerate exposed resources. The header
// is fixed 4 bytes:
//
//	bit 0..1 = version (2 in v1)
//	bit 2..3 = type (0=CON, 1=NON, 2=ACK, 3=RST)
//	bit 4..7 = token length (0..8)
//	byte 1   = code (e.g. 0x01 = GET, 0x02 = POST)
//	bytes 2..3 = message id (big endian)
//	then TKL bytes of token, then options TLV, optional 0xff payload marker.
//
// We capture code + token + URI options, and reply with a 2.05 Content
// payload listing one made-up /.well-known/core entry — that's the
// typical "this is a real CoAP server" answer.
type coap struct{ lim *udpReflectLimiter }

func (c *coap) Name() string { return "coap" }

const (
	coapTypeCON = 0
	coapTypeACK = 2

	coapCodeDeleted     = 0x42 // 2.02 (Deleted)
	coapCodeChanged     = 0x44 // 2.04 (Changed)
	coapCodeContent     = 0x45 // 2.05 (Content)
	coapCodeBadRequest  = 0x80 // 4.00
	coapCodeUnsupported = 0xa1 // 5.01
)

func (c *coap) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	if len(payload) < 4 {
		res.Meta["short"] = true
		return res, nil
	}
	ver := (payload[0] >> 6) & 0x3
	mtype := (payload[0] >> 4) & 0x3
	tkl := int(payload[0] & 0x0f)
	code := payload[1]
	mid := binary.BigEndian.Uint16(payload[2:4])
	res.Meta["ver"] = ver
	res.Meta["type"] = mtype
	res.Meta["tkl"] = tkl
	res.Meta["code"] = code
	res.Meta["mid"] = mid

	if ver != 1 || tkl > 8 || 4+tkl > len(payload) {
		// Not a sane CoAP packet; stay quiet to avoid amplification.
		res.Meta["malformed"] = true
		return res, nil
	}
	token := payload[4 : 4+tkl]
	res.Meta["token_hex"] = byteToHex(token)

	// Walk options to extract the Uri-Path (option number 11). Each
	// option is a 1-byte delta+length, with extended forms for values
	// over 12. We only care about Uri-Path so the implementation is
	// intentionally narrow.
	off := 4 + tkl
	curOpt := 0
	var uriPath []byte
	for off < len(payload) {
		b := payload[off]
		if b == 0xff {
			// payload marker
			off++
			break
		}
		off++
		delta := int(b >> 4)
		olen := int(b & 0x0f)
		switch delta {
		case 13:
			if off >= len(payload) {
				break
			}
			delta = 13 + int(payload[off])
			off++
		case 14:
			if off+1 >= len(payload) {
				break
			}
			delta = 269 + int(binary.BigEndian.Uint16(payload[off:off+2]))
			off += 2
		case 15:
			res.Meta["opt_err"] = "delta=15"
			return c.reply(payload, mid, token, coapCodeBadRequest, nil, src, pc, res)
		}
		switch olen {
		case 13:
			if off >= len(payload) {
				break
			}
			olen = 13 + int(payload[off])
			off++
		case 14:
			if off+1 >= len(payload) {
				break
			}
			olen = 269 + int(binary.BigEndian.Uint16(payload[off:off+2]))
			off += 2
		case 15:
			res.Meta["opt_err"] = "len=15"
			return c.reply(payload, mid, token, coapCodeBadRequest, nil, src, pc, res)
		}
		if off+olen > len(payload) {
			break
		}
		curOpt += delta
		val := payload[off : off+olen]
		off += olen
		if curOpt == 11 { // Uri-Path
			if len(uriPath) > 0 {
				uriPath = append(uriPath, '/')
			}
			uriPath = append(uriPath, val...)
		}
	}
	if len(uriPath) > 0 {
		res.Meta["uri_path"] = string(uriPath)
		// /.well-known/core enumerates every resource — the CoAP discovery
		// amplification primitive (small GET → large link-format reply).
		if string(uriPath) == ".well-known/core" {
			flagAnomaly(&res, "coap-resource-discovery")
			flagAnomaly(&res, "amplification-probe")
		}
	}

	// Method-aware reply (code: 0x01 GET, 0x02 POST, 0x03 PUT, 0x04 DELETE).
	// Writes against an exposed CoAP device are actuation attempts (toggling
	// a relay, reflashing config) — flag them and answer as a real device
	// would, but never act.
	switch code {
	case 0x02, 0x03: // POST / PUT
		flagAnomaly(&res, "coap-write-attempt")
		return c.reply(payload, mid, token, coapCodeChanged, nil, src, pc, res)
	case 0x04: // DELETE
		flagAnomaly(&res, "coap-write-attempt")
		return c.reply(payload, mid, token, coapCodeDeleted, nil, src, pc, res)
	}

	// GET: reply with /.well-known/core listing a believable set of resources
	// — looks like a real CoAP IoT device to common scanners.
	body := []byte(`</.well-known/core>;rt="core",` +
		`</led>;rt="oic.r.switch.binary";if="oic.if.a",` +
		`</sensors/temp>;rt="oic.r.temperature";if="oic.if.s",` +
		`</3/0>;rt="oma.lwm2m";ct=11543`)
	return c.reply(payload, mid, token, coapCodeContent, body, src, pc, res)
}

func (c *coap) reply(req []byte, mid uint16, token []byte, code byte, body []byte, src net.Addr, pc net.PacketConn, res Result) (Result, error) {
	hdr := make([]byte, 4)
	// version=1, type=ACK, tkl=len(token)
	hdr[0] = byte(1<<6) | byte(coapTypeACK<<4) | byte(len(token)&0x0f)
	hdr[1] = code
	binary.BigEndian.PutUint16(hdr[2:4], mid)
	pkt := append([]byte{}, hdr...)
	pkt = append(pkt, token...)
	// Content-Format option (option 12) = application/link-format (40).
	pkt = append(pkt, 0xc1, 40)
	if len(body) > 0 {
		pkt = append(pkt, 0xff)
		pkt = append(pkt, body...)
	}
	// Global rate-limit replies so a spoofed-source flood can't reflect
	// amplified bandwidth at a forged victim (a 4-byte CoAP probe would
	// otherwise draw an ~82-byte response).
	if !c.lim.allow() {
		res.Meta["rate_limited"] = true
		return res, nil
	}
	if _, err := pc.WriteTo(pkt, src); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "coap 2.05 Content"
	return res, nil
}
