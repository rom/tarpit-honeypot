package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
)

// dtls is a UDP DTLS receiver (Datagram TLS — RFC 6347/9147, used by WebRTC,
// CoAPS, OpenVPN, IKEv2/IPsec helpers, and some VPN/embedded stacks). A DTLS
// ClientHello is sent in the clear, so we parse it, compute JA3/JA4 over it
// (the same fingerprints as TLS-over-TCP), and reply with a
// HelloVerifyRequest carrying a cookie — the standard DTLS anti-spoofing
// response that makes us look like a real DTLS server while costing us no
// session state. We never complete the handshake (no key exchange), so the
// sensor can't be used as a reflector: the HelloVerifyRequest is bounded and
// only sent in reply to a genuine ClientHello.
type dtls struct{}

func (d *dtls) Name() string { return "dtls" }

// DTLS record header (13 bytes): type(1) version(2) epoch(2) seq(6) length(2).
// DTLS handshake header (12 bytes): type(1) length(3) message_seq(2)
// fragment_offset(3) fragment_length(3), then the handshake body.
const (
	dtlsRecHdr   = 13
	dtlsHsHdr    = 12
	dtlsTypeHS   = 22   // content type: handshake
	dtlsClientHi = 0x01 // handshake type: ClientHello
	dtlsHelloVR  = 0x03 // handshake type: HelloVerifyRequest
)

func (d *dtls) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{"proto": "dtls"}}
	res.Payload = payload

	body, dtlsVer, ok := dtlsClientHelloBody(payload)
	if !ok {
		// Not a DTLS ClientHello — record the attempt and stay silent (no
		// reply to a non-handshake datagram, so we never reflect). A
		// non-handshake datagram to a DTLS port is junk/scan noise.
		res.Meta["dtls"] = "non-clienthello"
		flagAnomaly(&res, "dtls-malformed")
		return res, nil
	}

	// The DTLS ClientHello body differs from TLS in exactly one place: it
	// inserts a `cookie` vector right after session_id. Strip it so the body
	// matches the TLS layout, then wrap it in a TLS Handshake header so the
	// existing JA3/JA4 parser can consume it unchanged.
	tlsBody, ok := dtlsBodyToTLS(body)
	if !ok {
		res.Meta["dtls"] = "unparsable-clienthello"
		return res, nil
	}
	tlsHandshake := make([]byte, 4+len(tlsBody))
	tlsHandshake[0] = dtlsClientHi
	tlsHandshake[1] = byte(len(tlsBody) >> 16)
	tlsHandshake[2] = byte(len(tlsBody) >> 8)
	tlsHandshake[3] = byte(len(tlsBody))
	copy(tlsHandshake[4:], tlsBody)

	if raw, hash := fingerprint.JA3(tlsHandshake); hash != "" {
		res.Meta["ja3"] = hash
		res.Meta["ja3_raw"] = raw
	}
	if ja4 := fingerprint.JA4(tlsHandshake); ja4 != "" {
		res.Meta["ja4"] = ja4
	}
	res.Meta["dtls_version"] = dtlsVersionName(dtlsVer)
	// A DTLS ClientHello to a honeypot port is a service probe — attributable
	// scan activity even though we don't carry the (cookie-verified) session.
	flagAnomaly(&res, "dtls-probe")

	// Reply with a HelloVerifyRequest (epoch 0) carrying a fixed-shape cookie.
	// A real DTLS client will resend its ClientHello echoing the cookie; we
	// don't carry the session, so the engagement is a single capture — but the
	// believable verify-request keeps a scanner's DTLS probe from immediately
	// concluding "closed".
	if pc != nil && src != nil {
		hvr := buildHelloVerifyRequest(dtlsVer)
		if _, err := pc.WriteTo(hvr, src); err != nil {
			res.Meta["write_err"] = err.Error()
		} else {
			res.BannerSent = "dtls hello-verify-request"
		}
	}
	return res, nil
}

// dtlsClientHelloBody validates the DTLS record + handshake framing and
// returns the ClientHello body (from legacy_version onward), the DTLS version,
// and ok. It requires an unfragmented ClientHello (fragment_offset 0 and
// fragment_length == handshake length), which is the normal first flight.
func dtlsClientHelloBody(p []byte) (body []byte, version uint16, ok bool) {
	if len(p) < dtlsRecHdr+dtlsHsHdr {
		return nil, 0, false
	}
	if p[0] != dtlsTypeHS {
		return nil, 0, false
	}
	version = binary.BigEndian.Uint16(p[1:3]) // record version (DTLS 1.0=0xfeff, 1.2=0xfefd)
	recLen := int(binary.BigEndian.Uint16(p[11:13]))
	rec := p[dtlsRecHdr:]
	if recLen > len(rec) {
		return nil, 0, false
	}
	rec = rec[:recLen]
	if len(rec) < dtlsHsHdr || rec[0] != dtlsClientHi {
		return nil, 0, false
	}
	hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	fragOff := int(rec[6])<<16 | int(rec[7])<<8 | int(rec[8])
	fragLen := int(rec[9])<<16 | int(rec[10])<<8 | int(rec[11])
	if fragOff != 0 || fragLen != hsLen {
		return nil, 0, false // fragmented first flight — out of scope
	}
	hb := rec[dtlsHsHdr:]
	if hsLen > len(hb) {
		return nil, 0, false
	}
	return hb[:hsLen], version, true
}

// dtlsBodyToTLS converts a DTLS ClientHello body to the TLS ClientHello layout
// by removing the DTLS-only `cookie` vector that sits between session_id and
// cipher_suites. Returns the rewritten body and ok.
func dtlsBodyToTLS(b []byte) ([]byte, bool) {
	// legacy_version(2) + random(32) + session_id(1-len + ...).
	p := 2 + 32
	if p >= len(b) {
		return nil, false
	}
	sidLen := int(b[p])
	p++
	p += sidLen
	if p >= len(b) {
		return nil, false
	}
	// cookie(1-len + cookie) — the DTLS-only field to drop.
	cookieLen := int(b[p])
	cookieStart := p
	p++
	p += cookieLen
	if p > len(b) {
		return nil, false
	}
	// Splice out [cookieStart, p): keep everything before the cookie length
	// byte and everything after the cookie bytes.
	out := make([]byte, 0, len(b)-(p-cookieStart))
	out = append(out, b[:cookieStart]...)
	out = append(out, b[p:]...)
	return out, true
}

// buildHelloVerifyRequest assembles a DTLS record wrapping a
// HelloVerifyRequest handshake (server_version + a fixed cookie).
func buildHelloVerifyRequest(version uint16) []byte {
	cookie := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe}
	// HelloVerifyRequest body: server_version(2) + cookie_len(1) + cookie.
	hvrBody := make([]byte, 0, 3+len(cookie))
	hvrBody = append(hvrBody, byte(version>>8), byte(version))
	hvrBody = append(hvrBody, byte(len(cookie)))
	hvrBody = append(hvrBody, cookie...)

	// Handshake header (12 bytes), unfragmented.
	hs := make([]byte, dtlsHsHdr+len(hvrBody))
	hs[0] = dtlsHelloVR
	hs[1] = byte(len(hvrBody) >> 16)
	hs[2] = byte(len(hvrBody) >> 8)
	hs[3] = byte(len(hvrBody))
	// message_seq 0, fragment_offset 0, fragment_length == length.
	hs[9] = byte(len(hvrBody) >> 16)
	hs[10] = byte(len(hvrBody) >> 8)
	hs[11] = byte(len(hvrBody))
	copy(hs[dtlsHsHdr:], hvrBody)

	// Record header (13 bytes): type=handshake, epoch 0, seq 0.
	rec := make([]byte, dtlsRecHdr+len(hs))
	rec[0] = dtlsTypeHS
	rec[1] = byte(version >> 8)
	rec[2] = byte(version)
	binary.BigEndian.PutUint16(rec[11:13], uint16(len(hs)))
	copy(rec[dtlsRecHdr:], hs)
	return rec
}

func dtlsVersionName(v uint16) string {
	switch v {
	case 0xfeff:
		return "DTLS 1.0"
	case 0xfefd:
		return "DTLS 1.2"
	case 0xfefc:
		return "DTLS 1.3"
	default:
		return "DTLS"
	}
}
