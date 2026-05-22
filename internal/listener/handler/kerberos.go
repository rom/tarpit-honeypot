package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type kerberos struct{}

func (k *kerberos) Name() string { return "kerberos" }

// Kerberos KDC (port 88 TCP). Wire format is a 4-byte big-endian length
// followed by a DER-encoded ASN.1 message. The first message a client
// sends is almost always an AS-REQ (0x6A in DER-tagged form via
// [APPLICATION 10]).
//
// We capture the principal name + service name + encryption types
// claimed, and reply with a generic KRB-ERROR (KDC_ERR_PREAUTH_REQUIRED
// = 25) which triggers a pre-auth round that we don't continue. That's
// enough to be classified as a KDC and to log the brute-force username.
func (k *kerberos) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	msgLen := binary.BigEndian.Uint32(lenBuf)
	if msgLen < 4 || msgLen > 65535 {
		res.Meta = map[string]any{"bad_length": msgLen}
		return res, nil
	}
	body := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	res.Payload = append(lenBuf, body...)

	if len(body) < 1 {
		return res, nil
	}
	tag := body[0]
	res.Meta = map[string]any{"asn1_tag": tag}
	switch tag {
	case 0x6A:
		res.Meta["message_type"] = "AS-REQ"
	case 0x6C:
		res.Meta["message_type"] = "TGS-REQ"
		// A TGS-REQ asks for a service ticket; on a honeypot KDC no
		// legitimate client does this — it's the Kerberoasting primitive
		// (request service tickets to crack offline).
		flagAnomaly(&res, "kerberos-tgs-request")
	default:
		res.Meta["message_type"] = "unknown"
	}
	// RC4-HMAC (etype 23 = 0x17) in the requested etype list is the
	// offline-crack downgrade Kerberoasting / AS-REP roasting rely on
	// (modern Windows defaults to AES 17/18). DER INTEGER 23 = 02 01 17.
	if bytes.Contains(body, []byte{0x02, 0x01, 0x17}) {
		res.Meta["rc4_requested"] = true
		flagAnomaly(&res, "kerberos-rc4-requested")
	}

	// Reply with a KRB-ERROR(KDC_ERR_PREAUTH_REQUIRED). Minimal:
	// the client only needs the error-code byte to know to retry.
	krbErr := buildKRBError(25)
	out := append(make([]byte, 4), krbErr...)
	binary.BigEndian.PutUint32(out, uint32(len(krbErr)))
	if _, err := conn.Write(out); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "kerberos KRB-ERROR (preauth required)"
	return res, nil
}

// buildKRBError is intentionally minimal — most scanners just check the
// outer tag and outer error code field. We send a [APPLICATION 30] (0x7E)
// wrapping a SEQUENCE with a small error-code INTEGER.
func buildKRBError(code int) []byte {
	// Inner: SEQUENCE { [0] pvno INTEGER, [1] msg-type INTEGER, [4] error-code INTEGER }
	inner := []byte{
		0xA0, 0x03, 0x02, 0x01, 0x05, // [0] pvno = 5
		0xA1, 0x03, 0x02, 0x01, 0x1E, // [1] msg-type = 30 (KRB-ERROR)
		0xA6, 0x03, 0x02, 0x01, byte(code), // [6] error-code
	}
	seq := append([]byte{0x30, byte(len(inner))}, inner...)
	wrapped := append([]byte{0x7E, byte(len(seq))}, seq...)
	return wrapped
}
