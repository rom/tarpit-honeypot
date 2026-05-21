package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// hartIP is a HART-IP responder on TCP/UDP 5094 — the IP gateway to HART
// process field instruments (transmitters, valve positioners). The HART-IP
// message header is 8 bytes: version, msgType, msgID, status, seqNum(2),
// byteCount(2). We answer a session-initiate request and a token-passing
// PDU with a valid response header so a scanner records a live HART-IP
// gateway, capturing the message type. Fingerprint-grade, no field I/O.
type hartIP struct{}

func (h *hartIP) Name() string { return "hartip" }

func (h *hartIP) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	hdr := make([]byte, 8)
	n, _ := conn.Read(hdr)
	if n < 5 {
		res.Meta["read_err"] = "short header"
		return res, nil
	}
	res.Payload = append([]byte(nil), hdr[:n]...)
	version := hdr[0]
	msgType := hdr[1]
	msgID := hdr[2]
	res.Meta["hartip_version"] = int(version)
	res.Meta["hartip_msg_type"] = int(msgType)
	res.Meta["hartip_msg_id"] = hartMsgIDName(msgID)
	flagAnomaly(&res, "ics-hartip-probe")

	// Drain any declared body (bounded) so the framing stays aligned.
	if n >= 8 {
		bc := int(binary.BigEndian.Uint16(hdr[6:8]))
		if bc > 8 && bc <= 512 {
			body := make([]byte, bc-8)
			_, _ = conn.Read(body)
			res.Payload = append(res.Payload, body...)
		}
	}

	// Response header: version 1, msgType 1 (response), echo msgID, status 0.
	resp := make([]byte, 8)
	resp[0] = 1
	resp[1] = 1
	resp[2] = msgID
	resp[3] = 0
	if n >= 6 {
		copy(resp[4:6], hdr[4:6]) // echo sequence number
	}
	binary.BigEndian.PutUint16(resp[6:8], 8) // byteCount = header only
	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "hart-ip response"
	return res, nil
}

func hartMsgIDName(id byte) string {
	switch id {
	case 0:
		return "session-initiate"
	case 1:
		return "session-close"
	case 2:
		return "keep-alive"
	case 3:
		return "token-passing-pdu"
	}
	return "unknown"
}
