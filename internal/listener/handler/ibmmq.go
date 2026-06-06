package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
)

// ibmmq emulates the IBM MQ (WebSphere MQ) channel listener on TCP 1414. An MQ
// client opens with a Transmission Segment whose header ("TSH ") carries a
// control opcode (segment type); the first flow ("Initial Data", opcode 0x01)
// negotiates the FAP level and names the SVRCONN channel + queue manager the
// client wants, and a later "Security" flow (opcode 0x06) carries the MQCSP
// user/password. We capture that recon (channel / queue-manager names are
// high-value) and the connect attempt, then drop — capture only, we never
// complete the MQ handshake or grant a channel.
//
// TSH header (big-endian): StructID(4)="TSH " · MQSegmLen(4) · ByteOrder(1) ·
// SegmType/opcode(1) · CtlFlag1(1) · CtlFlag2(1) · …
type ibmmq struct{}

func (m *ibmmq) Name() string { return "ibmmq" }

// mqOpcode names the TSH control opcode (FAP segment type).
func mqOpcode(b byte) string {
	switch b {
	case 0x01:
		return "INITIAL_DATA"
	case 0x02:
		return "RESYNC_DATA"
	case 0x03:
		return "RESET_DATA"
	case 0x04:
		return "MESSAGE_DATA"
	case 0x05:
		return "STATUS_DATA"
	case 0x06:
		return "SECURITY_DATA"
	case 0x07:
		return "PING_DATA"
	case 0x08:
		return "REQUEST_MSGS"
	case 0x0D:
		return "MQCONN"
	case 0x0E:
		return "MQDISC"
	}
	return "opcode"
}

func (m *ibmmq) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	buf := make([]byte, 8192)
	n, _ := conn.Read(buf)
	if n <= 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}
	data := buf[:n]
	res.Payload = append([]byte(nil), data...)

	if n < 12 || string(data[0:4]) != "TSH " {
		res.Meta["non_mq"] = true
		return res, nil
	}
	flagAnomaly(&res, "ibmmq-connect")
	res.Meta["mq_struct"] = "TSH"
	res.Meta["mq_segment_len"] = binary.BigEndian.Uint32(data[4:8])
	op := mqOpcode(data[9])
	res.Meta["mq_opcode"] = op

	// Printable runs carry the channel name, queue-manager, and application name.
	strs := mqPrintable(data, 3)
	if len(strs) > 0 {
		res.Meta["mq_strings"] = strs
	}
	if ch := mqChannelName(strs); ch != "" {
		res.Meta["mq_channel"] = ch
	}

	switch data[9] {
	case 0x06:
		flagAnomaly(&res, "ibmmq-security-flow")
		res.Meta["intent"] = "IBM MQ security flow — MQCSP credential exchange (channel auth probe)"
	case 0x01, 0x0D:
		res.Meta["intent"] = "IBM MQ channel negotiation — SVRCONN/queue-manager reconnaissance"
	default:
		res.Meta["intent"] = "IBM MQ " + op + " segment"
	}

	for _, rec := range cve.MatchPayload("ibmmq", string(data)) {
		res.CVEHits = appendUnique(res.CVEHits, rec.ID)
		flagAnomaly(&res, "cve:"+rec.ID)
	}
	return res, nil
}

// mqPrintable returns printable-ASCII runs of >= min bytes from b.
func mqPrintable(b []byte, min int) []string {
	var out []string
	start := -1
	for i := 0; i <= len(b); i++ {
		printable := i < len(b) && b[i] >= 0x20 && b[i] < 0x7f
		if printable {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= min {
			out = append(out, string(b[start:i]))
		}
		start = -1
	}
	return out
}

// mqChannelName picks the MQ channel name out of the captured strings — MQ
// channel names are uppercase, dot-separated (e.g. SYSTEM.DEF.SVRCONN,
// DEV.APP.SVRCONN).
func mqChannelName(strs []string) string {
	best := ""
	for _, s := range strs {
		if !looksLikeMQChannel(s) {
			continue
		}
		if len(s) > len(best) {
			best = s
		}
	}
	return best
}

func looksLikeMQChannel(s string) bool {
	if len(s) < 4 || len(s) > 20 {
		return false
	}
	dot := false
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '%', r == '/':
		case r == '.':
			dot = true
		default:
			return false
		}
	}
	return dot
}
