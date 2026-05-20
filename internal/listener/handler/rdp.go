package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
)

type rdp struct{}

func (r *rdp) Name() string { return "rdp" }

// Microsoft RDP (port 3389). The handshake opens with X.224 / TPKT:
//
//	TPKT (4 bytes): version=3, reserved=0, length(big-endian)
//	X.224 Connection Request: length(1), code=0xE0, dst_ref(2), src_ref(2),
//	                          class(1), then optional Cookie/RDP_NEG_REQ
//
// Inside the variable part the client puts a "Cookie: mstshc=<user>\r\n"
// line and/or an RDP_NEG_REQ TLV announcing supported security protocols
// (PROTOCOL_SSL=0x01, PROTOCOL_HYBRID=0x02, etc.). We capture both and
// reply with an X.224 Connection Confirm announcing PROTOCOL_SSL only —
// which makes most scanners attempt TLS, at which point our flow ends
// (we can't speak full RDP).
func (r *rdp) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}

	tpkt := make([]byte, 4)
	if _, err := io.ReadFull(conn, tpkt); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	if tpkt[0] != 0x03 {
		res.Meta = map[string]any{"non_tpkt_version": tpkt[0]}
		return res, nil
	}
	total := binary.BigEndian.Uint16(tpkt[2:4])
	if total < 7 || total > 4096 {
		res.Meta = map[string]any{"bad_tpkt_length": total}
		return res, nil
	}
	body := make([]byte, int(total)-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	res.Payload = append(tpkt, body...)

	// CVE exploit-attempt recognition (BlueKeep's rogue "MS_T120"
	// channel name appears as ASCII in the MCS Connect PDU). Detection only.
	for _, rec := range cve.MatchPayload("rdp", string(res.Payload)) {
		res.CVEHits = appendUnique(res.CVEHits, rec.ID)
		flagAnomaly(&res, "cve:"+rec.ID)
	}

	if len(body) < 6 || body[1] != 0xE0 {
		res.Meta = map[string]any{"cotp_type": body[1]}
		return res, nil
	}
	dstRef := binary.BigEndian.Uint16(body[2:4])
	srcRef := binary.BigEndian.Uint16(body[4:6])
	res.Meta = map[string]any{
		"dst_ref": dstRef,
		"src_ref": srcRef,
	}
	// Variable part after class byte.
	if len(body) > 7 {
		variable := body[7:]
		if cookie := extractCookie(variable); cookie != "" {
			res.Meta["cookie"] = cookie
		}
		if negReq := findNegReq(variable); negReq != nil {
			res.Meta["rdp_neg_req"] = describeNegReq(negReq)
		}
	}

	// Build X.224 Connection Confirm with RDP_NEG_RSP selecting PROTOCOL_SSL.
	cc := []byte{
		0x0E, 0xD0, // length, type=CC
		0x00, 0x00, // dst ref echoes server-chosen
		byte(srcRef >> 8), byte(srcRef & 0xFF), // mirror src
		0x00, // class 0
		// RDP_NEG_RSP TLV: type=0x02, flags=0x00, length(2)=0x0008, selected_protocol(4)
		0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
	}
	tpktOut := []byte{0x03, 0x00, 0x00, byte(4 + len(cc))}
	if _, err := conn.Write(append(tpktOut, cc...)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "rdp X.224 CC + RDP_NEG_RSP(PROTOCOL_SSL)"
	return res, nil
}

func extractCookie(b []byte) string {
	// "Cookie: mstshash=<user>\r\n"
	const prefix = "Cookie: "
	for i := 0; i+len(prefix) <= len(b); i++ {
		if string(b[i:i+len(prefix)]) == prefix {
			end := i + len(prefix)
			for end < len(b) && b[end] != '\r' && b[end] != '\n' {
				end++
			}
			return string(b[i+len(prefix) : end])
		}
	}
	return ""
}

func findNegReq(b []byte) []byte {
	// RDP_NEG_REQ TLV begins with type=0x01.
	for i := 0; i+8 <= len(b); i++ {
		if b[i] == 0x01 && b[i+2] == 0x08 && b[i+3] == 0x00 {
			return b[i : i+8]
		}
	}
	return nil
}

func describeNegReq(t []byte) map[string]any {
	if len(t) < 8 {
		return nil
	}
	flags := t[1]
	proto := binary.LittleEndian.Uint32(t[4:8])
	out := map[string]any{
		"flags":              flags,
		"requested_protocol": proto,
	}
	names := []string{}
	if proto&0x01 != 0 {
		names = append(names, "SSL")
	}
	if proto&0x02 != 0 {
		names = append(names, "HYBRID")
	}
	if proto&0x04 != 0 {
		names = append(names, "RDSTLS")
	}
	if proto&0x08 != 0 {
		names = append(names, "HYBRID_EX")
	}
	if len(names) > 0 {
		out["requested_protocol_names"] = names
	}
	return out
}
