package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

type iec104 struct{}

func (i *iec104) Name() string { return "iec104" }

// IEC 60870-5-104 (port 2404). Frames are APCI = 0x68 + length + 4
// control bytes (CTR1..CTR4); I-format frames carry an ASDU body.
// Real scanners:
//
//   1. Send STARTDT_ACT (U-format 0x07 0x00 0x00 0x00) and wait for
//      STARTDT_CON (0x0b 0x00 0x00 0x00).
//   2. Optionally send TESTFR_ACT and wait for TESTFR_CON.
//   3. Send a General Interrogation request — I-format ASDU type
//      100 (C_IC_NA_1) with COT=6 (activation). A real RTU replies
//      with an ASDU 100 with COT=7 (activation confirmation),
//      streams a batch of M_ME_NB_1 / M_SP_NA_1 measurement /
//      single-point objects, then ASDU 100 with COT=10 (activation
//      termination).
//
// Our handler runs the connection as a loop until the peer closes
// (or `ReadTimeout` expires), captures every received frame's type
// and IOA(s), and replies with appropriate U-format confirmations
// + a believable General Interrogation result. The capture is what
// matters for SIEM enrichment; the believable IGI keeps the scanner
// classifying us as a real RTU long enough to log follow-up TTPs.
func (i *iec104) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	var frames []map[string]any
	maxFrames := 16
	var totalPayload []byte

	for f := 0; f < maxFrames; f++ {
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			if f == 0 {
				res.Meta["read_err"] = err.Error()
			}
			break
		}
		if hdr[0] != 0x68 {
			res.Meta["non_iec104_start"] = hdr[0]
			break
		}
		length := int(hdr[1])
		if length < 4 || length > 253 {
			res.Meta["bad_length"] = length
			break
		}
		body, ok := safe.AllocBytes(length)
		if !ok {
			res.Meta["alloc_err"] = length
			break
		}
		if _, err := io.ReadFull(conn, body); err != nil {
			res.Meta["read_err"] = err.Error()
			break
		}
		totalPayload = append(totalPayload, hdr...)
		totalPayload = append(totalPayload, body...)

		frame := classifyFrame(body)
		frames = append(frames, frame)

		// Reply per control type.
		ctype, _ := frame["control_type"].(string)
		switch ctype {
		case "STARTDT_ACT":
			_, _ = conn.Write([]byte{0x68, 0x04, 0x0b, 0x00, 0x00, 0x00})
		case "STOPDT_ACT":
			_, _ = conn.Write([]byte{0x68, 0x04, 0x23, 0x00, 0x00, 0x00})
		case "TESTFR_ACT":
			_, _ = conn.Write([]byte{0x68, 0x04, 0x83, 0x00, 0x00, 0x00})
		case "I-format":
			i.replyToIFrame(conn, body, frame)
		}
	}
	if len(frames) > 0 {
		res.Meta["frames"] = frames
	}
	res.Payload = totalPayload
	res.BannerSent = "iec104 multi-frame engagement"
	return res, nil
}

// classifyFrame inspects the 4 control bytes + optional ASDU body and
// returns a meta map with control_type and, for I-frames, asdu_type +
// cot + common_addr + ioa.
func classifyFrame(body []byte) map[string]any {
	if len(body) < 4 {
		return map[string]any{"control_type": "truncated"}
	}
	ct := body[0]
	out := map[string]any{}
	switch {
	case ct&0x01 == 0:
		out["control_type"] = "I-format"
		// I-format: send_seq (CTR1..2 with low bit 0), recv_seq (CTR3..4).
		out["send_seq"] = int(binary.LittleEndian.Uint16(body[0:2])>>1) & 0x7FFF
		out["recv_seq"] = int(binary.LittleEndian.Uint16(body[2:4])>>1) & 0x7FFF
		// ASDU body starts at byte 4: type_id(1) vsq(1) cot(2) common_addr(2) ...
		if len(body) >= 4+6 {
			out["asdu_type"] = body[4]
			out["asdu_type_name"] = asduTypeName(body[4])
			out["vsq"] = body[5]
			out["cot"] = int(binary.LittleEndian.Uint16(body[6:8])) & 0x3F
			out["cot_name"] = cotName(int(binary.LittleEndian.Uint16(body[6:8])) & 0x3F)
			out["common_addr"] = int(binary.LittleEndian.Uint16(body[8:10]))
			// First IOA (3 bytes LE) starts at byte 10.
			if len(body) >= 4+9 {
				ioa := uint32(body[10]) | uint32(body[11])<<8 | uint32(body[12])<<16
				out["ioa"] = ioa
			}
		}
	case ct&0x03 == 0x01:
		out["control_type"] = "S-format"
		out["recv_seq"] = int(binary.LittleEndian.Uint16(body[2:4])>>1) & 0x7FFF
	case ct&0x03 == 0x03:
		switch ct & 0xFC {
		case 0x04:
			out["control_type"] = "STARTDT_ACT"
		case 0x08:
			out["control_type"] = "STARTDT_CON"
		case 0x10:
			out["control_type"] = "STOPDT_ACT"
		case 0x20:
			out["control_type"] = "STOPDT_CON"
		case 0x40:
			out["control_type"] = "TESTFR_ACT"
		case 0x80:
			out["control_type"] = "TESTFR_CON"
		default:
			out["control_type"] = "U-format"
		}
	}
	return out
}

// replyToIFrame implements the scanner-facing portion of IEC 60870-5-101
// type identifiers we expect to see during reconnaissance.
func (i *iec104) replyToIFrame(conn net.Conn, body []byte, meta map[string]any) {
	asduType, _ := meta["asdu_type"].(byte)
	cot, _ := meta["cot"].(int)

	switch asduType {
	case 100: // C_IC_NA_1 — General Interrogation
		// COT=6 (activation) -> reply with COT=7 (act-con) immediately,
		// stream three M_ME_NB_1 (type 11) measurements with COT=20
		// (interrogated by general interrogation), then COT=10 (act-term).
		if cot == 6 {
			i.writeIFrame(conn, 100, 7, []byte{0, 0, 0x14}) // act-con
			i.streamFakeMeasurements(conn)
			i.writeIFrame(conn, 100, 10, []byte{0, 0, 0x14}) // act-term
		}
	case 102: // C_RD_NA_1 — Read command
		if cot == 5 { // request
			i.writeIFrame(conn, 102, 7, body[10:13]) // confirm
		}
	case 103: // C_CS_NA_1 — Clock sync
		if cot == 6 {
			i.writeIFrame(conn, 103, 7, body[10:]) // confirm with echoed time
		}
	case 45, 46: // C_SC_NA_1 / C_DC_NA_1 — Single / Double command
		if cot == 6 && len(body) >= 14 {
			// Reply act-con with the IOA echoed; a real RTU would also
			// either execute or reject.
			i.writeIFrame(conn, asduType, 7, body[10:14])
		}
	}
}

// streamFakeMeasurements emits three normalized-measurement frames
// (M_ME_NB_1, type 11) at IOAs 0x4001..0x4003 with believable
// scaled values. A scanner reading the interrogation result sees a
// populated process image.
func (i *iec104) streamFakeMeasurements(conn net.Conn) {
	pts := []struct {
		ioa  uint32
		val  int16
		qual byte
	}{
		{0x4001, 4711, 0x00},  // good quality, value 4711
		{0x4002, -120, 0x00},
		{0x4003, 32000, 0x40}, // bit 6 = blocked
	}
	for _, p := range pts {
		// VSQ for one object = 0x01 (SQ=0, count=1).
		// Object: IOA(3) + value(2 LE) + quality(1).
		obj := []byte{
			byte(p.ioa), byte(p.ioa >> 8), byte(p.ioa >> 16),
			byte(uint16(p.val)), byte(uint16(p.val) >> 8),
			p.qual,
		}
		i.writeIFrame(conn, 11, 20, obj)
	}
}

// writeIFrame builds and sends one I-format APCI with a single ASDU.
// Send/recv sequence numbers are stamped 0 — for the scanner-side
// observation that's fine; the protocol doesn't fail on out-of-order
// in a probe context.
func (i *iec104) writeIFrame(conn net.Conn, asduType byte, cot int, obj []byte) {
	asdu := []byte{
		asduType,
		0x01, // VSQ: 1 object, SQ=0
		byte(cot), 0x00,
		0x01, 0x00, // common-address = 1 (the typical RTU CA)
	}
	asdu = append(asdu, obj...)
	apdu := make([]byte, 0, 6+len(asdu))
	apdu = append(apdu, 0x68, byte(4+len(asdu))) // start + length
	apdu = append(apdu, 0x00, 0x00, 0x00, 0x00)  // CTR1..4 (I-format, seqs 0)
	apdu = append(apdu, asdu...)
	_, _ = conn.Write(apdu)
}

// asduTypeName maps IEC 60870-5-101 type identifiers to their canonical
// names. Only the types a recon scanner actually emits — a complete
// table is in §7.2.2 of the standard.
func asduTypeName(t byte) string {
	switch t {
	case 1:
		return "M_SP_NA_1" // single-point, no time
	case 3:
		return "M_DP_NA_1" // double-point
	case 9:
		return "M_ME_NA_1" // normalized measured
	case 11:
		return "M_ME_NB_1" // scaled measured
	case 13:
		return "M_ME_NC_1" // short float measured
	case 30:
		return "M_SP_TB_1" // single-point with CP56Time2a
	case 36:
		return "M_ME_TF_1" // short float w/ time
	case 45:
		return "C_SC_NA_1" // single command
	case 46:
		return "C_DC_NA_1" // double command
	case 100:
		return "C_IC_NA_1" // general interrogation
	case 101:
		return "C_CI_NA_1" // counter interrogation
	case 102:
		return "C_RD_NA_1" // read command
	case 103:
		return "C_CS_NA_1" // clock sync
	case 105:
		return "C_RP_NA_1" // reset process
	}
	return ""
}

// cotName returns the Cause-of-Transmission decode. COT is a 6-bit
// field; the top 2 bits are P/N + T flags we ignore for the meta.
func cotName(c int) string {
	switch c {
	case 1:
		return "periodic"
	case 2:
		return "background-scan"
	case 3:
		return "spontaneous"
	case 4:
		return "initialized"
	case 5:
		return "request"
	case 6:
		return "activation"
	case 7:
		return "activation-confirmation"
	case 8:
		return "deactivation"
	case 9:
		return "deactivation-confirmation"
	case 10:
		return "activation-termination"
	case 20:
		return "interrogated-by-general-interrogation"
	case 45:
		return "unknown-type"
	case 46:
		return "unknown-cot"
	case 47:
		return "unknown-common-address"
	case 48:
		return "unknown-ioa"
	}
	return ""
}
