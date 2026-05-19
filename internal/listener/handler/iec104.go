package handler

import (
	"context"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type iec104 struct{}

func (i *iec104) Name() string { return "iec104" }

// IEC 60870-5-104 (port 2404). Frames start with 0x68, then a length byte,
// then 4 control bytes. A scanner typically sends STARTDT_ACT
// (0x68 0x04 0x07 0x00 0x00 0x00) and waits for STARTDT_CON
// (0x68 0x04 0x0b 0x00 0x00 0x00). We read one frame and reply with
// STARTDT_CON regardless of what they sent — enough for fingerprinting.
func (i *iec104) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	if hdr[0] != 0x68 {
		res.Meta = map[string]any{"non_iec104_start": hdr[0]}
		return res, nil
	}
	length := int(hdr[1])
	if length < 4 || length > 253 {
		res.Meta = map[string]any{"bad_length": length}
		return res, nil
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	res.Payload = append(hdr, body...)

	// Identify the control type from the first control byte.
	ct := body[0]
	ctype := "I-format"
	switch {
	case ct&0x01 == 0:
		ctype = "I-format"
	case ct&0x03 == 0x01:
		ctype = "S-format"
	case ct&0x03 == 0x03:
		// U-format: bits 2..7 encode TESTFR/STOPDT/STARTDT, ACT/CON.
		switch ct & 0xFC {
		case 0x04:
			ctype = "STARTDT_ACT"
		case 0x08:
			ctype = "STARTDT_CON"
		case 0x10:
			ctype = "STOPDT_ACT"
		case 0x20:
			ctype = "STOPDT_CON"
		case 0x40:
			ctype = "TESTFR_ACT"
		case 0x80:
			ctype = "TESTFR_CON"
		default:
			ctype = "U-format"
		}
	}
	res.Meta = map[string]any{"control_type": ctype}

	// Reply with STARTDT_CON (control byte 0x0b).
	reply := []byte{0x68, 0x04, 0x0b, 0x00, 0x00, 0x00}
	if _, err := conn.Write(reply); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "iec104 STARTDT_CON"
	return res, nil
}
