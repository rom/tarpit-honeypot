package handler

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// dlmsH emulates a DLMS/COSEM smart meter (IEC 62056) reached over the TCP
// "wrapper" transport (default port 4059). A client opens an Application
// Association with an AARQ APDU (tag 0x60); we recognize the wrapper framing
// and the AARQ, answer with a believable AARE (tag 0x61), and flag the
// association as ICS field-device access. Complements the M-Bus handler for
// utility-metering coverage.
type dlmsH struct{}

func (dlmsH) Name() string { return "dlms" }

func (dlmsH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{"service": "dlms-cosem"}}
	br := bufio.NewReader(conn)

	// Wrapper header: version(2)=0x0001, src wPort(2), dst wPort(2), length(2).
	hdr := make([]byte, 8)
	if _, err := readFull(br, hdr); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append([]byte(nil), hdr...)
	if binary.BigEndian.Uint16(hdr[0:2]) != 0x0001 {
		res.Meta["non_dlms_wrapper"] = hex.EncodeToString(hdr[0:2])
		return res, nil
	}
	res.Meta["dlms_wrapper"] = true
	res.Meta["dlms_src"] = binary.BigEndian.Uint16(hdr[2:4])
	res.Meta["dlms_dst"] = binary.BigEndian.Uint16(hdr[4:6])
	n := int(binary.BigEndian.Uint16(hdr[6:8]))
	if n < 0 || n > 4096 {
		res.Meta["bad_length"] = n
		return res, nil
	}
	apdu := make([]byte, n)
	if _, err := readFull(br, apdu); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(res.Payload, apdu...)

	if len(apdu) > 0 && apdu[0] == 0x60 { // AARQ — association request
		flagAnomaly(&res, "ics-dlms-association")
		flagAnomaly(&res, "ics-field-device-probe")
		res.Meta["dlms_apdu"] = "AARQ"
		res.Meta["intent"] = "DLMS/COSEM association request (AARQ) — smart-meter field-device access"
		// Reply AARE (tag 0x61) accepting the association, in a wrapper frame.
		aare := []byte{0x61, 0x29, 0xa1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
			0xa2, 0x03, 0x02, 0x01, 0x00, 0xa3, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x00}
		out := make([]byte, 8)
		binary.BigEndian.PutUint16(out[0:2], 0x0001)
		binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(hdr[4:6])) // swap src/dst
		binary.BigEndian.PutUint16(out[4:6], binary.BigEndian.Uint16(hdr[2:4]))
		binary.BigEndian.PutUint16(out[6:8], uint16(len(aare)))
		_, _ = conn.Write(append(out, aare...))
		res.BannerSent = "dlms AARE"
	} else if len(apdu) > 0 {
		res.Meta["dlms_apdu_tag"] = hexByte(apdu[0])
	}
	return res, nil
}
