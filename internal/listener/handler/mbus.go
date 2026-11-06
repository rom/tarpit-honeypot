package handler

import (
	"bufio"
	"context"
	"encoding/hex"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// mbusH emulates a Meter-Bus (M-Bus, EN 13757-2/3) device reached over a TCP
// gateway (commonly port 10001). M-Bus is the dominant European fieldbus for
// utility sub-metering (heat / water / gas / electricity) and is increasingly
// exposed to IP through serial-to-Ethernet gateways. We recognize the M-Bus
// link-layer framing, answer SND_NKE with an ACK and REQ_UD2 with a believable
// RSP_UD meter record, and flag the read/write/init as ATT&CK-for-ICS.
type mbusH struct{}

func (mbusH) Name() string { return "mbus" }

func (mbusH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{"service": "mbus"}}
	br := bufio.NewReader(conn)

	first, err := br.ReadByte()
	if err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}

	var c, a byte
	switch first {
	case 0x10: // short frame: 10 C A CS 16
		buf := make([]byte, 4)
		if _, err := readFull(br, buf); err != nil {
			res.Meta["read_err"] = err.Error()
			return res, nil
		}
		c, a = buf[0], buf[1]
		res.Payload = append([]byte{0x10}, buf...)
	case 0x68: // long/control frame: 68 L L 68 C A CI ... CS 16
		hdr := make([]byte, 3) // L L 68
		if _, err := readFull(br, hdr); err != nil {
			res.Meta["read_err"] = err.Error()
			return res, nil
		}
		l := int(hdr[0])
		body := make([]byte, l+2) // body (l bytes) + CS + 16
		if _, err := readFull(br, body); err != nil {
			res.Meta["read_err"] = err.Error()
			return res, nil
		}
		if l >= 2 {
			c, a = body[0], body[1]
		}
		res.Payload = append([]byte{0x68}, append(hdr, body...)...)
		if l >= 3 {
			res.Meta["mbus_ci"] = hexByte(body[2])
		}
	default:
		res.Meta["non_mbus_first_byte"] = hexByte(first)
		return res, nil
	}

	res.Meta["mbus_control"] = hexByte(c)
	res.Meta["mbus_address"] = int(a)
	flagAnomaly(&res, "mbus-request")

	// Classify by the control field with the FCB (0x20) masked off.
	switch c &^ 0x20 {
	case 0x40: // SND_NKE — initialize / normalize slave
		flagAnomaly(&res, "ics-field-device-probe")
		res.Meta["mbus_function"] = "SND_NKE"
		res.Meta["intent"] = "M-Bus SND_NKE — meter link initialization (field-device recon)"
		_, _ = conn.Write([]byte{0xE5}) // single-char ACK
		res.BannerSent = "mbus ACK"
	case 0x5B, 0x5A: // REQ_UD2 / REQ_UD1 — request meter data
		flagAnomaly(&res, "ics-process-data-access")
		res.Meta["mbus_function"] = "REQ_UD2"
		res.Meta["intent"] = "M-Bus REQ_UD2 — meter reading / process-data collection (T0802)"
		frame := mbusRSPUD(a)
		_, _ = conn.Write(frame)
		res.Meta["mbus_response"] = hex.EncodeToString(frame)
		res.BannerSent = "mbus RSP_UD"
	case 0x53: // SND_UD — send user data (configuration / set write)
		flagAnomaly(&res, "ics-plc-write")
		res.Meta["mbus_function"] = "SND_UD"
		res.Meta["intent"] = "M-Bus SND_UD — configuration/set write to the meter (T0836)"
		_, _ = conn.Write([]byte{0xE5})
		res.BannerSent = "mbus ACK"
	default:
		res.Meta["mbus_function"] = "unknown"
		_, _ = conn.Write([]byte{0xE5})
		res.BannerSent = "mbus ACK"
	}
	return res, nil
}

// mbusRSPUD builds a valid RSP_UD long frame with a fabricated fixed data
// header + one volume record, so an M-Bus reader (libmbus) sees a real meter.
func mbusRSPUD(addr byte) []byte {
	// body = C A CI + fixed-data-header(12) + one data record(6)
	body := []byte{
		0x08, addr, 0x72, // C=RSP_UD, A echoed, CI=0x72 (variable data, long header)
		0x78, 0x56, 0x34, 0x12, // ID (BCD, little-endian) = 12345678
		0xAE, 0x4D, // manufacturer (2 bytes)
		0x01,       // version
		0x04,       // medium = heat
		0x2A,       // access number
		0x00,       // status
		0x00, 0x00, // signature
		0x04, 0x13, 0xE8, 0x03, 0x00, 0x00, // DIF=32-bit int, VIF=volume(1e-3 m^3), value=1000
	}
	var cs byte
	for _, b := range body {
		cs += b
	}
	frame := []byte{0x68, byte(len(body)), byte(len(body)), 0x68}
	frame = append(frame, body...)
	frame = append(frame, cs, 0x16)
	return frame
}

func hexByte(b byte) string { return "0x" + hex.EncodeToString([]byte{b}) }
