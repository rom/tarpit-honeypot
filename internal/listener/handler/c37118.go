package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// c37118 is an IEEE C37.118.2 synchrophasor responder on TCP 4712 — the
// protocol PMUs (phasor measurement units) and PDCs (phasor data
// concentrators) speak across the wide-area measurement systems that watch
// the transmission grid. A PDC client opens by sending a COMMAND frame
// asking for the configuration (CFG-2) and then "turn on transmission";
// from then on the device streams DATA frames at 30-60 Hz.
//
// C37.118.2 frame (big-endian):
//
//	SYNC(2)      0xAA + (frametype<<4 | version)
//	FRAMESIZE(2) total bytes incl. CHK
//	IDCODE(2)    PMU/PDC stream id
//	SOC(4)       second-of-century (UNIX time)
//	FRACSEC(4)   fraction-of-second + time quality
//	... type-specific body ...
//	CHK(2)       CRC-CCITT
//
// frametype: 0=DATA 1=HEADER 2=CFG-1 3=CFG-2 4=COMMAND 5=CFG-3.
// The only client-originated frame is COMMAND, whose 2-byte CMD selects:
// 1=turn off data, 2=turn on data, 3=send HEADER, 4=send CFG-1, 5=send
// CFG-2, 6=send CFG-3, 8=extended frame. "Turn off data" against a live
// PMU blinds the wide-area monitoring of that bus — a control action — so
// we capture + classify the command and answer with a believable CFG-2 /
// HEADER frame. Fingerprint-grade: no real measurement stream.
type c37118 struct{}

func (c *c37118) Name() string { return "c37118" }

const c37118Sync = 0xAA

func (c *c37118) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	// Common 14-byte header up to FRACSEC; FRAMESIZE then tells us the rest.
	hdr := make([]byte, 14)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append([]byte(nil), hdr...)
	if hdr[0] != c37118Sync {
		res.Meta["non_c37118"] = true
		return res, nil
	}
	ftype := (hdr[1] >> 4) & 0x07
	version := hdr[1] & 0x0F
	frameSize := binary.BigEndian.Uint16(hdr[2:4])
	idcode := binary.BigEndian.Uint16(hdr[4:6])
	res.Meta["c37118_version"] = version
	res.Meta["c37118_frame_type"] = c37118FrameName(ftype)
	res.Meta["c37118_idcode"] = idcode
	flagAnomaly(&res, "ics-field-device-probe")
	setIfEmpty(res.Meta, "intent", "C37.118 synchrophasor probe — PMU/PDC stream enumeration")

	// Drain the rest of the frame (body + CHK) using FRAMESIZE.
	if frameSize > 14 && frameSize < 4096 {
		rest := make([]byte, int(frameSize)-14)
		if _, err := io.ReadFull(conn, rest); err == nil {
			res.Payload = append(res.Payload, rest...)
			if ftype == 4 && len(rest) >= 2 { // COMMAND: CMD is the first body word
				c.handleCommand(conn, &res, idcode, binary.BigEndian.Uint16(rest[0:2]))
				return res, nil
			}
		}
	}

	// Non-command frame (or truncated): answer a config request optimistically
	// with CFG-2 so a scanner records a live synchrophasor source.
	c.writeFrame(conn, &res, 3, idcode, c37118CFG2Body())
	res.BannerSent = "c37118 cfg-2"
	return res, nil
}

func (c *c37118) handleCommand(conn net.Conn, res *Result, idcode, cmd uint16) {
	res.Meta["c37118_command"] = c37118CmdName(cmd)
	switch cmd {
	case 1: // turn off data transmission — blinds wide-area monitoring.
		flagAnomaly(res, "ics-pmu-command")
		res.Meta["intent"] = "C37.118 turn-off-transmission — halting PMU data stream (denial of monitoring)"
		c.writeFrame(conn, res, 1, idcode, []byte("STREAM OFF\r\n"))
	case 2: // turn on data transmission.
		flagAnomaly(res, "ics-pmu-command")
		res.Meta["intent"] = "C37.118 turn-on-transmission — starting PMU data stream"
		c.writeFrame(conn, res, 1, idcode, []byte("STREAM ON\r\n"))
	case 3: // send HEADER frame.
		c.writeFrame(conn, res, 1, idcode, []byte("Tarpit PMU / station BUS-1 / IEEE C37.118-2011\r\n"))
	case 4, 5: // send CFG-1 / CFG-2.
		c.writeFrame(conn, res, 3, idcode, c37118CFG2Body())
	case 6: // send CFG-3.
		c.writeFrame(conn, res, 5, idcode, c37118CFG2Body())
	default:
		c.writeFrame(conn, res, 1, idcode, []byte("OK\r\n"))
	}
	res.BannerSent = "c37118 " + c37118CmdName(cmd) + " reply"
}

// writeFrame emits a C37.118 frame of the given type carrying body, with a
// freshly-computed FRAMESIZE and CRC-CCITT checksum.
func (c *c37118) writeFrame(conn net.Conn, res *Result, ftype byte, idcode uint16, body []byte) {
	frame := make([]byte, 14+len(body)+2)
	frame[0] = c37118Sync
	frame[1] = (ftype << 4) | 0x01 // version 1 (2005) / 2 bits unused
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	binary.BigEndian.PutUint16(frame[4:6], idcode)
	// SOC/FRACSEC left zero — a scanner reads the frame type + config, not time.
	copy(frame[14:], body)
	crc := crcCCITT(frame[:len(frame)-2])
	binary.BigEndian.PutUint16(frame[len(frame)-2:], crc)
	if _, err := conn.Write(frame); err != nil {
		res.Meta["write_err"] = err.Error()
	}
}

// c37118CFG2Body is a minimal believable CFG-2 body (1 PMU, station name,
// one phasor + one analog channel). Enough for a scanner to see a configured
// synchrophasor; not a spec-complete configuration block.
func c37118CFG2Body() []byte {
	b := make([]byte, 0, 64)
	b = binary.BigEndian.AppendUint32(b, 1000000)          // TIME_BASE
	b = binary.BigEndian.AppendUint16(b, 1)                // NUM_PMU = 1
	b = append(b, []byte("Tarpit PMU BUS-1     ")[:16]...) // STN (16 bytes)
	b = binary.BigEndian.AppendUint16(b, 7734)             // IDCODE
	b = binary.BigEndian.AppendUint16(b, 0x0004)           // FORMAT
	b = binary.BigEndian.AppendUint16(b, 1)                // PHNMR
	b = binary.BigEndian.AppendUint16(b, 1)                // ANNMR
	b = binary.BigEndian.AppendUint16(b, 0)                // DGNMR
	b = append(b, []byte("VA              ")...)           // CHNAM (16 bytes)
	b = binary.BigEndian.AppendUint16(b, 60)               // DATA_RATE (60 Hz)
	return b
}

func c37118FrameName(ft byte) string {
	switch ft {
	case 0:
		return "DATA"
	case 1:
		return "HEADER"
	case 2:
		return "CFG-1"
	case 3:
		return "CFG-2"
	case 4:
		return "COMMAND"
	case 5:
		return "CFG-3"
	}
	return "frame" + itoa(int(ft))
}

func c37118CmdName(cmd uint16) string {
	switch cmd {
	case 1:
		return "turn-off-transmission"
	case 2:
		return "turn-on-transmission"
	case 3:
		return "send-header"
	case 4:
		return "send-cfg-1"
	case 5:
		return "send-cfg-2"
	case 6:
		return "send-cfg-3"
	case 8:
		return "extended-frame"
	}
	return "cmd" + itoa(int(cmd))
}

// crcCCITT computes the CRC-CCITT (XModem: poly 0x1021, init 0xFFFF, no final
// XOR) used by C37.118.2 for the frame CHK word.
func crcCCITT(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
