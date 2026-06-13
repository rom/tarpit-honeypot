package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// dnp3 is a DNP3 (IEEE 1815) outstation responder on TCP 20000.
//
// DNP3 data-link frame:
//
//	start(2)=0x05 0x64 | len(1) | ctrl(1) | dest(2 LE) | src(2 LE) | crc(2)
//	[ user-data blocks: up to 16 bytes + crc(2), repeated ]
//
// The control byte's low nibble is the link function; with PRM=1 (master ->
// outstation) function 9 = REQUEST_LINK_STATUS, 0 = RESET_LINK_STATES,
// 2 = TEST_LINK, 3 = CONFIRMED_USER_DATA, 4 = UNCONFIRMED_USER_DATA. The
// last two carry the transport + application layer, where the real intent
// lives: READ (recon), WRITE / SELECT / OPERATE (control manipulation) and
// COLD/WARM_RESTART (rebooting the outstation). We de-block the user data,
// name the application function, flag the dangerous ones, and answer with a
// believable link-layer reply so a scanner records a live DNP3 outstation.
type dnp3 struct{}

func (d *dnp3) Name() string { return "dnp3" }

func (d *dnp3) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}

	// One overlay shared across the connection's frames, so an OPERATE followed
	// by a READ of the output-status group on the same TCP session reads back
	// the actuation (the master's confirm-it-landed check).
	mem := newDNP3Mem()
	const maxFrames = 16

	for f := 0; f < maxFrames; f++ {
		withTimeout(conn, cfg.ReadTimeout) // re-arm the idle window per frame
		hdr := make([]byte, 10)            // start(2)+len(1)+ctrl(1)+dest(2)+src(2)+crc(2)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			if f == 0 {
				res.Meta["read_err"] = err.Error()
			}
			break
		}
		res.Payload = append(res.Payload, hdr...)
		if hdr[0] != 0x05 || hdr[1] != 0x64 {
			res.Meta["non_dnp3"] = true
			break
		}
		length := hdr[2]
		ctrl := hdr[3]
		dest := binary.LittleEndian.Uint16(hdr[4:6])
		src := binary.LittleEndian.Uint16(hdr[6:8])
		prm := ctrl&0x40 != 0
		fn := ctrl & 0x0F
		res.Meta["dnp3_dest"] = dest
		res.Meta["dnp3_src"] = src
		res.Meta["dnp3_function"] = dnp3FuncName(prm, fn)
		setIfEmpty(res.Meta, "intent", "DNP3 link-layer probe — confirming a live outstation")

		// CONFIRMED_USER_DATA / UNCONFIRMED_USER_DATA carry the application layer.
		// When the application function warrants a real response (READ / control /
		// WRITE), answer at the application layer: link-ACK a confirmed request
		// first, then send the application response.
		if (fn == 3 || fn == 4) && length > 5 {
			if app := d.parseAppLayer(conn, &res, int(length)-5, mem); app != nil {
				if fn == 3 {
					ack := []byte{0x05, 0x64, 0x05, 0x80}
					ack = binary.LittleEndian.AppendUint16(ack, src)
					ack = binary.LittleEndian.AppendUint16(ack, dest)
					ack = binary.LittleEndian.AppendUint16(ack, dnp3CRC(ack))
					_, _ = conn.Write(ack)
				}
				if _, err := conn.Write(dnp3WrapApp(src, dest, app)); err != nil {
					res.Meta["write_err"] = err.Error()
					break
				}
				res.BannerSent = "dnp3 application response"
				continue
			}
		}

		// Otherwise a link-layer reply, swapping src/dest. A user-data frame gets
		// an ACK (function 0); everything else gets a LINK_STATUS (function 11) so
		// a scanner's REQUEST_LINK_STATUS is answered like a real outstation.
		replyFn := byte(0x0B) // LINK_STATUS
		if fn == 3 {
			replyFn = 0x00 // ACK a confirmed user-data frame
		}
		frame := []byte{0x05, 0x64, 0x05, 0x80 | replyFn}
		frame = binary.LittleEndian.AppendUint16(frame, src)  // dest = original src
		frame = binary.LittleEndian.AppendUint16(frame, dest) // src  = original dest
		frame = binary.LittleEndian.AppendUint16(frame, dnp3CRC(frame))
		if _, err := conn.Write(frame); err != nil {
			res.Meta["write_err"] = err.Error()
			break
		}
		res.BannerSent = "dnp3 link reply"
	}
	return res, nil
}

// parseAppLayer reads the user-data blocks, strips per-block CRCs, parses the
// transport + application headers to name and classify the function, and
// returns the application-response payload to send (or nil to fall back to a
// link-layer reply).
func (d *dnp3) parseAppLayer(conn net.Conn, res *Result, userLen int, mem *dnp3Mem) []byte {
	// Transmitted size = userLen data bytes + 2-byte CRC per (<=16-byte) block.
	blocks := (userLen + 15) / 16
	transmitted := userLen + 2*blocks
	if transmitted <= 0 || transmitted > 512 {
		return nil
	}
	raw := make([]byte, transmitted)
	if _, err := io.ReadFull(conn, raw); err != nil {
		res.Meta["read_err"] = err.Error()
		return nil
	}
	res.Payload = append(res.Payload, raw...)

	// De-block: take up to 16 data bytes, skip the 2-byte CRC, repeat — bounded
	// by the declared user-data length so trailing CRC bytes never leak in.
	var data []byte
	remaining := userLen
	for off := 0; off < len(raw) && remaining > 0; off += 18 {
		take := 16
		if take > remaining {
			take = remaining
		}
		if off+take > len(raw) {
			take = len(raw) - off
		}
		data = append(data, raw[off:off+take]...)
		remaining -= take
	}
	// data = transport(1) + app_control(1) + function_code(1) + objects.
	if len(data) < 3 {
		return nil
	}
	seq := data[1] & 0x0F
	appFn := data[2]
	objs := data[3:]
	res.Meta["dnp3_app_function"] = dnp3AppFuncName(appFn)
	switch appFn {
	case 1: // READ — sampling the outstation's points (recon/collection).
		flagAnomaly(res, "ics-process-data-access")
		res.Meta["intent"] = "DNP3 READ — polling outstation points / process data"
		return dnp3ReadResponse(objs, mem, seq)
	case 2: // WRITE — changing outstation values.
		flagAnomaly(res, "ics-plc-write")
		res.Meta["intent"] = "DNP3 WRITE — modifying outstation values (control manipulation)"
		return dnp3NullResponse(seq)
	case 3, 4, 5, 6: // SELECT / OPERATE / DIRECT_OPERATE(_NR) — actuating outputs.
		flagAnomaly(res, "ics-dnp3-control")
		res.Meta["intent"] = "DNP3 " + dnp3AppFuncName(appFn) + " — actuating control points (breakers/setpoints)"
		// SELECT (3) arms but does not actuate; OPERATE / DIRECT_OPERATE apply.
		return dnp3ControlResponse(objs, mem, seq, appFn != 3)
	case 13, 14: // COLD_RESTART / WARM_RESTART — rebooting the outstation.
		flagAnomaly(res, "ics-device-restart")
		res.Meta["intent"] = "DNP3 " + dnp3AppFuncName(appFn) + " — restarting the outstation (denial of control)"
	case 18: // STOP_APPL — halt the application.
		flagAnomaly(res, "ics-device-restart")
		res.Meta["intent"] = "DNP3 STOP_APPL — stopping the outstation application"
	case 20, 21: // ENABLE/DISABLE_UNSOLICITED — silence event reporting.
		flagAnomaly(res, "ics-dnp3-control")
		res.Meta["intent"] = "DNP3 " + dnp3AppFuncName(appFn) + " — toggling unsolicited reporting"
	}
	return nil // restart / stop / unsolicited: keep the link-layer reply
}

func dnp3FuncName(prm bool, fn byte) string {
	if prm {
		switch fn {
		case 0:
			return "RESET_LINK_STATES"
		case 2:
			return "TEST_LINK"
		case 3:
			return "CONFIRMED_USER_DATA"
		case 4:
			return "UNCONFIRMED_USER_DATA"
		case 9:
			return "REQUEST_LINK_STATUS"
		}
	}
	return "fn" + itoa(int(fn))
}

func dnp3AppFuncName(fn byte) string {
	switch fn {
	case 0:
		return "CONFIRM"
	case 1:
		return "READ"
	case 2:
		return "WRITE"
	case 3:
		return "SELECT"
	case 4:
		return "OPERATE"
	case 5:
		return "DIRECT_OPERATE"
	case 6:
		return "DIRECT_OPERATE_NR"
	case 7:
		return "IMMED_FREEZE"
	case 13:
		return "COLD_RESTART"
	case 14:
		return "WARM_RESTART"
	case 18:
		return "STOP_APPL"
	case 20:
		return "ENABLE_UNSOLICITED"
	case 21:
		return "DISABLE_UNSOLICITED"
	case 23:
		return "DELAY_MEASURE"
	}
	return "appfn" + itoa(int(fn))
}

// dnp3CRC computes the DNP3 data-link CRC (CRC-16/DNP, reflected poly
// 0xA6BC, final XOR 0xFFFF) over the frame header bytes.
func dnp3CRC(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA6BC
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}
