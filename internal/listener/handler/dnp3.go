package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// dnp3 is a minimal DNP3 (IEEE 1815) outstation responder on TCP 20000.
// DNP3 data-link frame:
//
//	start(2)=0x05 0x64 | len(1) | ctrl(1) | dest(2 LE) | src(2 LE) | crc(2)
//
// The control byte's low nibble is the function; with PRM=1 (master ->
// outstation) function 9 = REQUEST_LINK_STATUS, 0 = RESET_LINK_STATES,
// 2 = TEST_LINK. A real outstation answers a link-status request with a
// LINK_STATUS frame (PRM=0, function 11). We capture the addresses +
// function and reply with a believable LINK_STATUS so a scanner records
// a live DNP3 outstation.
type dnp3 struct{}

func (d *dnp3) Name() string { return "dnp3" }

func (d *dnp3) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	hdr := make([]byte, 10) // start(2)+len(1)+ctrl(1)+dest(2)+src(2)+crc(2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append([]byte(nil), hdr...)
	if hdr[0] != 0x05 || hdr[1] != 0x64 {
		res.Meta["non_dnp3"] = true
		return res, nil
	}
	ctrl := hdr[3]
	dest := binary.LittleEndian.Uint16(hdr[4:6])
	src := binary.LittleEndian.Uint16(hdr[6:8])
	fn := ctrl & 0x0F
	res.Meta["dnp3_dest"] = dest
	res.Meta["dnp3_src"] = src
	res.Meta["dnp3_function"] = dnp3FuncName(ctrl&0x40 != 0, fn)

	// Build a LINK_STATUS reply (PRM=0, DIR=1, function 11), swapping
	// src/dest so the master's address becomes our destination.
	frame := []byte{0x05, 0x64, 0x05, 0x8B}
	frame = binary.LittleEndian.AppendUint16(frame, src)  // dest = original src
	frame = binary.LittleEndian.AppendUint16(frame, dest) // src  = original dest
	crc := dnp3CRC(frame)
	frame = binary.LittleEndian.AppendUint16(frame, crc)
	if _, err := conn.Write(frame); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "dnp3 link-status"
	return res, nil
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
