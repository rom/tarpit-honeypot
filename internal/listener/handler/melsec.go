package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// melsec is a Mitsubishi MELSEC (MC protocol, 3E frame) TCP receiver
// (port 1025 / 5007 / 5006 / depending on model). 3E request frame:
//
//   subhdr(2)=0x5000  network(1)  PC(1)  module_io(2)  module_station(1)
//   data_len(2)  cpu_timer(2)  command(2)  subcommand(2)  ...
//
// Common scanner request: 0x0101 / 0x0000 (read CPU model). We reply
// with a synthesized "Q03UDV CPU" string so the scanner classifies us
// as a real Mitsubishi PLC.
type melsec struct{}

func (m *melsec) Name() string { return "melsec" }

func (m *melsec) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	hdr := make([]byte, 11)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	subhdr := binary.LittleEndian.Uint16(hdr[0:2])
	if subhdr != 0x5000 {
		res.Meta["non_3e_subhdr"] = subhdr
		return res, nil
	}
	dataLen := binary.LittleEndian.Uint16(hdr[7:9])
	if dataLen < 4 || dataLen > 1024 {
		res.Meta["bad_data_len"] = dataLen
		return res, nil
	}
	body := make([]byte, dataLen-2) // subtract the 2-byte cpu_timer already in hdr[9:11]
	if _, err := io.ReadFull(conn, body); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(hdr, body...)
	if len(body) >= 4 {
		cmd := binary.LittleEndian.Uint16(body[0:2])
		sub := binary.LittleEndian.Uint16(body[2:4])
		res.Meta["command"] = cmd
		res.Meta["subcommand"] = sub
	}

	// Build a 3E response: subhdr=0xD000, swap network/PC, data_len,
	// completion code 0x0000, then CPU model bytes.
	model := []byte("Q03UDVCPU")
	resp := make([]byte, 0, 11+2+len(model))
	resp = binary.LittleEndian.AppendUint16(resp, 0xD000) // response sub-header
	resp = append(resp, hdr[2:7]...)                      // network/PC/module bytes echoed
	// data length = 2 (completion code) + payload
	resp = binary.LittleEndian.AppendUint16(resp, uint16(2+len(model)))
	resp = binary.LittleEndian.AppendUint16(resp, 0x0000) // completion code = success
	resp = append(resp, model...)
	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "melsec response (Q03UDVCPU)"
	_ = cfg
	return res, nil
}
