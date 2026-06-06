package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// focas is a FANUC FOCAS (FANUC Open CNC API Specifications) responder on
// TCP 8193 — the Ethernet protocol of FANUC CNC controllers (machine tools,
// robots) and the port Shodan/Censys fingerprint as "fanuc". A FOCAS client
// opens with a fixed binary header; the library (Fwlib) exchanges request /
// response packets to read machine state (cnc_rdcncid, cnc_sysinfo,
// cnc_statinfo) and, with the right calls, alter programs or feed/spindle
// overrides.
//
// The wire framing isn't publicly specified in full, but the opening
// exchange is recognizable: a short fixed-length request to which a live
// controller answers with a fixed-length reply carrying its model/series.
// We capture the request and answer with a believable FOCAS reply so a
// scanner records a live FANUC CNC, flag the probe, and classify any
// recognizable request opcode. Fingerprint-grade — no CNC state machine.
type focas struct{}

func (f *focas) Name() string { return "focas" }

func (f *focas) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n <= 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}
	req := buf[:n]
	res.Payload = append([]byte(nil), req...)
	res.Meta["focas_request_len"] = n
	if n >= 2 {
		res.Meta["focas_opcode"] = fmtByteU16(binary.BigEndian.Uint16(req[0:2]))
	}
	flagAnomaly(&res, "ics-device-enumeration")
	setIfEmpty(res.Meta, "intent", "FANUC FOCAS probe — CNC controller enumeration / fingerprint")

	// FOCAS reply: a fixed 16-byte header (echoing a request/response marker)
	// followed by an ASCII model/series string a scanner greps for. Real
	// controllers embed cnc_sysinfo fields (series, version, axes); this is
	// enough to look like a live FANUC 0i/30i-class control.
	hdr := make([]byte, 16)
	hdr[0] = 0x00
	hdr[1] = 0x01 // response marker
	binary.BigEndian.PutUint16(hdr[2:4], 0x0001)
	body := []byte("FANUC Series 30i-MODEL B\x00")
	binary.BigEndian.PutUint16(hdr[14:16], uint16(len(body)))
	resp := append(hdr, body...)
	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.Meta["focas_model"] = "FANUC Series 30i-MODEL B"
	res.BannerSent = "focas sysinfo"
	return res, nil
}
