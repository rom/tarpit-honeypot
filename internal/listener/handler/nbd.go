package handler

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// nbd emulates a Network Block Device server (newstyle handshake, TCP 10809).
// An exposed NBD export is a data-theft / ransomware target: the server greets,
// the client sends its flags and an option (commonly LIST to enumerate exports,
// or EXPORT_NAME / GO to attach one). We complete the greeting, capture the
// option + requested export name, flag the attempt, and never serve a device.
type nbd struct{}

func (n *nbd) Name() string { return "nbd" }

func (n *nbd) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	// newstyle greeting: "NBDMAGIC" + "IHAVEOPT" + 2-byte handshake flags
	// (FIXED_NEWSTYLE | NO_ZEROES).
	greet := append([]byte("NBDMAGIC"), []byte("IHAVEOPT")...)
	greet = append(greet, 0x00, 0x03)
	if _, err := conn.Write(greet); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "nbd newstyle greeting"

	br := bufio.NewReader(conn)
	var cf [4]byte
	if _, err := io.ReadFull(br, cf[:]); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Meta["nbd_client_flags"] = binary.BigEndian.Uint32(cf[:])

	// First option request: 8-byte "IHAVEOPT" magic, 4-byte option, 4-byte len.
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return res, nil
	}
	opt := binary.BigEndian.Uint32(hdr[8:12])
	dlen := binary.BigEndian.Uint32(hdr[12:16])
	res.Meta["nbd_option"] = nbdOptName(opt)
	flagAnomaly(&res, "nbd-handshake")
	if dlen > 0 && dlen <= 4096 {
		data := make([]byte, dlen)
		if _, err := io.ReadFull(br, data); err == nil {
			res.Payload = append([]byte(nil), data...)
			if opt == 1 || opt == 7 { // EXPORT_NAME / GO carry the export name
				res.Meta["nbd_export"] = safe.SanitizeForLog(string(data))
			}
		}
	}
	if opt == 3 { // NBD_OPT_LIST — enumerate exports (recon)
		flagAnomaly(&res, "nbd-export-enumeration")
	}
	return res, nil
}

func nbdOptName(o uint32) string {
	switch o {
	case 1:
		return "EXPORT_NAME"
	case 2:
		return "ABORT"
	case 3:
		return "LIST"
	case 6:
		return "INFO"
	case 7:
		return "GO"
	case 8:
		return "STRUCTURED_REPLY"
	}
	return "opt-" + strconv.Itoa(int(o))
}
