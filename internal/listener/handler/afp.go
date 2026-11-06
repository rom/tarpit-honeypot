package handler

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// afpH emulates an Apple Filing Protocol server (TCP 548) over DSI (Data
// Stream Interface). Exposed AFP file sharing is a data-theft finding and the
// home of several pre-auth CVEs. We recognize the DSI header, answer a
// DSIGetStatus with a believable server-info block (name, AFP versions, UAMs),
// and flag the probe. No shares are real.
type afpH struct{}

func (afpH) Name() string { return "afp" }

// DSI command codes (AFP over TCP).
const (
	dsiGetStatus   = 3
	dsiOpenSession = 4
)

func (afpH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{"service": "afp"}}
	br := bufio.NewReader(conn)

	// DSI header is 16 bytes: flags, command, requestID(2), errCode/off(4),
	// totalDataLength(4), reserved(4).
	hdr := make([]byte, 16)
	if _, err := readFull(br, hdr); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append([]byte(nil), hdr...)
	cmd := hdr[1]
	reqID := binary.BigEndian.Uint16(hdr[2:4])
	res.Meta["dsi_command"] = int(cmd)

	switch cmd {
	case dsiGetStatus:
		flagAnomaly(&res, "afp-getstatus")
		res.Meta["intent"] = "AFP DSIGetStatus — file-server fingerprint / share enumeration"
		info := afpServerInfo()
		_, _ = conn.Write(afpReply(cmd, reqID, info))
		res.BannerSent = "afp getstatus"
	case dsiOpenSession:
		flagAnomaly(&res, "afp-opensession")
		res.Meta["intent"] = "AFP DSIOpenSession — login session to the file server"
		_, _ = conn.Write(afpReply(cmd, reqID, []byte{0x01, 0x04, 0x00, 0x00, 0x04, 0x00}))
		res.BannerSent = "afp opensession"
	default:
		res.Meta["intent"] = "AFP/DSI request"
	}
	return res, nil
}

// afpReply builds a DSI reply header (flags=0x01 reply) + payload.
func afpReply(cmd byte, reqID uint16, payload []byte) []byte {
	h := make([]byte, 16)
	h[0] = 0x01 // reply
	h[1] = cmd
	binary.BigEndian.PutUint16(h[2:4], reqID)
	binary.BigEndian.PutUint32(h[8:12], uint32(len(payload)))
	return append(h, payload...)
}

// afpServerInfo returns a minimal, believable AFP GetStatus reply body: the
// machine type, supported AFP versions and UAMs, and a server name.
func afpServerInfo() []byte {
	// A compact hand-rolled server-info block (offsets are approximate but
	// well-formed enough for a scanner's fingerprint). Strings are
	// length-prefixed Pascal strings.
	pstr := func(s string) []byte { return append([]byte{byte(len(s))}, s...) }
	var b []byte
	b = append(b, 0x00, 0x1a)            // MachineType offset (nominal)
	b = append(b, 0x00, 0x22)            // AFPVersionCount offset
	b = append(b, 0x00, 0x2e)            // UAMCount offset
	b = append(b, 0x00, 0x00)            // VolumeIcon offset
	b = append(b, 0x00, 0x00)            // flags
	b = append(b, pstr("fileserver")...) // server name
	b = append(b, pstr("Macmini")...)    // machine type
	b = append(b, 0x03)                  // AFP version count
	b = append(b, pstr("AFP3.4")...)
	b = append(b, pstr("AFP3.3")...)
	b = append(b, pstr("AFP3.1")...)
	b = append(b, 0x02) // UAM count
	b = append(b, pstr("DHCAST128")...)
	b = append(b, pstr("DHX2")...)
	return b
}
