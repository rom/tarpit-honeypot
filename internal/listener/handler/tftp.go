package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type tftp struct{}

func (t *tftp) Name() string { return "tftp" }

// TFTP (RFC 1350, port 69 UDP). Both RRQ (opcode 1, read) and WRQ (opcode 2,
// write) carry filename + null + mode + null. We capture the requested
// filename + mode and reply with Error (opcode 5) code 2 (Access violation).
// That ends the transfer cleanly and avoids becoming a free file server.
//
// We do NOT support actual transfer (DATA / ACK). That would require
// per-source state and creates an amplifier (DATA blocks are 516 bytes
// and the protocol is lock-step).
func (t *tftp) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...)}

	if len(payload) < 4 {
		res.Meta = map[string]any{"short_packet": true}
		return res, nil
	}
	opcode := binary.BigEndian.Uint16(payload[0:2])
	opName := tftpOpName(opcode)
	res.Meta = map[string]any{"opcode": opName}

	switch opcode {
	case 1, 2:
		// RRQ or WRQ. Layout: opcode(2) | filename(null-terminated) | mode(null-terminated)
		// Possibly followed by RFC 2347 options.
		fields := bytes.Split(payload[2:], []byte{0})
		if len(fields) >= 1 {
			res.Meta["filename"] = string(fields[0])
		}
		if len(fields) >= 2 {
			res.Meta["mode"] = string(fields[1])
		}
		// Extra fields are RFC 2347 options (blksize, tsize, timeout, ...)
		opts := map[string]string{}
		for i := 2; i+1 < len(fields); i += 2 {
			if len(fields[i]) > 0 {
				opts[string(fields[i])] = string(fields[i+1])
			}
		}
		if len(opts) > 0 {
			res.Meta["options"] = opts
		}
		// Protocol-misuse detection. A WRQ is an upload — pushing a file
		// (often a tampered firmware / config) onto the device. An RRQ for
		// a device config file is config exfil (the classic "copy running-
		// config tftp" pivot against network gear). We serve neither.
		filename := ""
		if len(fields) >= 1 {
			filename = string(fields[0])
		}
		if opcode == 2 {
			flagAnomaly(&res, "tftp-write-attempt")
			// A WRQ for a firmware/OS image is an attempt to flash tampered
			// firmware onto network gear — the highest-impact TFTP abuse.
			if tftpFirmwareName(filename) {
				flagAnomaly(&res, "tftp-firmware-push")
			}
		} else if tftpConfigName(filename) {
			flagAnomaly(&res, "tftp-config-read")
		}
		// Directory traversal / absolute / UNC paths in the filename are an
		// arbitrary-file read-or-write attempt.
		if strings.Contains(filename, "..") || strings.HasPrefix(filename, "/") || strings.Contains(filename, "\\") {
			flagAnomaly(&res, "tftp-path-traversal")
		}
		sendTFTPError(pc, src, 2, "Access violation")
		res.BannerSent = "tftp ERROR access_violation"

	case 3, 4, 5:
		// DATA / ACK / ERROR — we don't keep transfer state, but log it.
		res.Meta["unexpected_in_initial"] = true

	default:
		res.Meta["unknown_opcode"] = opcode
	}
	_ = cfg
	return res, nil
}

func sendTFTPError(pc net.PacketConn, dst net.Addr, code uint16, msg string) {
	pkt := make([]byte, 4+len(msg)+1)
	binary.BigEndian.PutUint16(pkt[0:2], 5) // opcode ERROR
	binary.BigEndian.PutUint16(pkt[2:4], code)
	copy(pkt[4:], msg)
	pkt[len(pkt)-1] = 0
	_, _ = pc.WriteTo(pkt, dst)
}

// tftpConfigName reports whether a requested filename looks like a network
// device's configuration or firmware image — the targets an attacker reads
// over TFTP to harvest credentials / topology or to stage a downgrade.
func tftpConfigName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	// Cisco's well-known auto-load names + generic config/firmware files.
	for _, sub := range []string{
		"running-config", "startup-config", "running-confg", "startup-confg",
		"network-confg", "router-confg", "cisconet.cfg", "ciscortr.cfg",
	} {
		if strings.Contains(n, sub) {
			return true
		}
	}
	for _, ext := range []string{".cfg", ".conf", ".config", ".confg", ".bin", ".img", ".rom"} {
		if strings.HasSuffix(n, ext) {
			return true
		}
	}
	return false
}

// tftpFirmwareName reports whether the name looks like a firmware / OS image
// (the payload of a tampered-firmware WRQ against network/IoT gear).
func tftpFirmwareName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, ext := range []string{".bin", ".img", ".rom", ".trx", ".chk", ".pkg", ".tar", ".ios", ".swi"} {
		if strings.HasSuffix(n, ext) {
			return true
		}
	}
	return strings.Contains(n, "firmware") || strings.Contains(n, "uimage")
}

func tftpOpName(c uint16) string {
	switch c {
	case 1:
		return "RRQ"
	case 2:
		return "WRQ"
	case 3:
		return "DATA"
	case 4:
		return "ACK"
	case 5:
		return "ERROR"
	case 6:
		return "OACK"
	}
	return ""
}
