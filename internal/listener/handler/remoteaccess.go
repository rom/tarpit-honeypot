package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// teamviewer emulates the TeamViewer relay protocol (TCP 5938).
// TeamViewer opens with a banner-shaped handshake; the distinctive
// thing a scanner keys on is the "\x17\x24..." framing + the literal
// ASCII string "TeamViewer" in the early bytes. We read the client's
// first frame, capture it, and reply with a minimal handshake echo so
// the scanner records a live TeamViewer relay.
type teamviewer struct{}

func (t *teamviewer) Name() string { return "teamviewer" }

func (t *teamviewer) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	// TeamViewer clients send a CMD_PING-shaped first packet. Read a
	// bounded chunk.
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		res.Payload = append([]byte(nil), buf[:n]...)
		res.Meta["client_hello_hex"] = byteToHex(buf[:min(n, 32)])
	}
	// Reply with a TeamViewer-shaped handshake: the protocol uses a
	// 17 24 ... framing; we send a plausible server hello that
	// references the version.
	reply := append([]byte{0x17, 0x24, 0x00, 0x00}, []byte("TeamViewer\x00")...)
	_, _ = conn.Write(reply)
	res.BannerSent = "teamviewer relay hello"
	return res, nil
}

// anydesk emulates AnyDesk (TCP 7070). AnyDesk speaks a TLS-ish
// protocol but the discovery banner on 7070 is an HTTP-looking probe;
// we answer with the AnyDesk relay's characteristic short reply.
type anydesk struct{}

func (a *anydesk) Name() string { return "anydesk" }

func (a *anydesk) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		res.Payload = append([]byte(nil), buf[:n]...)
		res.Meta["client_hello_hex"] = byteToHex(buf[:min(n, 32)])
	}
	// AnyDesk's discovery reply references the version string.
	_, _ = conn.Write([]byte("ad.anynet.relay 7.1.11\r\n"))
	res.BannerSent = "anydesk relay hello"
	return res, nil
}

// openvpn emulates the OpenVPN control channel (TCP/UDP 1194). The
// first packet of an OpenVPN session is a P_CONTROL_HARD_RESET_CLIENT
// (opcode 7 in the high 5 bits of the first byte for the TCP framing,
// or 0x38 for the classic). We capture the client reset + reply with a
// P_CONTROL_HARD_RESET_SERVER so a scanner (nmap openvpn probe)
// classifies us as an OpenVPN server. TCP variant has a 2-byte length
// prefix; this handler is the TCP form.
type openvpn struct{}

func (o *openvpn) Name() string { return "openvpn" }

func (o *openvpn) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	// TCP framing: 2-byte big-endian length, then the OpenVPN packet.
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	plen := int(binary.BigEndian.Uint16(lenBuf))
	if plen < 1 || plen > 2048 {
		res.Meta["bad_length"] = plen
		return res, nil
	}
	pkt, ok := safe.AllocBytes(plen)
	if !ok {
		return res, nil
	}
	if _, err := io.ReadFull(conn, pkt); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(lenBuf, pkt...)
	opcode := pkt[0] >> 3
	res.Meta["opvn_opcode"] = opcode
	// P_CONTROL_HARD_RESET_CLIENT_V2 = 7.
	if opcode != 7 && opcode != 1 {
		res.Meta["non_openvpn"] = true
		return res, nil
	}
	res.Meta["openvpn_reset"] = true

	// Reply P_CONTROL_HARD_RESET_SERVER_V2 (opcode 8 << 3 = 0x40) with
	// a fresh session id. Minimal but enough for fingerprinting.
	sid := make([]byte, 8)
	if len(pkt) >= 9 {
		copy(sid, pkt[1:9]) // not strictly needed; just echo entropy
	}
	body := append([]byte{0x40}, sid...)
	body = append(body, 0x00) // packet-id array length 0
	frame := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(body)))
	copy(frame[2:], body)
	_, _ = conn.Write(frame)
	res.BannerSent = "openvpn HARD_RESET_SERVER"
	flagAnomaly(&res, "openvpn-probe")
	return res, nil
}

// citrixICA emulates the Citrix ICA / CGP protocol (TCP 1494 / 2598).
// The ICA browser handshake begins with a distinctive
// "\x7f\x7f...ICA" exchange. We answer with the ICA server hello so a
// scanner records a Citrix XenApp/XenDesktop server.
type citrixICA struct{}

func (c *citrixICA) Name() string { return "citrix_ica" }

func (c *citrixICA) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		res.Payload = append([]byte(nil), buf[:n]...)
		res.Meta["client_hello_hex"] = byteToHex(buf[:min(n, 32)])
	}
	// ICA server detection reply: the classic "ICA" + 0x01 0x30 marker.
	_, _ = conn.Write([]byte{0x7f, 0x7f, 'I', 'C', 'A', 0x01, 0x30, 0x02, 0x00, 0x00})
	res.BannerSent = "citrix ICA hello"
	return res, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
