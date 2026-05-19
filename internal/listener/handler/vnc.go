package handler

import (
	"context"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type vnc struct{}

func (v *vnc) Name() string { return "vnc" }

// VNC / RFB (port 5900). The protocol opens with a 12-byte ASCII version
// string: "RFB 003.008\n". The client responds with its preferred version
// in the same format. We then send a SecurityResult of "VNC Authentication"
// + a 16-byte challenge, the client sends a 16-byte response, and we
// always answer with "auth failed".
//
// We capture the client RFB version + their auth response (a DES-encrypted
// password). Scanners brute-forcing default VNC passwords leak the
// response bytes here.
func (v *vnc) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}

	const serverVersion = "RFB 003.008\n"
	if _, err := conn.Write([]byte(serverVersion)); err != nil {
		res.Meta = map[string]any{"write_err": err.Error()}
		return res, nil
	}
	res.BannerSent = serverVersion

	clientVer := make([]byte, 12)
	if _, err := io.ReadFull(conn, clientVer); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	res.Payload = append([]byte(nil), clientVer...)
	res.Meta = map[string]any{
		"client_version": string(clientVer),
	}

	// SecurityTypes: 1 type, type=2 (VNC auth).
	if _, err := conn.Write([]byte{1, 2}); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	// Client picks a security type (1 byte).
	sel := make([]byte, 1)
	if _, err := io.ReadFull(conn, sel); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Meta["security_type_selected"] = sel[0]
	if sel[0] != 2 {
		// Client picked something we didn't offer; just close.
		return res, nil
	}

	// Send 16-byte challenge.
	challenge := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}
	if _, err := conn.Write(challenge); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	response := make([]byte, 16)
	if _, err := io.ReadFull(conn, response); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(res.Payload, response...)
	res.Meta["auth_response_hex"] = byteToHex(response)

	// SecurityResult = 1 (failed).
	_, _ = conn.Write([]byte{0, 0, 0, 1})
	res.BannerSent = "rfb 003.008 + VNC auth failed"
	return res, nil
}

func byteToHex(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}
