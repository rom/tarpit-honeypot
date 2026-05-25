package handler

import (
	"context"
	crand "crypto/rand"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

type vnc struct {
	id *identity.Identity
}

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

	// Server RFB version: deployment-unique pick from the real
	// RFB-version pool (3.3 / 3.7 / 3.8 / 4.1 / ARD) so a scanner
	// hitting many sensors sees a believable spread of VNC products.
	serverVersion := "RFB 003.008\n"
	if v.id != nil {
		serverVersion = v.id.VNCVersion()
	}
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

	// The security-handshake form depends on the negotiated RFB version. In
	// RFB 3.3 the SERVER chooses the single security type and sends it as a
	// 4-byte value; only in 3.7+ does the server send a type LIST the client
	// picks from. Embedded KVM-over-IP / IPMI VNC commonly speaks 3.3, so a
	// 3.7-only handshake is a honeypot tell against those clients.
	if rfbMinor(clientVer) <= 3 {
		res.Meta["rfb_security"] = "3.3"
		// Server-chosen security type = 2 (VNC auth), 4-byte big-endian.
		if _, err := conn.Write([]byte{0, 0, 0, 2}); err != nil {
			res.Meta["write_err"] = err.Error()
			return res, nil
		}
	} else {
		res.Meta["rfb_security"] = "3.7+"
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
	}

	// Send a fresh 16-byte challenge per connection — that's what a real
	// VNC server does (the DES auth nonce). A static challenge would itself
	// be a fingerprint and enable precomputed-response attacks.
	challenge := make([]byte, 16)
	if _, err := crand.Read(challenge); err != nil && v.id != nil {
		// crypto/rand should never fail; fall back to a deployment value.
		challenge = v.id.Bytes("vnc-challenge", 16)
	}
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
	// Record the challenge alongside the response: a VNC password is only
	// offline-crackable from the (challenge, DES-response) pair, so capturing
	// just the response is not actionable. Flag the auth attempt so a VNC
	// default-password brute-force surfaces as an event.
	res.Meta["challenge_hex"] = byteToHex(challenge)
	res.Meta["auth_response_hex"] = byteToHex(response)
	flagAnomaly(&res, "vnc-auth-attempt")

	// SecurityResult = 1 (failed).
	_, _ = conn.Write([]byte{0, 0, 0, 1})
	res.BannerSent = "rfb 003.008 + VNC auth failed"
	return res, nil
}

// rfbMinor parses the minor number from an RFB version string of the form
// "RFB 003.008\n" (here 8). Returns 8 (a safe 3.7+ default) on a malformed
// string so we never accidentally drop into the 3.3 path for junk input.
func rfbMinor(ver []byte) int {
	s := string(ver)
	dot := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 || dot+4 > len(s) {
		return 8
	}
	n := 0
	for i := dot + 1; i < dot+4; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 8
		}
		n = n*10 + int(c-'0')
	}
	return n
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
