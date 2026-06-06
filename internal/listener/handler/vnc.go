package handler

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

type vnc struct {
	id          *identity.Identity
	acceptCreds string // "" / "none" / "defaults" / "any" — gates the post-auth session
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
	if fam := vncClientFamily(string(clientVer)); fam != "" {
		res.Meta["vnc_client"] = fam
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
		res.Meta["security_type_name"] = vncSecurityTypeName(sel[0])
		if sel[0] != 2 {
			// Client picked a type we didn't offer (a well-behaved client only
			// picks from the list). Type 1 (None) means a scanner hunting for an
			// unauthenticated VNC server; the higher types (Tight/TLS/VeNCrypt/
			// Apple-ARD) leak the client family. Record + flag, then close.
			if sel[0] == 1 {
				flagAnomaly(&res, "vnc-none-auth-probe")
				res.Meta["intent"] = "VNC None-auth probe — scanning for an unauthenticated VNC server"
			}
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

	// When the deployment lets attackers "in" (accept_creds any/defaults), accept
	// the auth and run a post-auth RFB session: send a ServerInit and capture the
	// client's keystrokes + clipboard (ClientCutText). Otherwise reject as a real
	// password-protected server would. The DES response is captured for offline
	// cracking either way.
	if v.acceptCreds == "any" || v.acceptCreds == "defaults" {
		if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil { // SecurityResult = OK
			res.Meta["write_err"] = err.Error()
			return res, nil
		}
		res.Meta["auth_accepted"] = true
		flagAnomaly(&res, "vnc-session")
		v.runVNCSession(conn, &res)
		res.BannerSent = "rfb 003.008 + VNC auth accepted (session)"
		return res, nil
	}
	// SecurityResult = 1 (failed). In RFB 3.8 the server follows the status
	// word with a length-prefixed reason string; older versions send only the
	// 4-byte status. Omitting the reason on a 3.8 association is itself a
	// honeypot tell, so we mirror a real server.
	failure := []byte{0, 0, 0, 1}
	if rfbMinor(clientVer) >= 8 {
		reason := "Authentication failed"
		rl := make([]byte, 4)
		binary.BigEndian.PutUint32(rl, uint32(len(reason)))
		failure = append(failure, rl...)
		failure = append(failure, []byte(reason)...)
	}
	_, _ = conn.Write(failure)
	res.BannerSent = "rfb 003.008 + VNC auth failed"
	return res, nil
}

// vncClientFamily fingerprints the VNC client/server product from its RFB
// version string. Apple Remote Desktop / macOS Screen Sharing uses the
// non-standard minor 889 ("RFB 003.889") — a strong, documented tell;
// other products mostly share "RFB 003.008", so we only name what is
// genuinely distinctive and leave the rest to the encodings fingerprint.
func vncClientFamily(ver string) string {
	switch {
	case len(ver) >= 11 && ver[:8] == "RFB 003." && ver[8:11] == "889":
		return "apple-remote-desktop"
	case len(ver) >= 11 && ver[:8] == "RFB 004.":
		return "apple-screen-sharing"
	case len(ver) >= 11 && ver[:8] == "RFB 003." && ver[8:11] == "006":
		return "ultravnc"
	}
	return ""
}

// vncSecurityTypeName names the RFB security type a client selects (RFC 6143
// + the common vendor extensions a scanner/real client may pick).
func vncSecurityTypeName(t byte) string {
	switch t {
	case 0:
		return "Invalid"
	case 1:
		return "None"
	case 2:
		return "VNC-Authentication"
	case 5:
		return "RA2"
	case 6:
		return "RA2ne"
	case 16:
		return "Tight"
	case 17:
		return "Ultra"
	case 18:
		return "TLS"
	case 19:
		return "VeNCrypt"
	case 30:
		return "Apple-ARD"
	}
	return "type-" + itoa(int(t))
}

// runVNCSession plays the post-auth RFB server role: read ClientInit, send a
// ServerInit (framebuffer geometry + pixel format + desktop name), then read a
// bounded number of client messages, capturing typed keys (KeyEvent) and
// clipboard pastes (ClientCutText) — both high-value (passwords / commands /
// pasted secrets). Defensive: every read is bounded and a parse it can't follow
// just ends the session.
func (v *vnc) runVNCSession(conn net.Conn, res *Result) {
	hdr := make([]byte, 1)
	if _, err := io.ReadFull(conn, hdr); err != nil { // ClientInit (shared-flag)
		return
	}
	if _, err := conn.Write(serverInit("honeypot")); err != nil {
		return
	}
	var typed []byte
	defer func() {
		if len(typed) > 0 {
			res.Meta["keystrokes"] = string(typed)
		}
	}()
	for i := 0; i < 64; i++ {
		mt := make([]byte, 1)
		if _, err := io.ReadFull(conn, mt); err != nil {
			return
		}
		switch mt[0] {
		case 0: // SetPixelFormat: 3 pad + 16
			if !skipN(conn, 19) {
				return
			}
		case 2: // SetEncodings: 1 pad + 2 count + count*4
			b := make([]byte, 3)
			if _, err := io.ReadFull(conn, b); err != nil {
				return
			}
			n := int(b[1])<<8 | int(b[2])
			if n < 0 || n > 4096 {
				return
			}
			// The advertised encodings are a strong client fingerprint (Tight,
			// ZRLE, the Apple/TightVNC pseudo-encodings, the JPEG-quality and
			// cursor pseudo-encodings). Capture them once.
			enc := make([]byte, n*4)
			if _, err := io.ReadFull(conn, enc); err != nil {
				return
			}
			if res.Meta["vnc_encodings"] == nil {
				res.Meta["vnc_encodings"] = vncEncodingNames(enc)
			}
		case 3: // FramebufferUpdateRequest: 9
			if !skipN(conn, 9) {
				return
			}
		case 4: // KeyEvent: down-flag(1) + pad(2) + keysym(4)
			b := make([]byte, 7)
			if _, err := io.ReadFull(conn, b); err != nil {
				return
			}
			if b[0] == 1 { // key down
				keysym := binary.BigEndian.Uint32(b[3:7])
				if c := keysymToASCII(keysym); c != 0 && len(typed) < 4096 {
					typed = append(typed, c)
				}
			}
		case 5: // PointerEvent: button(1) + x(2) + y(2)
			if !skipN(conn, 5) {
				return
			}
		case 6: // ClientCutText: 3 pad + length(4) + text
			b := make([]byte, 7)
			if _, err := io.ReadFull(conn, b); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint32(b[3:7]))
			if n < 0 || n > 1<<16 {
				return
			}
			text := make([]byte, n)
			if _, err := io.ReadFull(conn, text); err != nil {
				return
			}
			res.Meta["clipboard"] = string(text)
			flagAnomaly(res, "vnc-clipboard-capture")
		default:
			return // unknown message type — end the session
		}
	}
}

// vncEncodingNames decodes a SetEncodings body (big-endian int32 encoding
// numbers) into human-readable names for the recognized encodings and
// pseudo-encodings. Unknown numbers are rendered as their signed value.
func vncEncodingNames(b []byte) []string {
	var out []string
	for i := 0; i+4 <= len(b) && len(out) < 64; i += 4 {
		e := int32(binary.BigEndian.Uint32(b[i : i+4]))
		out = appendUnique(out, vncEncodingName(e))
	}
	return out
}

func vncEncodingName(e int32) string {
	switch e {
	case 0:
		return "Raw"
	case 1:
		return "CopyRect"
	case 2:
		return "RRE"
	case 5:
		return "Hextile"
	case 6:
		return "Zlib"
	case 7:
		return "Tight"
	case 8:
		return "ZlibHex"
	case 16:
		return "ZRLE"
	case -239:
		return "Cursor"
	case -223:
		return "DesktopSize"
	case -257:
		return "PointerPos"
	case -307:
		return "ExtDesktopSize"
	case -224:
		return "LastRect"
	}
	if e <= -23 && e >= -32 {
		return "JPEG-Quality"
	}
	if e <= -247 && e >= -256 {
		return "Compression"
	}
	return "enc" + itoa(int(e))
}

// serverInit builds an RFB ServerInit: 1024x768, 32bpp true-colour pixel format,
// then the desktop name.
func serverInit(name string) []byte {
	out := make([]byte, 0, 24+len(name))
	out = append(out, 0x04, 0x00, 0x03, 0x00) // width=1024, height=768
	// pixel format: bpp=32, depth=24, big-endian=0, true-colour=1,
	// r/g/b-max=255, r/g/b-shift=16/8/0, 3 pad.
	out = append(out, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0)
	nl := make([]byte, 4)
	binary.BigEndian.PutUint32(nl, uint32(len(name)))
	out = append(out, nl...)
	return append(out, []byte(name)...)
}

// skipN reads and discards n bytes, reporting success.
func skipN(conn net.Conn, n int) bool {
	if n == 0 {
		return true
	}
	_, err := io.CopyN(io.Discard, conn, int64(n))
	return err == nil
}

// keysymToASCII maps an X11 keysym to a captured byte: printable ASCII maps to
// itself; Return/Tab/Space to their controls; everything else to 0 (skip).
func keysymToASCII(k uint32) byte {
	switch {
	case k >= 0x20 && k <= 0x7e:
		return byte(k)
	case k == 0xff0d: // Return
		return '\n'
	case k == 0xff09: // Tab
		return '\t'
	}
	return 0
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
