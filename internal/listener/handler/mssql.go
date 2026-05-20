package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// mssql emulates the Microsoft SQL Server TDS pre-login exchange (TCP
// 1433). A scanner (nmap ms-sql-info, metasploit mssql_ping) opens
// with a TDS PRELOGIN packet (type 0x12); a real server replies with a
// PRELOGIN response carrying VERSION / ENCRYPTION / INSTOPT option
// tokens. We answer with a believable SQL Server version + an
// ENCRYPT_NOT_SUP flag, then read the (optional) follow-up LOGIN7
// packet and capture the username if present before closing.
//
// TDS packet header (8 bytes):
//
//	type(1) status(1) length(2 BE) spid(2) packetID(1) window(1)
type mssql struct {
	id *identity.Identity
}

func (m *mssql) Name() string { return "mssql" }

const (
	tdsPreLogin = 0x12
	tdsLogin7   = 0x10
	tdsResponse = 0x04
)

func (m *mssql) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	pktType := hdr[0]
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	res.Meta["tds_packet_type"] = pktType
	if length < 8 || length > 8192 {
		res.Meta["bad_tds_length"] = length
		return res, nil
	}
	body, ok := safe.AllocBytes(length - 8)
	if !ok {
		res.Meta["alloc_err"] = length
		return res, nil
	}
	if _, err := io.ReadFull(conn, body); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(hdr, body...)

	if pktType != tdsPreLogin {
		res.Meta["non_prelogin"] = true
		return res, nil
	}

	// Build a PRELOGIN response. Version: SQL Server 2019 RTM
	// (15.0.2000.5). The deployment id salts the minor build so two
	// sensors differ.
	build := uint16(2000)
	subBuild := uint16(5)
	if m.id != nil {
		build = 1000 + uint16(m.id.Uint32("mssql-build")%3000)
	}
	resp := m.buildPreLoginResponse(15, 0, build, subBuild)
	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "mssql PRELOGIN response (15.0)"
	res.Meta["server_version"] = "15.0." + itoa(int(build)) + "." + itoa(int(subBuild))

	// Optionally read the LOGIN7 packet — it carries the username +
	// (encrypted) password. We just capture the username offset/len if
	// the client sends one.
	lhdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, lhdr); err == nil && lhdr[0] == tdsLogin7 {
		llen := int(binary.BigEndian.Uint16(lhdr[2:4]))
		if llen > 8 && llen < 8192 {
			lbody, ok := safe.AllocBytes(llen - 8)
			if ok {
				if _, err := io.ReadFull(conn, lbody); err == nil {
					if u := parseLogin7User(lbody); u != "" {
						res.Meta["login_user"] = safe.SanitizeForLog(u)
						flagAnomaly(&res, "mssql-login-attempt")
					}
				}
			}
		}
		// Reply LOGINACK-shaped error so the client sees a real-looking
		// auth failure (we never grant access).
		_, _ = conn.Write(m.buildLoginError())
	}
	return res, nil
}

// buildPreLoginResponse assembles a TDS PRELOGIN response with VERSION,
// ENCRYPTION (=NOT_SUP), and TERMINATOR option tokens.
func (m *mssql) buildPreLoginResponse(major, minor byte, build, subBuild uint16) []byte {
	// Option tokens: each is token(1) offset(2 BE) length(2 BE).
	// Tokens: VERSION(0), ENCRYPTION(1), TERMINATOR(0xFF).
	// VERSION data = 6 bytes (major, minor, build hi, build lo, subbuild lo, subbuild hi).
	// ENCRYPTION data = 1 byte.
	const (
		tokVersion    = 0x00
		tokEncryption = 0x01
		tokTerm       = 0xFF
		encNotSup     = 0x02
	)
	// Header: 2 option tokens (5 bytes each) + 1 terminator (1 byte) = 11.
	hdrLen := 5 + 5 + 1
	versionData := []byte{major, minor, byte(build >> 8), byte(build), byte(subBuild), byte(subBuild >> 8)}
	encData := []byte{encNotSup}

	verOff := hdrLen
	encOff := verOff + len(versionData)

	var opts []byte
	opts = append(opts, tokVersion)
	opts = binary.BigEndian.AppendUint16(opts, uint16(verOff))
	opts = binary.BigEndian.AppendUint16(opts, uint16(len(versionData)))
	opts = append(opts, tokEncryption)
	opts = binary.BigEndian.AppendUint16(opts, uint16(encOff))
	opts = binary.BigEndian.AppendUint16(opts, uint16(len(encData)))
	opts = append(opts, tokTerm)

	payload := append(opts, versionData...)
	payload = append(payload, encData...)

	return wrapTDS(tdsResponse, payload)
}

// buildLoginError builds a minimal TDS response carrying an ERROR
// token (login failed) so the client gets a real-looking rejection.
func (m *mssql) buildLoginError() []byte {
	// ERROR token (0xAA): length(2) number(4) state(1) class(1)
	// msglen(2) msg(N*2 UCS2) servernamelen(1) ... — we keep it short.
	msg := utf16le("Login failed for user.")
	var tok []byte
	tok = append(tok, 0xAA)
	bodyLen := 4 + 1 + 1 + 2 + len(msg) + 1 + 1 + 4
	tok = binary.LittleEndian.AppendUint16(tok, uint16(bodyLen))
	tok = binary.LittleEndian.AppendUint32(tok, 18456) // error number 18456
	tok = append(tok, 1)                               // state
	tok = append(tok, 14)                              // class (severity)
	tok = binary.LittleEndian.AppendUint16(tok, uint16(len(msg)/2))
	tok = append(tok, msg...)
	tok = append(tok, 0)                           // server name len
	tok = append(tok, 0)                           // proc name len
	tok = binary.LittleEndian.AppendUint32(tok, 1) // line number
	// DONE token (0xFD): status(2) curcmd(2) rowcount(8).
	tok = append(tok, 0xFD, 0x02, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0)
	return wrapTDS(tdsResponse, tok)
}

// wrapTDS prepends the 8-byte TDS packet header (single, final packet)
// to a payload.
func wrapTDS(pktType byte, payload []byte) []byte {
	total := 8 + len(payload)
	out := make([]byte, total)
	out[0] = pktType
	out[1] = 0x01 // status: EOM (end of message)
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	// spid, packetID, window left zero.
	copy(out[8:], payload)
	return out
}

// parseLogin7User pulls the user-name field out of a LOGIN7 packet
// body. LOGIN7 has a fixed header then offset/length pairs for
// hostname, username, password, etc. (UCS-2). The username
// offset/len live at a fixed location; we bounds-check everything.
func parseLogin7User(body []byte) string {
	// LOGIN7 fixed portion is 36 bytes of dwords then the
	// offset/length table. ibUserName is at offset 0+... — rather than
	// hard-code the full layout (fragile), scan for the
	// OffsetLength block: it starts at byte 36. ibUserName at 36+8,
	// cchUserName at 36+10 (each entry is 2x uint16).
	const tableStart = 36
	if len(body) < tableStart+12 {
		return ""
	}
	ibUser := int(binary.LittleEndian.Uint16(body[tableStart+8 : tableStart+10]))
	cchUser := int(binary.LittleEndian.Uint16(body[tableStart+10 : tableStart+12]))
	// Offsets in LOGIN7 are relative to the start of the packet DATA
	// (i.e. body here). cchUser is a character count (UCS-2 -> *2).
	byteLen := cchUser * 2
	chunk, ok := safe.Slice(body, ibUser, byteLen)
	if !ok || byteLen == 0 {
		return ""
	}
	return fromUTF16le(chunk)
}

// utf16le encodes an ASCII string as little-endian UTF-16.
func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// fromUTF16le decodes little-endian UTF-16 to a Go string (BMP only).
func fromUTF16le(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	out := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, rune(uint16(b[i])|uint16(b[i+1])<<8))
	}
	return string(out)
}
