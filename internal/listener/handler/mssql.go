package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"

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
	tdsSQLBatch = 0x01
)

func (m *mssql) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	dbReplyDelaySleep() // heavy-DB realism: a loaded server answers in seconds
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
	// The client's PRELOGIN ENCRYPTION option tells us whether it will encrypt
	// the LOGIN7 (and thus the credentials). OFF / NOT_SUP means the password
	// crosses in the clear (only XOR-obfuscated) — sniffable credential exposure.
	if enc, ok := tdsPreloginEncryption(body); ok {
		res.Meta["client_encryption"] = enc
		if enc == 0x00 || enc == 0x02 {
			flagAnomaly(&res, "mssql-encryption-disabled")
			setIfEmpty(res.Meta, "intent", "MSSQL login without TLS encryption — cleartext credential exposure")
		}
	}
	resp := m.buildPreLoginResponse(15, 0, build, subBuild)
	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "mssql PRELOGIN response (15.0)"
	res.Meta["server_version"] = "15.0." + itoa(int(build)) + "." + itoa(int(subBuild))

	// Optionally read the LOGIN7 packet. It is a rich intel source — beyond the
	// username/password it carries the client hostname, the application name and
	// the client library/driver (which reveal the tool), the target server +
	// database + language, the client PID and TDS/program version, and the
	// client's MAC address. parseLogin7 extracts them all (and de-obfuscates the
	// trivially-encoded password) into res.Meta.
	lhdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, lhdr); err == nil && lhdr[0] == tdsLogin7 {
		llen := int(binary.BigEndian.Uint16(lhdr[2:4]))
		if llen > 8 && llen < 8192 {
			lbody, ok := safe.AllocBytes(llen - 8)
			if ok {
				if _, err := io.ReadFull(conn, lbody); err == nil {
					parseLogin7(lbody, &res)
				}
			}
		}
		// In full-interaction mode, send a LOGINACK so the client proceeds to
		// issue a SQLBatch — capturing post-auth T-SQL (xp_cmdshell, UNC
		// coercion, CLR, linked-server, BULK). Otherwise reply with a
		// real-looking auth failure (we never grant access).
		if FullInteractionAllowed() {
			_, _ = conn.Write(mssqlLoginAck())
			m.readSQLBatch(conn, &res)
		} else {
			_, _ = conn.Write(m.buildLoginError())
		}
	}
	return res, nil
}

// tdsPreloginEncryption extracts the ENCRYPTION option (token 0x01) value from a
// client PRELOGIN body: a list of (type1, offset2, len2) option tokens
// terminated by 0xFF, followed by the option data.
func tdsPreloginEncryption(body []byte) (byte, bool) {
	for i := 0; i+5 <= len(body); i += 5 {
		if body[i] == 0xFF {
			break
		}
		if body[i] == 0x01 { // ENCRYPTION
			off := int(binary.BigEndian.Uint16(body[i+1 : i+3]))
			if off >= 0 && off < len(body) {
				return body[off], true
			}
		}
	}
	return 0, false
}

// mssqlLoginAck builds a minimal TDS Tabular-Result response carrying a LOGINACK
// token + a final DONE token, so a client accepts the login and sends its first
// SQLBatch. Capture-only — no session state is created.
func mssqlLoginAck() []byte {
	prog := utf16leBytes("Microsoft SQL Server")
	inner := []byte{0x01}                   // interface = SQL
	inner = append(inner, 0x04, 0, 0, 0x74) // TDS 7.4
	inner = append(inner, byte(len(prog)/2))
	inner = append(inner, prog...)
	inner = append(inner, 15, 0, 0x07, 0xd0) // server version 15.0.2000
	tok := []byte{0xAD, byte(len(inner)), byte(len(inner) >> 8)}
	tok = append(tok, inner...)
	// DONE token: status DONE_FINAL(0x0000), curcmd 0, rowcount 0 (8 bytes).
	tok = append(tok, 0xFD, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0)
	return wrapTDS(0x04, tok)
}

// readSQLBatch reads one post-login TDS packet; if it is a SQLBatch (type 0x01),
// it extracts the UCS-2 T-SQL text and classifies it.
func (m *mssql) readSQLBatch(conn net.Conn, res *Result) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	if hdr[0] != tdsSQLBatch {
		return
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length <= 8 || length > 1<<16 {
		return
	}
	b, ok := safe.AllocBytes(length - 8)
	if !ok {
		return
	}
	if _, err := io.ReadFull(conn, b); err != nil {
		return
	}
	sql := decodeUCS2Printable(b)
	if sql == "" {
		return
	}
	if len(sql) > 4096 {
		sql = sql[:4096]
	}
	res.Meta["tds_sql_batch"] = safe.SanitizeForLog(sql)
	flagAnomaly(res, "mssql-post-auth-query")
	classifyTSQL(res, sql)
	// Reply DONE so a polite client doesn't hang.
	_, _ = conn.Write(wrapTDS(0x04, []byte{0xFD, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}))
}

// classifyTSQL flags post-auth T-SQL abuse primitives. Detection only.
func classifyTSQL(res *Result, sql string) {
	l := strings.ToLower(sql)
	switch {
	case strings.Contains(l, "xp_cmdshell"):
		flagAnomaly(res, "mssql-xp-cmdshell")
		res.Meta["intent"] = "MSSQL xp_cmdshell — OS command execution"
	case strings.Contains(l, "sp_oacreate") || strings.Contains(l, "sp_oamethod"):
		flagAnomaly(res, "mssql-ole-automation")
		res.Meta["intent"] = "MSSQL OLE automation (sp_OACreate) — command execution"
	case strings.Contains(l, "xp_dirtree") || strings.Contains(l, "xp_fileexist") || strings.Contains(l, "xp_subdirs"):
		flagAnomaly(res, "mssql-unc-coercion")
		res.Meta["intent"] = "MSSQL UNC auth coercion (xp_dirtree) — NetNTLM capture/relay"
	case strings.Contains(l, "create assembly") || strings.Contains(l, "0x4d5a") || strings.Contains(l, "clr enabled"):
		flagAnomaly(res, "mssql-clr-assembly")
		res.Meta["intent"] = "MSSQL CLR assembly load — code execution"
	case strings.Contains(l, "openquery") || strings.Contains(l, "openrowset") || strings.Contains(l, " at ["):
		flagAnomaly(res, "mssql-linked-server")
		setIfEmpty(res.Meta, "intent", "MSSQL linked-server / OPENROWSET — lateral movement / file read")
	case strings.Contains(l, "bulk insert"):
		flagAnomaly(res, "mssql-bulk-fileread")
		setIfEmpty(res.Meta, "intent", "MSSQL BULK INSERT — arbitrary file read")
	case strings.Contains(l, "xp_regread") || strings.Contains(l, "xp_regwrite"):
		flagAnomaly(res, "mssql-registry-access")
	case strings.Contains(l, "sp_add_job") || strings.Contains(l, "sp_add_jobstep") || strings.Contains(l, "cmdexec"):
		flagAnomaly(res, "mssql-agent-job")
		res.Meta["intent"] = "MSSQL Agent job (CmdExec/PowerShell step) — persistence / execution"
	case strings.Contains(l, "execute as login") || strings.Contains(l, "execute as user"):
		flagAnomaly(res, "mssql-impersonation")
		res.Meta["intent"] = "MSSQL EXECUTE AS — privilege escalation via impersonation"
	case sqlLooksInjection(l):
		flagAnomaly(res, "mssql-sqli-probe")
	}
}

// utf16leBytes encodes an ASCII string as UTF-16LE.
func utf16leBytes(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0)
	}
	return out
}

// decodeUCS2Printable extracts printable ASCII from a UTF-16LE byte run.
func decodeUCS2Printable(b []byte) string {
	var sb []byte
	for i := 0; i+1 < len(b); i += 2 {
		if b[i+1] == 0 && (b[i] == '\t' || b[i] == ' ' || (b[i] >= 0x21 && b[i] < 0x7f)) {
			sb = append(sb, b[i])
		}
	}
	return string(sb)
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

// parseLogin7 extracts the rich intel a TDS LOGIN7 packet carries into res.Meta.
//
// LOGIN7 layout (MS-TDS §2.2.6.4): a 36-byte fixed header (TDSVersion,
// PacketSize, ClientProgVer, ClientPID, ConnectionID, the OptionFlags,
// ClientTimeZone, ClientLCID) followed by an OffsetLength table of (ib,cch)
// uint16 pairs whose offsets are relative to the start of this body. The
// password field is obfuscated with the trivial swap-nibbles + XOR-0xA5
// scheme, which we reverse. Everything is bounds-checked.
func parseLogin7(body []byte, res *Result) {
	const t = 36 // OffsetLength table start
	if len(body) < t+24 {
		return
	}
	// field reads a UCS-2 string given the byte offset of its (ib,cch) pair.
	field := func(pairOff int) string {
		if pairOff+4 > len(body) {
			return ""
		}
		ib := int(binary.LittleEndian.Uint16(body[pairOff : pairOff+2]))
		cch := int(binary.LittleEndian.Uint16(body[pairOff+2 : pairOff+4]))
		chunk, ok := safe.Slice(body, ib, cch*2)
		if !ok || cch == 0 {
			return ""
		}
		return fromUTF16le(chunk)
	}
	// OffsetLength table order: HostName, UserName, Password, AppName,
	// ServerName, (Unused/Extension), CltIntName, Language, Database.
	host := field(t + 0)
	user := field(t + 4)
	pwEnc := body // password decoded separately (needs de-obfuscation)
	app := field(t + 12)
	server := field(t + 16)
	library := field(t + 24) // CltIntName — the client driver / interface
	language := field(t + 28)
	database := field(t + 32)

	set := func(k, v string) {
		if v != "" {
			res.Meta[k] = safe.SanitizeForLog(v)
		}
	}
	set("login_hostname", host)
	set("login_user", user)
	set("login_app", app)         // e.g. "Microsoft SQL Server Management Studio", "sqlcmd"
	set("login_server", server)   // the server name the client targeted
	set("login_library", library) // ".Net SqlClient Data Provider" / "ODBC" / "go-mssqldb"
	set("login_language", language)
	set("login_database", database)

	// Password: ib@t+8, cch@t+10 — read raw then de-obfuscate.
	if t+12 <= len(body) {
		ib := int(binary.LittleEndian.Uint16(body[t+8 : t+10]))
		cch := int(binary.LittleEndian.Uint16(body[t+10 : t+12]))
		if raw, ok := safe.Slice(pwEnc, ib, cch*2); ok && cch > 0 {
			if pw := decodeTDSPassword(raw); pw != "" {
				res.Meta["login_password"] = safe.SanitizeForLog(pw)
			}
		}
	}

	// Fixed-header intel: TDS version, client program version, client PID, LCID.
	res.Meta["tds_version"] = "0x" + itoa32hex(binary.LittleEndian.Uint32(body[0:4]))
	if pid := binary.LittleEndian.Uint32(body[16:20]); pid != 0 {
		res.Meta["client_pid"] = pid
	}

	// ClientID (the client MAC address) sits right after the 9 (ib,cch) pairs:
	// table start + 9*4 = t+36, 6 bytes.
	if mac, ok := safe.Slice(body, t+36, 6); ok && !allZero(mac) {
		res.Meta["client_mac"] = fmtMAC(mac)
	}

	if user != "" || res.Meta["login_password"] != nil {
		flagAnomaly(res, "mssql-login-attempt")
		u, _ := res.Meta["login_user"].(string)
		p, _ := res.Meta["login_password"].(string)
		flagDefaultCred(res, u, p)
	}
}

// decodeTDSPassword reverses the LOGIN7 password obfuscation. The client
// encodes each byte as swap-nibbles(b) XOR 0xA5, so decoding is the inverse:
// XOR 0xA5 first, then swap the nibbles back. The result is UTF-16LE.
func decodeTDSPassword(raw []byte) string {
	dec := make([]byte, len(raw))
	for i, b := range raw {
		x := b ^ 0xA5
		dec[i] = (x << 4) | (x >> 4)
	}
	return fromUTF16le(dec)
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// fmtMAC renders 6 bytes as aa:bb:cc:dd:ee:ff.
func fmtMAC(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 17)
	for i, x := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexd[x>>4], hexd[x&0x0f])
	}
	return string(out)
}

// itoa32hex renders a uint32 as a hex string (no leading 0x).
func itoa32hex(v uint32) string {
	if v == 0 {
		return "0"
	}
	const hexd = "0123456789abcdef"
	var buf [8]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = hexd[v&0x0f]
		v >>= 4
	}
	return string(buf[i:])
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
