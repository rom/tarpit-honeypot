package handler

import (
	"encoding/binary"
	"testing"
)

// encTDSPassword applies the forward LOGIN7 password obfuscation: for each
// UTF-16LE byte, swap nibbles then XOR 0xA5.
func encTDSPassword(s string) []byte {
	u := utf16le(s)
	out := make([]byte, len(u))
	for i, b := range u {
		sw := (b << 4) | (b >> 4)
		out[i] = sw ^ 0xA5
	}
	return out
}

// buildLogin7 assembles a LOGIN7 body (the bytes after the 8-byte TDS header)
// with the given fields placed in a data area after the fixed+table header.
func buildLogin7(host, user, pass, app, server, lib, lang, db string, mac [6]byte) []byte {
	const t = 36
	// 9 (ib,cch) pairs = 36 bytes, + ClientID(6) + SSPI(4) + AtchDB(4) +
	// ChangePw(4) + cbSSPILong(4) = data starts at t+36+22 = 94. Round to 96.
	dataStart := 96
	body := make([]byte, dataStart)
	// Fixed header bits we assert on: TDS version + client PID.
	binary.LittleEndian.PutUint32(body[0:4], 0x74000004) // TDS 7.4
	binary.LittleEndian.PutUint32(body[16:20], 4242)     // client PID
	copy(body[t+36:t+42], mac[:])                        // ClientID (MAC)

	put := func(pairOff int, raw []byte) {
		ib := len(body)
		body = append(body, raw...)
		binary.LittleEndian.PutUint16(body[pairOff:pairOff+2], uint16(ib))
		// cch is a CHARACTER count (UTF-16 -> /2); password stored as bytes too.
		binary.LittleEndian.PutUint16(body[pairOff+2:pairOff+4], uint16(len(raw)/2))
	}
	put(t+0, utf16le(host))
	put(t+4, utf16le(user))
	put(t+8, encTDSPassword(pass))
	put(t+12, utf16le(app))
	put(t+16, utf16le(server))
	put(t+24, utf16le(lib))
	put(t+28, utf16le(lang))
	put(t+32, utf16le(db))
	return body
}

func TestParseLogin7FullExtraction(t *testing.T) {
	mac := [6]byte{0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef}
	body := buildLogin7("DESKTOP-ATTACK", "sa", "P@ssw0rd!", "sqlcmd",
		"victim-sql", "ODBC", "us_english", "master", mac)
	var res Result
	res.Meta = map[string]any{}
	parseLogin7(body, &res)

	checks := map[string]string{
		"login_hostname": "DESKTOP-ATTACK",
		"login_user":     "sa",
		"login_password": "P@ssw0rd!",
		"login_app":      "sqlcmd",
		"login_server":   "victim-sql",
		"login_library":  "ODBC",
		"login_language": "us_english",
		"login_database": "master",
		"client_mac":     "00:0c:29:ab:cd:ef",
	}
	for k, want := range checks {
		if got, _ := res.Meta[k].(string); got != want {
			t.Errorf("%s = %q; want %q", k, got, want)
		}
	}
	if res.Meta["client_pid"] != uint32(4242) {
		t.Errorf("client_pid = %v; want 4242", res.Meta["client_pid"])
	}
	if !hasAnom(res, "mssql-login-attempt") {
		t.Errorf("login attempt not flagged: %v", res.Meta["anomalies"])
	}
}
