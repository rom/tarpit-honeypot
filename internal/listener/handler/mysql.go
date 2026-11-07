package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

type mysql struct {
	id   *identity.Identity
	arch *archetype.Profile
}

func (m *mysql) Name() string { return "mysql" }

// MySQL protocol (port 3306). The server speaks first with a "Handshake
// Initialization Packet" (protocol 10) that advertises capabilities and
// includes a 20-byte salt. The client replies with a "Handshake Response"
// packet carrying username + auth_response (hashed password). We capture
// the username + raw auth_response bytes, then reply with an ERR_Packet
// 1045 (Access denied).
//
// Every MySQL packet has a 4-byte header: length(3) + sequence(1).
func (m *mysql) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	// Heavy-DB realism: a real loaded SQL server doesn't answer in microseconds.
	dbReplyDelaySleep()

	// Build handshake packet (sequence id = 0).
	salt1 := make([]byte, 8)
	salt2 := make([]byte, 12)
	_, _ = rand.Read(salt1)
	_, _ = rand.Read(salt2)

	ver := "5.7.42-log"
	switch {
	case m.arch != nil && m.arch.MySQLVersion() != "":
		ver = m.arch.MySQLVersion()
	case m.id != nil:
		ver = m.id.MySQLVersion()
	}
	body := []byte{}
	body = append(body, 0x0a)           // protocol version 10
	body = append(body, []byte(ver)...) // server version (per-deployment)
	body = append(body, 0)
	body = binary.LittleEndian.AppendUint32(body, 1) // connection id
	body = append(body, salt1...)                    // auth_plugin_data_part_1
	body = append(body, 0)                           // filler
	body = append(body, 0xff, 0xf7)                  // capability flags low
	body = append(body, 0x21)                        // utf8_general_ci
	body = append(body, 0x02, 0x00)                  // status flags
	body = append(body, 0xff, 0x81)                  // capability flags high (CLIENT_PLUGIN_AUTH)
	body = append(body, 0x15)                        // length of auth-plugin-data = 21
	body = append(body, make([]byte, 10)...)         // reserved 10 bytes of 0
	body = append(body, salt2...)                    // auth_plugin_data_part_2
	body = append(body, 0)                           // null terminator
	body = append(body, []byte("mysql_native_password")...)
	body = append(body, 0)

	pkt := make([]byte, 4+len(body))
	pkt[0] = byte(len(body))
	pkt[1] = byte(len(body) >> 8)
	pkt[2] = byte(len(body) >> 16)
	pkt[3] = 0
	copy(pkt[4:], body)
	if _, err := conn.Write(pkt); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "mysql handshake (" + ver + ")"

	// Read client handshake response.
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	respLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if respLen < 4 || respLen > 8192 {
		res.Meta["bad_response_len"] = respLen
		return res, nil
	}
	respBody := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBody); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(hdr, respBody...)

	// Parse: client_capabilities(4) max_packet(4) charset(1) reserved(23) username\0 ...
	if len(respBody) >= 32 {
		capFlags := binary.LittleEndian.Uint32(respBody[0:4])
		res.Meta["client_caps"] = capFlags
		const (
			clientSSL          = 0x00000800
			clientPluginAuth   = 0x00080000
			clientDeprecateEOF = 0x01000000
		)
		if capFlags&clientSSL != 0 {
			// The client asked to switch to TLS (which we don't terminate);
			// note it — many libmysqlclient-based scanners set this.
			res.Meta["ssl_requested"] = true
		}
		p := 32
		username, authResp := "", []byte(nil)
		nullEnd := indexByte(respBody[p:], 0)
		if nullEnd > 0 {
			username = string(respBody[p : p+nullEnd])
			res.Meta["username"] = username
			p += nullEnd + 1
			flagAnomaly(&res, "mysql-login-attempt")
		}
		// Auth-response: either length-encoded (CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)
		// or 1-byte length + bytes (default). Most clients send 1 byte len.
		if p < len(respBody) {
			alen := int(respBody[p])
			p++
			if p+alen <= len(respBody) && alen > 0 {
				authResp = respBody[p : p+alen]
				res.Meta["auth_response_hex"] = byteToHex(authResp)
				p += alen
			}
		}
		// An empty auth-response is a blank/default-password login attempt — the
		// first thing a scanner tries against root/admin.
		if len(authResp) == 0 && username != "" {
			flagAnomaly(&res, "mysql-default-credential")
			setIfEmpty(res.Meta, "intent", "MySQL empty/blank-password login attempt ("+username+")")
		}
		// Optional database name (null-terminated, present with CLIENT_CONNECT_WITH_DB).
		db := ""
		if p < len(respBody) {
			dbEnd := indexByte(respBody[p:], 0)
			if dbEnd > 0 {
				db = string(respBody[p : p+dbEnd])
				res.Meta["database"] = db
				p += dbEnd + 1
			} else if dbEnd == 0 {
				p++ // empty db name
			}
		}
		// Optional client auth-plugin name (CLIENT_PLUGIN_AUTH) — tells us
		// whether the client expects mysql_native_password vs caching_sha2.
		if capFlags&clientPluginAuth != 0 && p < len(respBody) {
			if pEnd := indexByte(respBody[p:], 0); pEnd > 0 {
				ap := string(respBody[p : p+pEnd])
				res.Meta["auth_plugin"] = ap
				// Requesting the cleartext/legacy auth plugin is a downgrade so
				// the password can be sniffed.
				if ap == "mysql_clear_password" || ap == "mysql_old_password" {
					flagAnomaly(&res, "mysql-auth-downgrade")
					setIfEmpty(res.Meta, "intent", "MySQL weak auth-plugin requested ("+ap+") — cleartext/legacy downgrade")
				}
			}
		}

		// Honeytoken authentication: if the attacker presents the exact DB
		// credential planted in the fake web app's leaked .env (user
		// "intranet_app", the per-deployment password, db "intranet" or none),
		// accept the login — they harvested loot from the webapp and it "works",
		// which is the intended deception (and a very high-signal event).
		salt := append(append([]byte{}, salt1...), salt2...)
		if username == webDBUser {
			if m.id != nil && mysqlNativeAuthOK(webappHoneyCreds(m.id).dbPass, salt, authResp) &&
				(db == "" || db == webDBName) {
				dbReplyDelaySleep()
				_, _ = conn.Write(mysqlOKPacket(2))
				res.Meta["auth_accepted"] = true
				flagAnomaly(&res, "mysql-honeytoken-auth")
				res.Meta["intent"] = "MySQL login with the planted .env DB credential — attacker reused harvested webapp loot"
				m.runQuerySession(conn, &res, capFlags&clientDeprecateEOF != 0)
				return res, nil
			}
		}
	}

	// Send ERR_Packet 1045 Access denied. Sequence id = 2.
	dbReplyDelaySleep()
	errBody := []byte{}
	errBody = append(errBody, 0xff)                           // ERR_Packet marker
	errBody = binary.LittleEndian.AppendUint16(errBody, 1045) // error code
	errBody = append(errBody, '#')
	errBody = append(errBody, []byte("28000")...)                  // SQL state
	errBody = append(errBody, []byte("Access denied for user")...) // message
	errPkt := make([]byte, 4+len(errBody))
	errPkt[0] = byte(len(errBody))
	errPkt[1] = byte(len(errBody) >> 8)
	errPkt[2] = byte(len(errBody) >> 16)
	errPkt[3] = 2
	copy(errPkt[4:], errBody)
	_, _ = conn.Write(errPkt)
	return res, nil
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// webDBUser / webDBName are the database identity the fake web app leaks in its
// .env / config files. The decoy MySQL honors exactly this user + the planted
// per-deployment password so the harvested credential authenticates.
const (
	webDBUser = "intranet_app"
	webDBName = "intranet"
)

// mysqlNativeAuthOK validates a mysql_native_password handshake response against
// a known plaintext password + the 20-byte server salt. The client sends
//
//	resp = SHA1(pw) XOR SHA1( salt || SHA1(SHA1(pw)) )
//
// so we recompute it and compare. Returns false on any length mismatch.
func mysqlNativeAuthOK(password string, salt, resp []byte) bool {
	if len(resp) != sha1.Size || len(salt) < 20 {
		return false
	}
	salt = salt[:20]
	h1 := sha1.Sum([]byte(password)) // SHA1(pw)
	h2 := sha1.Sum(h1[:])            // SHA1(SHA1(pw))
	hh := sha1.New()
	hh.Write(salt)
	hh.Write(h2[:])
	tok := hh.Sum(nil) // SHA1(salt || SHA1(SHA1(pw)))
	var match byte
	for i := 0; i < sha1.Size; i++ {
		match |= (h1[i] ^ tok[i]) ^ resp[i]
	}
	return match == 0
}

// mysqlOKPacket builds a minimal OK_Packet (auth success) with the given
// sequence id: header 0x00, affected_rows 0, last_insert_id 0, status flags
// AUTOCOMMIT, 0 warnings.
func mysqlOKPacket(seq byte) []byte {
	body := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	pkt := make([]byte, 4+len(body))
	pkt[0] = byte(len(body))
	pkt[1] = byte(len(body) >> 8)
	pkt[2] = byte(len(body) >> 16)
	pkt[3] = seq
	copy(pkt[4:], body)
	return pkt
}

// runQuerySession reads a bounded number of post-auth COM_QUERY commands from a
// client that authenticated with the honeytoken credential, capturing the SQL
// it runs (high-value intel — what the attacker does once "inside"). Each query
// is answered with a believable empty result / OK. Only entered when the reply
// policy permits full interaction; otherwise we accept the login and stop.
func (m *mysql) runQuerySession(conn net.Conn, res *Result, deprecateEOF bool) {
	if !FullInteractionAllowed() {
		return
	}
	var queries []string
	defer func() {
		if len(queries) > 0 {
			res.Meta["sql_queries"] = queries
			flagAnomaly(res, "mysql-post-auth-query")
		}
	}()
	hdr := make([]byte, 4)
	for i := 0; i < 32; i++ {
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		if n <= 0 || n > 1<<16 {
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		cmd := buf[0]
		switch cmd {
		case 0x01: // COM_QUIT
			return
		case 0x03: // COM_QUERY
			q := string(buf[1:])
			if len(q) > 2048 {
				q = q[:2048]
			}
			if len(queries) < 64 {
				queries = append(queries, q)
			}
			classifyMySQLQuery(res, q)
			dbReplyDelaySleep()
			// Answer common recon queries with a believable result set so the
			// attacker's client keeps the session going and reveals more TTPs;
			// everything else gets an empty OK. Nothing is executed.
			if cols, row, ok := mysqlReconAnswer(q, m.mysqlVersion()); ok {
				_, _ = conn.Write(mysqlTextResultSet(cols, row, deprecateEOF))
			} else {
				_, _ = conn.Write(mysqlOKPacket(1))
			}
		default:
			dbReplyDelaySleep()
			_, _ = conn.Write(mysqlOKPacket(1))
		}
	}
}

// classifyMySQLQuery flags high-signal post-auth SQL: UDF command execution,
// INTO OUTFILE/DUMPFILE webshell/my.cnf drops (CVE-2016-6662), credential-hash
// dumps, and SQL-injection probes. Detection only — nothing is executed.
func classifyMySQLQuery(res *Result, q string) {
	l := strings.ToLower(q)
	switch {
	case strings.Contains(l, "lib_mysqludf_sys") || strings.Contains(l, "sys_exec") ||
		strings.Contains(l, "sys_eval") || (strings.Contains(l, "create function") && strings.Contains(l, "soname")):
		flagAnomaly(res, "mysql-udf-exec")
		res.Meta["intent"] = "MySQL UDF command execution (sys_exec / lib_mysqludf_sys)"
	case strings.Contains(l, "into outfile") || strings.Contains(l, "into dumpfile"):
		flagAnomaly(res, "mysql-outfile-write")
		if strings.Contains(l, "malloc_lib") || strings.Contains(l, "[mysqld]") {
			res.CVEHits = appendUnique(res.CVEHits, "CVE-2016-6662")
			flagAnomaly(res, "cve:CVE-2016-6662")
			res.Meta["intent"] = "MySQL my.cnf injection via OUTFILE — code execution (CVE-2016-6662)"
		} else {
			setIfEmpty(res.Meta, "intent", "MySQL INTO OUTFILE/DUMPFILE — webshell / file drop")
		}
	case strings.Contains(l, "mysql.user") || strings.Contains(l, "authentication_string"):
		flagAnomaly(res, "mysql-credential-dump")
		setIfEmpty(res.Meta, "intent", "MySQL credential-hash dump (mysql.user)")
	case strings.Contains(l, "load data") && strings.Contains(l, "local"):
		flagAnomaly(res, "mysql-load-data-local")
		setIfEmpty(res.Meta, "intent", "MySQL LOAD DATA LOCAL INFILE — client-side file read")
	case strings.Contains(l, "change master") || strings.Contains(l, "change replication source"):
		flagAnomaly(res, "mysql-replication")
		setIfEmpty(res.Meta, "intent", "MySQL CHANGE MASTER — rogue replication setup")
	case strings.Contains(l, "@@version") || strings.Contains(l, "@@datadir") ||
		strings.Contains(l, "@@hostname") || strings.Contains(l, "@@secure_file_priv") || strings.Contains(l, "version()"):
		flagAnomaly(res, "mysql-recon-query")
		setIfEmpty(res.Meta, "intent", "MySQL server-variable reconnaissance")
	case sqlLooksInjection(l):
		flagAnomaly(res, "mysql-sqli-probe")
		setIfEmpty(res.Meta, "intent", "MySQL SQL-injection probe")
	}
}

// mysqlVersion returns the server version string this decoy presents (kept in
// sync with the handshake greeting).
func (m *mysql) mysqlVersion() string {
	if m.arch != nil && m.arch.MySQLVersion() != "" {
		return m.arch.MySQLVersion()
	}
	if m.id != nil {
		return m.id.MySQLVersion()
	}
	return "5.7.42-log"
}

// mysqlLenEnc encodes a MySQL length-encoded integer (small values only, which
// is all a believable recon result needs).
func mysqlLenEnc(n int) []byte {
	switch {
	case n < 251:
		return []byte{byte(n)}
	case n < 1<<16:
		return []byte{0xfc, byte(n), byte(n >> 8)}
	default:
		return []byte{0xfd, byte(n), byte(n >> 8), byte(n >> 16)}
	}
}

// mysqlLenEncStr encodes a length-encoded string.
func mysqlLenEncStr(s string) []byte {
	return append(mysqlLenEnc(len(s)), []byte(s)...)
}

// mysqlPacket frames a packet body with its 3-byte length + sequence id.
func mysqlPacket(seq byte, body []byte) []byte {
	pkt := make([]byte, 4+len(body))
	pkt[0] = byte(len(body))
	pkt[1] = byte(len(body) >> 8)
	pkt[2] = byte(len(body) >> 16)
	pkt[3] = seq
	copy(pkt[4:], body)
	return pkt
}

// mysqlColumnDef builds a Protocol::ColumnDefinition41 for a VAR_STRING column.
func mysqlColumnDef(name string) []byte {
	var b []byte
	b = append(b, mysqlLenEncStr("def")...) // catalog
	b = append(b, mysqlLenEncStr("")...)    // schema
	b = append(b, mysqlLenEncStr("")...)    // table
	b = append(b, mysqlLenEncStr("")...)    // org_table
	b = append(b, mysqlLenEncStr(name)...)  // name
	b = append(b, mysqlLenEncStr("")...)    // org_name
	b = append(b, 0x0c)                     // length of the fixed-length fields
	b = append(b, 0x21, 0x00)               // charset utf8_general_ci
	b = append(b, 0x00, 0x04, 0x00, 0x00)   // column length (1024)
	b = append(b, 0xfd)                     // type = MYSQL_TYPE_VAR_STRING
	b = append(b, 0x00, 0x00)               // flags
	b = append(b, 0x00)                     // decimals
	b = append(b, 0x00, 0x00)               // filler
	return b
}

// mysqlTextResultSet builds a complete COM_QUERY text result set. It honours the
// client's CLIENT_DEPRECATE_EOF capability: with it, the intermediate EOF is
// omitted and the set is terminated by an OK packet (0xFE header); without it,
// the classic EOF packets frame the column list and the rows.
func mysqlTextResultSet(cols []string, rows [][]string, deprecateEOF bool) []byte {
	var out []byte
	seq := byte(1)
	emit := func(body []byte) {
		out = append(out, mysqlPacket(seq, body)...)
		seq++
	}
	emit(mysqlLenEnc(len(cols))) // column count
	for _, c := range cols {
		emit(mysqlColumnDef(c))
	}
	eof := []byte{0xfe, 0x00, 0x00, 0x02, 0x00} // header, warnings(2), status(2)=AUTOCOMMIT
	if !deprecateEOF {
		emit(eof)
	}
	for _, row := range rows {
		var rb []byte
		for _, f := range row {
			if f == "\x00NULL" { // sentinel for a SQL NULL field
				rb = append(rb, 0xfb)
				continue
			}
			rb = append(rb, mysqlLenEncStr(f)...)
		}
		emit(rb)
	}
	if deprecateEOF {
		// OK packet with EOF header terminates the set.
		emit([]byte{0xfe, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
	} else {
		emit(eof)
	}
	return out
}

// mysqlReconAnswer maps a recognised reconnaissance query to a believable
// result set (column names + rows). ok is false for anything else.
func mysqlReconAnswer(q, ver string) (cols []string, rows [][]string, ok bool) {
	l := strings.ToLower(strings.TrimSpace(strings.TrimRight(q, ";")))
	switch {
	case strings.Contains(l, "@@version_comment"):
		return []string{"@@version_comment"}, [][]string{{"MySQL Community Server (GPL)"}}, true
	case strings.Contains(l, "@@version") || l == "select version()" || strings.Contains(l, " version()"):
		return []string{"version()"}, [][]string{{ver}}, true
	case strings.Contains(l, "current_user") || l == "select user()" || strings.Contains(l, " user()"):
		return []string{"user()"}, [][]string{{"root@localhost"}}, true
	case strings.Contains(l, "database()") || strings.Contains(l, "schema()"):
		return []string{"database()"}, [][]string{{"\x00NULL"}}, true
	case strings.Contains(l, "@@datadir"):
		return []string{"@@datadir"}, [][]string{{"/var/lib/mysql/"}}, true
	case strings.Contains(l, "@@hostname"):
		return []string{"@@hostname"}, [][]string{{"db01"}}, true
	case l == "show databases":
		return []string{"Database"}, [][]string{{"information_schema"}, {"mysql"}, {"performance_schema"}, {"sys"}}, true
	case l == "select 1" || l == "select 1 as col":
		return []string{"1"}, [][]string{{"1"}}, true
	}
	return nil, nil, false
}

// sqlLooksInjection reports whether a (lowercased) query looks like an SQLi
// probe. Shared by the SQL DB handlers.
func sqlLooksInjection(l string) bool {
	return strings.Contains(l, "union select") || strings.Contains(l, "' or '1'='1") ||
		strings.Contains(l, "or 1=1") || strings.Contains(l, "sleep(") ||
		strings.Contains(l, "benchmark(") || strings.Contains(l, "/*!") ||
		strings.Contains(l, "information_schema") || strings.Contains(l, "' or 1=1--")
}
