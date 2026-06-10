package handler

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
)

type postgres struct {
	tlsMgr *certManager
	arch   *archetype.Profile
}

// newPostgres wires the cert manager so the handler can honour an SSLRequest
// with a real TLS upgrade. Without a data dir (e.g. some module-mode callers)
// it stays nil and the handler falls back to the plaintext 'N' refusal.
func newPostgres(deps Deps) *postgres {
	return &postgres{arch: deps.Archetype, tlsMgr: maybeCertMgr(deps)}
}

func (p *postgres) Name() string { return "postgres" }

// PostgreSQL frontend/backend protocol (port 5432). The first message from
// any client is one of:
//
//	StartupMessage  - length(4) + protocol(4) + null-terminated key/value pairs
//	SSLRequest      - length(8) + 0x04D2162F (we reply 'N' so the client falls back to plain)
//	GSSEncRequest   - similar; we just close
//
// After StartupMessage we send an AuthenticationCleartextPassword
// request (R + length=8 + 3) which makes the client send its password
// in the clear in a PasswordMessage (p + length + password\0). We
// capture that, then send a FATAL error response and close.
func (p *postgres) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	dbReplyDelaySleep() // heavy-DB realism: a loaded server answers in seconds
	res := Result{Meta: map[string]any{}}

	for i := 0; i < 2; i++ {
		head := make([]byte, 4)
		if _, err := io.ReadFull(conn, head); err != nil {
			res.Meta["read_err"] = err.Error()
			return res, nil
		}
		length := int(binary.BigEndian.Uint32(head))
		if length < 8 || length > 8192 {
			// Not a valid PostgreSQL message frame (a bare banner-grab / nmap
			// NULL or GenericLines probe). Real PostgreSQL answers an invalid
			// startup packet with a FATAL "unsupported frontend protocol"
			// ErrorResponse — emit one so a scanner fingerprints us as
			// PostgreSQL rather than guessing a generic / H2 service.
			res.Meta["bad_length"] = length
			_, _ = conn.Write(buildPgErrorFATAL("0A000", "unsupported frontend protocol 0.0: server supports 3.0 to 3.0"))
			res.BannerSent = "postgres FATAL 0A000"
			return res, nil
		}
		body := make([]byte, length-4)
		if _, err := io.ReadFull(conn, body); err != nil {
			res.Meta["read_err"] = err.Error()
			return res, nil
		}
		res.Payload = append(append(res.Payload, head...), body...)

		if length >= 8 && len(body) >= 4 {
			marker := binary.BigEndian.Uint32(body[0:4])
			switch marker {
			case 0x04D2162F: // SSLRequest
				res.Meta["ssl_request"] = true
				// Real Postgres answers 'S' then performs a TLS handshake; do
				// that when a cert manager is available so a libpq client with
				// sslmode=require/verify proceeds (and we capture the cleartext
				// password it sends post-handshake). Fall back to 'N' otherwise.
				if p.tlsMgr != nil {
					if tcfg, err := p.tlsMgr.serverConfig(cfg.ID, tlsHosts(cfg), p.arch); err == nil {
						if _, err := conn.Write([]byte{'S'}); err != nil {
							res.Meta["write_err"] = err.Error()
							return res, nil
						}
						tlsConn := tls.Server(conn, tcfg)
						if err := tlsConn.HandshakeContext(ctx); err != nil {
							res.Meta["tls_err"] = err.Error()
							return res, nil
						}
						conn = tlsConn
						res.Meta["tls"] = true
						res.Meta["tls_version"] = tlsVersionName(tlsConn.ConnectionState().Version)
						continue
					}
				}
				_, _ = conn.Write([]byte{'N'})
				continue
			case 0x04D21630: // GSSENCRequest
				_, _ = conn.Write([]byte{'N'})
				res.Meta["gssenc_request"] = true
				continue
			case 0x04D2162E: // CancelRequest (sent on a side connection)
				res.Meta["cancel_request"] = true
				if len(body) >= 12 {
					res.Meta["cancel_backend_pid"] = binary.BigEndian.Uint32(body[4:8])
				}
				return res, nil
			}
		}

		// Otherwise treat as StartupMessage.
		pgUser := ""
		if len(body) >= 4 {
			proto := binary.BigEndian.Uint32(body[0:4])
			res.Meta["protocol_version"] = proto
			params := parsePgParams(body[4:])
			if len(params) > 0 {
				res.Meta["startup_params"] = params
				pgUser = params["user"]
				// application_name reveals the client tool (psql / pgAdmin /
				// JDBC / "PostgreSQL JDBC Driver" / a scanner); database +
				// client_encoding round out the connecting party's intent.
				if app := params["application_name"]; app != "" {
					res.Meta["application_name"] = app
				}
				if db := params["database"]; db != "" {
					res.Meta["database"] = db
				}
				// A replication startup is how pg_basebackup / a rogue
				// standby clones the whole cluster — high-signal.
				if r := params["replication"]; r != "" && r != "false" && r != "0" {
					flagAnomaly(&res, "postgres-replication-connection")
				}
			}
		}

		// Send AuthenticationCleartextPassword: 'R' + length=8 (big-endian) + auth_type=3
		req := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}
		if _, err := conn.Write(req); err != nil {
			res.Meta["write_err"] = err.Error()
			return res, nil
		}
		// Read PasswordMessage: 'p' + length(4) + password\0
		pmTag := make([]byte, 5)
		if _, err := io.ReadFull(conn, pmTag); err == nil && pmTag[0] == 'p' {
			pmLen := int(binary.BigEndian.Uint32(pmTag[1:5])) - 4
			if pmLen > 0 && pmLen < 1024 {
				pw := make([]byte, pmLen)
				if _, err := io.ReadFull(conn, pw); err == nil {
					pw = bytesTrimNull(pw)
					res.Meta["password"] = string(pw)
					flagDefaultCred(&res, pgUser, string(pw))
				}
			}
		}
		// In full-interaction mode, accept the login and read one SimpleQuery so
		// post-auth RCE/file-read TTPs (COPY FROM PROGRAM, pg_read_file,
		// untrusted PL languages) surface. Otherwise fail like a locked server.
		if FullInteractionAllowed() {
			p.querySession(conn, &res)
			return res, nil
		}
		// FATAL response: 'E' + length + fields + 0
		errResp := buildPgErrorFATAL("28P01", "password authentication failed")
		_, _ = conn.Write(errResp)
		res.BannerSent = "postgres FATAL 28P01"
		return res, nil
	}
	return res, nil
}

// querySession accepts the login (AuthenticationOk + ReadyForQuery) and reads a
// bounded number of SimpleQuery ('Q') messages, classifying each for post-auth
// abuse. Nothing is executed — every query is answered with an empty
// CommandComplete. Mirrors the MySQL post-auth capture path.
func (p *postgres) querySession(conn net.Conn, res *Result) {
	// AuthenticationOk, a minimal ParameterStatus, BackendKeyData, ReadyForQuery.
	var out []byte
	out = append(out, 'R', 0, 0, 0, 8, 0, 0, 0, 0) // AuthenticationOk
	out = append(out, pgParamStatus("server_version", "14.11")...)
	out = append(out, 'K', 0, 0, 0, 12, 0, 0, 0x30, 0x39, 0, 0, 0x4d, 0x2) // BackendKeyData
	out = append(out, 'Z', 0, 0, 0, 5, 'I')                                // ReadyForQuery (idle)
	if _, err := conn.Write(out); err != nil {
		return
	}
	var queries []string
	defer func() {
		if len(queries) > 0 {
			res.Meta["pg_queries"] = queries
			flagAnomaly(res, "postgres-post-auth-query")
		}
	}()
	hdr := make([]byte, 5)
	for i := 0; i < 16; i++ {
		dbReplyDelaySleep()
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint32(hdr[1:5])) - 4
		if n < 0 || n > 1<<16 {
			return
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		switch hdr[0] {
		case 'Q': // SimpleQuery
			q := string(bytesTrimNull(payload))
			if len(q) > 2048 {
				q = q[:2048]
			}
			if len(queries) < 32 {
				queries = append(queries, q)
			}
			classifyPostgresQuery(res, q)
			// CommandComplete ("SELECT 0") + ReadyForQuery.
			cc := append([]byte{'C', 0, 0, 0, 0}, append([]byte("SELECT 0"), 0)...)
			binary.BigEndian.PutUint32(cc[1:5], uint32(len(cc)-1))
			_, _ = conn.Write(cc)
			_, _ = conn.Write([]byte{'Z', 0, 0, 0, 5, 'I'})
		case 'X': // Terminate
			return
		default:
			_, _ = conn.Write([]byte{'Z', 0, 0, 0, 5, 'I'})
		}
	}
}

// pgParamStatus builds a ParameterStatus ('S') message.
func pgParamStatus(k, v string) []byte {
	body := append(append([]byte(k), 0), append([]byte(v), 0)...)
	out := []byte{'S', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(body)))
	return append(out, body...)
}

// classifyPostgresQuery flags post-auth RCE / file-read / lateral abuse.
func classifyPostgresQuery(res *Result, q string) {
	l := strings.ToLower(q)
	switch {
	case strings.Contains(l, "copy") && strings.Contains(l, "program"):
		flagAnomaly(res, "postgres-copy-program")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2019-9193")
		flagAnomaly(res, "cve:CVE-2019-9193")
		res.Meta["intent"] = "PostgreSQL COPY ... FROM/TO PROGRAM — command execution (CVE-2019-9193)"
	case strings.Contains(l, "plperlu") || strings.Contains(l, "plpythonu") ||
		(strings.Contains(l, "create function") && strings.Contains(l, "language c")):
		flagAnomaly(res, "postgres-untrusted-plang")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2024-10979")
		flagAnomaly(res, "cve:CVE-2024-10979")
		res.Meta["intent"] = "PostgreSQL untrusted procedural-language function — code execution"
	case strings.Contains(l, "lo_import") || strings.Contains(l, "lo_export") ||
		strings.Contains(l, "pg_read_file") || strings.Contains(l, "pg_ls_dir") || strings.Contains(l, "pg_read_binary_file"):
		flagAnomaly(res, "postgres-file-access")
		res.Meta["intent"] = "PostgreSQL server-side file read/write (lo_import / pg_read_file)"
	case strings.Contains(l, "dblink") || strings.Contains(l, "postgres_fdw"):
		flagAnomaly(res, "postgres-dblink-ssrf")
		setIfEmpty(res.Meta, "intent", "PostgreSQL dblink/fdw — SSRF / lateral movement")
	case strings.HasPrefix(strings.TrimSpace(l), "set search_path"):
		flagAnomaly(res, "postgres-searchpath-hijack")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2018-1058")
		flagAnomaly(res, "cve:CVE-2018-1058")
	case sqlLooksInjection(l):
		flagAnomaly(res, "postgres-sqli-probe")
		setIfEmpty(res.Meta, "intent", "PostgreSQL SQL-injection probe")
	}
}

func parsePgParams(b []byte) map[string]string {
	// Null-terminated key, null-terminated value pairs, terminated by an
	// extra null.
	out := map[string]string{}
	parts := strings.Split(string(b), "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		k := parts[i]
		v := parts[i+1]
		if k == "" {
			break
		}
		out[k] = v
	}
	return out
}

func bytesTrimNull(b []byte) []byte {
	for i, v := range b {
		if v == 0 {
			return b[:i]
		}
	}
	return b
}

// buildPgErrorFATAL constructs an ErrorResponse matching what a real
// PostgreSQL 12+ backend emits: the localized severity (S), the
// non-localized severity (V, added in 9.6), the SQLSTATE code (C), the
// message (M), and the source-location fields (F/L/R). Emitting the full
// field set — not just S/C/M — is what nmap's PostgreSQL service signature
// keys on, so the decoy is fingerprinted as PostgreSQL rather than a
// generic / H2 database. Each field is a tagged, null-terminated string;
// the body ends with an extra null.
func buildPgErrorFATAL(code, msg string) []byte {
	field := func(b []byte, tag byte, val string) []byte {
		b = append(b, tag)
		b = append(b, []byte(val)...)
		return append(b, 0)
	}
	body := []byte{}
	body = field(body, 'S', "FATAL")
	body = field(body, 'V', "FATAL")
	body = field(body, 'C', code)
	body = field(body, 'M', msg)
	body = field(body, 'F', "postmaster.c")
	body = field(body, 'L', "2138")
	body = field(body, 'R', "ProcessStartupPacket")
	body = append(body, 0)
	out := make([]byte, 5+len(body))
	out[0] = 'E'
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(body)))
	copy(out[5:], body)
	return out
}
