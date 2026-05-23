package handler

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// pop3 emulates a POP3 mail server (RFC 1939 + CAPA/SASL, TCP 110). It greets
// with an APOP-capable timestamp banner, answers CAPA, walks the USER/PASS,
// APOP and SASL AUTH (PLAIN/LOGIN) logins, captures the credentials, and
// rejects the auth — mail-credential harvesting bait. Nothing is delivered.
type pop3 struct{}

func (p *pop3) Name() string { return "pop3" }

func (p *pop3) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	// APOP-style banner: the <id@host> timestamp tells a scanner APOP is
	// available (and is the challenge an APOP login would hash against).
	_, _ = conn.Write([]byte("+OK POP3 server ready <1896.697170952@mail>\r\n"))
	res.BannerSent = "+OK POP3 server ready"

	br := bufio.NewReader(conn)
	var user string
	var commands []string
	for i := 0; i < 12; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			if i == 0 {
				res.Meta["read_err"] = err.Error()
			}
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		res.Payload = append(res.Payload, []byte(line+"\n")...)
		commands = append(commands, line)
		fields := strings.SplitN(line, " ", 2)
		arg := ""
		if len(fields) > 1 {
			arg = fields[1]
		}
		switch strings.ToUpper(fields[0]) {
		case "USER":
			user = arg
			res.Meta["auth_user"] = user
			_, _ = conn.Write([]byte("+OK\r\n"))
		case "PASS":
			res.Meta["auth_pass"] = arg
			if user != "" {
				flagDefaultCred(&res, user, arg)
			}
			_, _ = conn.Write([]byte("-ERR [AUTH] authentication failed\r\n"))
		case "APOP":
			if af := strings.SplitN(arg, " ", 2); af[0] != "" {
				res.Meta["auth_user"] = af[0]
			}
			_, _ = conn.Write([]byte("-ERR [AUTH] authentication failed\r\n"))
		case "AUTH":
			p.handlePOP3Auth(arg, br, conn, &res)
		case "CAPA":
			_, _ = conn.Write([]byte("+OK Capability list follows\r\n" +
				"TOP\r\nUSER\r\nSASL PLAIN LOGIN\r\nUIDL\r\nRESP-CODES\r\nPIPELINING\r\nSTLS\r\nIMPLEMENTATION Dovecot\r\n.\r\n"))
		case "STLS":
			// We don't negotiate TLS; advertise it but fall back to plaintext.
			_, _ = conn.Write([]byte("-ERR TLS not available\r\n"))
		case "QUIT":
			_, _ = conn.Write([]byte("+OK bye\r\n"))
			res.Meta["commands"] = commands
			return res, nil
		case "STAT", "LIST", "UIDL", "RETR", "DELE", "TOP", "NOOP", "RSET":
			_, _ = conn.Write([]byte("-ERR not authenticated\r\n"))
		default:
			_, _ = conn.Write([]byte("-ERR unknown command\r\n"))
		}
	}
	if len(commands) > 0 {
		res.Meta["commands"] = commands
	}
	return res, nil
}

// handlePOP3Auth walks a SASL AUTH exchange (PLAIN / LOGIN) and decodes the
// base64 credential blobs so harvested user/pass land in meta.
func (p *pop3) handlePOP3Auth(arg string, br *bufio.Reader, conn net.Conn, res *Result) {
	f := strings.Fields(arg)
	if len(f) == 0 {
		// Bare "AUTH" -> list mechanisms.
		_, _ = conn.Write([]byte("+OK\r\nPLAIN\r\nLOGIN\r\n.\r\n"))
		return
	}
	mech := strings.ToUpper(f[0])
	res.Meta["auth_mech"] = mech
	switch mech {
	case "PLAIN":
		blob := ""
		if len(f) >= 2 {
			blob = f[1]
		} else {
			_, _ = conn.Write([]byte("+ \r\n"))
			line, _ := br.ReadString('\n')
			blob = strings.TrimRight(line, "\r\n")
		}
		if raw, err := base64.StdEncoding.DecodeString(blob); err == nil {
			segs := strings.Split(string(raw), "\x00")
			if len(segs) >= 3 {
				res.Meta["auth_user"] = segs[1]
				res.Meta["auth_pass"] = segs[2]
				flagDefaultCred(res, segs[1], segs[2])
			}
		}
		_, _ = conn.Write([]byte("-ERR [AUTH] authentication failed\r\n"))
	case "LOGIN":
		_, _ = conn.Write([]byte("+ " + base64.StdEncoding.EncodeToString([]byte("Username:")) + "\r\n"))
		uLine, _ := br.ReadString('\n')
		_, _ = conn.Write([]byte("+ " + base64.StdEncoding.EncodeToString([]byte("Password:")) + "\r\n"))
		pLine, _ := br.ReadString('\n')
		if u, err := base64.StdEncoding.DecodeString(strings.TrimRight(uLine, "\r\n")); err == nil {
			res.Meta["auth_user"] = string(u)
		}
		if pw, err := base64.StdEncoding.DecodeString(strings.TrimRight(pLine, "\r\n")); err == nil {
			res.Meta["auth_pass"] = string(pw)
		}
		if u, _ := res.Meta["auth_user"].(string); u != "" {
			pw, _ := res.Meta["auth_pass"].(string)
			flagDefaultCred(res, u, pw)
		}
		_, _ = conn.Write([]byte("-ERR [AUTH] authentication failed\r\n"))
	default:
		_, _ = conn.Write([]byte("-ERR Unsupported authentication mechanism\r\n"))
	}
}
