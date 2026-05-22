package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// pop3 emulates a POP3 mail server (RFC 1939, TCP 110). It greets, walks the
// USER/PASS (and APOP) login, captures the credentials, and rejects the
// auth — mail-credential harvesting bait. Nothing is stored or delivered.
type pop3 struct{}

func (p *pop3) Name() string { return "pop3" }

func (p *pop3) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	_, _ = conn.Write([]byte("+OK POP3 server ready\r\n"))
	res.BannerSent = "+OK POP3 server ready"

	br := bufio.NewReader(conn)
	var user string
	var commands []string
	for i := 0; i < 8; i++ {
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
		case "CAPA":
			_, _ = conn.Write([]byte("+OK\r\nUSER\r\nUIDL\r\nTOP\r\n.\r\n"))
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
