package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// imap emulates an IMAP4rev1 server (RFC 3501, TCP 143). It greets, then
// captures LOGIN credentials (and the mechanism from AUTHENTICATE) and
// rejects the auth — mail-credential harvesting bait.
type imap struct{}

func (m *imap) Name() string { return "imap" }

func (m *imap) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	_, _ = conn.Write([]byte("* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] Service ready\r\n"))
	res.BannerSent = "* OK IMAP4rev1 ready"

	br := bufio.NewReader(conn)
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
		// IMAP commands are "<tag> <COMMAND> <args>".
		parts := strings.SplitN(line, " ", 3)
		tag := parts[0]
		cmd, rest := "", ""
		if len(parts) > 1 {
			cmd = strings.ToUpper(parts[1])
		}
		if len(parts) > 2 {
			rest = parts[2]
		}
		switch cmd {
		case "LOGIN":
			user, pass := parseIMAPLogin(rest)
			if user != "" {
				res.Meta["auth_user"] = user
			}
			if pass != "" {
				res.Meta["auth_pass"] = pass
			}
			if user != "" {
				flagDefaultCred(&res, user, pass)
			}
			_, _ = conn.Write([]byte(tag + " NO [AUTHENTICATIONFAILED] Authentication failed\r\n"))
		case "CAPABILITY":
			_, _ = conn.Write([]byte("* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\n" + tag + " OK CAPABILITY completed\r\n"))
		case "AUTHENTICATE":
			res.Meta["auth_mech"] = rest
			_, _ = conn.Write([]byte(tag + " NO AUTHENTICATE failed\r\n"))
		case "LOGOUT":
			_, _ = conn.Write([]byte("* BYE logging out\r\n" + tag + " OK LOGOUT completed\r\n"))
			res.Meta["commands"] = commands
			return res, nil
		case "":
			// blank command token — ignore
		default:
			_, _ = conn.Write([]byte(tag + " NO not authenticated\r\n"))
		}
	}
	if len(commands) > 0 {
		res.Meta["commands"] = commands
	}
	return res, nil
}

// parseIMAPLogin extracts user + pass from an IMAP LOGIN argument, handling
// quoted strings: LOGIN "user" "pass" or LOGIN user pass.
func parseIMAPLogin(arg string) (user, pass string) {
	toks := splitIMAPArgs(arg)
	if len(toks) >= 1 {
		user = toks[0]
	}
	if len(toks) >= 2 {
		pass = toks[1]
	}
	return user, pass
}

// splitIMAPArgs splits on spaces but keeps "double-quoted" tokens whole.
func splitIMAPArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			inQ = !inQ
		case c == ' ' && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
