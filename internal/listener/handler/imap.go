package handler

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// imap emulates an IMAP4rev1 server (RFC 3501, TCP 143). It greets, answers
// the pre-auth recon commands (CAPABILITY / ID / NAMESPACE / LIST / STATUS),
// captures LOGIN and SASL AUTHENTICATE credentials, and rejects the auth —
// mail-credential harvesting bait. Nothing is stored or delivered.
type imap struct{}

func (m *imap) Name() string { return "imap" }

// imapCaps is the capability set we advertise (greeting + CAPABILITY). It
// names mechanisms we actually walk (LOGIN, AUTHENTICATE PLAIN/LOGIN) plus
// the declarative extensions a stock Dovecot lists.
const imapCaps = "IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE NAMESPACE AUTH=PLAIN AUTH=LOGIN"

func (m *imap) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	_, _ = conn.Write([]byte("* OK [CAPABILITY " + imapCaps + "] Dovecot ready.\r\n"))
	res.BannerSent = "* OK IMAP4rev1 ready"

	br := bufio.NewReader(conn)
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
			_, _ = conn.Write([]byte(tag + " NO [AUTHENTICATIONFAILED] Authentication failed.\r\n"))
		case "CAPABILITY":
			_, _ = conn.Write([]byte("* CAPABILITY " + imapCaps + "\r\n" + tag + " OK CAPABILITY completed.\r\n"))
		case "ID":
			// Clients send their own ID; we answer with a Dovecot-shaped one.
			_, _ = conn.Write([]byte("* ID (\"name\" \"Dovecot\")\r\n" + tag + " OK ID completed.\r\n"))
		case "NAMESPACE":
			_, _ = conn.Write([]byte("* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n" + tag + " OK NAMESPACE completed.\r\n"))
		case "STARTTLS":
			// We don't negotiate TLS — a real LOGINDISABLED-until-TLS server
			// still accepts the command; we answer OK then the client would
			// start TLS (which we can't), so most fall back to plaintext LOGIN.
			_, _ = conn.Write([]byte(tag + " OK Begin TLS negotiation now.\r\n"))
		case "AUTHENTICATE":
			m.handleIMAPAuth(rest, br, conn, tag, &res)
		case "LIST", "LSUB":
			_, _ = conn.Write([]byte("* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n" + tag + " OK List completed.\r\n"))
		case "SELECT", "EXAMINE":
			// Pre-auth SELECT must fail on a real server.
			_, _ = conn.Write([]byte(tag + " NO Not authenticated.\r\n"))
		case "STATUS":
			_, _ = conn.Write([]byte(tag + " NO Not authenticated.\r\n"))
		case "NOOP", "CHECK":
			_, _ = conn.Write([]byte(tag + " OK NOOP completed.\r\n"))
		case "LOGOUT":
			_, _ = conn.Write([]byte("* BYE Logging out.\r\n" + tag + " OK LOGOUT completed.\r\n"))
			res.Meta["commands"] = commands
			return res, nil
		case "":
			// blank command token — ignore
		default:
			_, _ = conn.Write([]byte(tag + " NO Not authenticated.\r\n"))
		}
	}
	if len(commands) > 0 {
		res.Meta["commands"] = commands
	}
	return res, nil
}

// handleIMAPAuth walks a SASL AUTHENTICATE exchange (PLAIN / LOGIN), decoding
// the base64 credential blobs so harvested user/pass land in meta. Supports
// the SASL-IR inline form ("AUTHENTICATE PLAIN <b64>") and the continuation
// form (server sends "+ ", client replies with the blob).
func (m *imap) handleIMAPAuth(rest string, br *bufio.Reader, conn net.Conn, tag string, res *Result) {
	f := strings.Fields(rest)
	mech := ""
	if len(f) > 0 {
		mech = strings.ToUpper(f[0])
	}
	res.Meta["auth_mech"] = mech
	switch mech {
	case "PLAIN":
		blob := ""
		if len(f) >= 2 {
			blob = f[1] // SASL-IR inline
		} else {
			_, _ = conn.Write([]byte("+ \r\n"))
			line, _ := br.ReadString('\n')
			blob = strings.TrimRight(line, "\r\n")
		}
		// PLAIN: base64(authzid \0 authcid \0 passwd)
		if raw, err := base64.StdEncoding.DecodeString(blob); err == nil {
			segs := strings.Split(string(raw), "\x00")
			if len(segs) >= 3 {
				res.Meta["auth_user"] = segs[1]
				res.Meta["auth_pass"] = segs[2]
				flagDefaultCred(res, segs[1], segs[2])
			}
		}
		_, _ = conn.Write([]byte(tag + " NO [AUTHENTICATIONFAILED] Authentication failed.\r\n"))
	case "LOGIN":
		_, _ = conn.Write([]byte("+ " + base64.StdEncoding.EncodeToString([]byte("Username:")) + "\r\n"))
		uLine, _ := br.ReadString('\n')
		_, _ = conn.Write([]byte("+ " + base64.StdEncoding.EncodeToString([]byte("Password:")) + "\r\n"))
		pLine, _ := br.ReadString('\n')
		if u, err := base64.StdEncoding.DecodeString(strings.TrimRight(uLine, "\r\n")); err == nil {
			res.Meta["auth_user"] = string(u)
		}
		if p, err := base64.StdEncoding.DecodeString(strings.TrimRight(pLine, "\r\n")); err == nil {
			res.Meta["auth_pass"] = string(p)
		}
		if u, _ := res.Meta["auth_user"].(string); u != "" {
			p, _ := res.Meta["auth_pass"].(string)
			flagDefaultCred(res, u, p)
		}
		_, _ = conn.Write([]byte(tag + " NO [AUTHENTICATIONFAILED] Authentication failed.\r\n"))
	default:
		_, _ = conn.Write([]byte(tag + " NO Unsupported authentication mechanism.\r\n"))
	}
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
