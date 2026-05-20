package handler

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
)

type smtpRecv struct {
	id   *identity.Identity
	jit  *jitter.Jitterer
	arch *archetype.Profile
}

func (s *smtpRecv) Name() string { return "smtp_recv" }

// SMTP receive honeypot (port 25). Implements just enough ESMTP to capture
// the client's HELO/EHLO, AUTH credentials (PLAIN + LOGIN), MAIL FROM,
// RCPT TO, and the start of the DATA body. We never deliver anything —
// every command after AUTH is answered with a 550 if it's not part of
// the credential capture flow.
//
// Captured fields land in meta: helo, auth_mech, auth_user, auth_pass,
// mail_from, rcpt_to, message_head.
func (s *smtpRecv) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	s.jit.Sleep(ctx)
	res := Result{Meta: map[string]any{}}

	host := "mail.example.com"
	if s.arch != nil && s.arch.SMTPHost() != "" {
		host = s.arch.SMTPHost()
	} else if s.id != nil {
		host = s.id.HostName()
	}
	product := "Postfix (Debian/GNU)"
	if s.arch != nil && s.arch.SMTPProduct() != "" {
		product = s.arch.SMTPProduct()
	}
	exts := s.arch.SMTPExtensions()
	if len(exts) == 0 {
		exts = defaultSMTPExtensions
	}
	greet := "220 " + host + " ESMTP " + product + "\r\n"
	if cfg.Banner != "" {
		greet = cfg.Banner
	}
	if _, err := conn.Write([]byte(greet)); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = greet
	br := bufio.NewReader(conn)

	rcpt := []string{}
	for i := 0; i < 32; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			res.Meta["read_err"] = err.Error()
			break
		}
		cmdLine := strings.TrimRight(line, "\r\n")
		res.Payload = append(res.Payload, []byte(cmdLine+"\n")...)
		cmd, arg := splitSMTPCmd(cmdLine)
		switch cmd {
		case "EHLO", "HELO":
			res.Meta["helo"] = arg
			if cmd == "HELO" {
				fmt.Fprintf(conn, "250 %s\r\n", host)
			} else {
				_, _ = conn.Write([]byte(buildSMTPEHLO(host, exts)))
			}
		case "AUTH":
			s.handleAuth(arg, br, conn, res.Meta)
			if u, _ := res.Meta["auth_user"].(string); u != "" {
				p, _ := res.Meta["auth_pass"].(string)
				flagDefaultCred(&res, u, p)
			}
		case "MAIL":
			res.Meta["mail_from"] = stripPrefixCI(arg, "FROM:")
			fmt.Fprintf(conn, "250 OK\r\n")
		case "RCPT":
			to := stripPrefixCI(arg, "TO:")
			rcpt = append(rcpt, to)
			// Open-relay probe: MAIL FROM and RCPT TO both reference
			// external domains (relaying mail for a third party). A
			// spammer testing whether we'll relay lands here.
			if from, _ := res.Meta["mail_from"].(string); isExternalAddr(from) && isExternalAddr(to) {
				flagAnomaly(&res, "smtp-open-relay-probe")
			}
			fmt.Fprintf(conn, "250 OK\r\n")
		case "VRFY":
			// User enumeration: VRFY <user> asks the server to confirm
			// a mailbox exists.
			res.Meta["vrfy_user"] = arg
			flagAnomaly(&res, "smtp-user-enumeration")
			fmt.Fprintf(conn, "252 Cannot VRFY user\r\n")
		case "EXPN":
			res.Meta["expn_list"] = arg
			flagAnomaly(&res, "smtp-user-enumeration")
			fmt.Fprintf(conn, "252 Cannot EXPN list\r\n")
		case "DATA":
			fmt.Fprintf(conn, "354 End data with <CR><LF>.<CR><LF>\r\n")
			head, ended := readDATAUntilDot(br, 4096)
			res.Meta["message_head"] = head
			if ended {
				fmt.Fprintf(conn, "250 OK: queued as 0xdeadbeef\r\n")
			}
		case "RSET":
			fmt.Fprintf(conn, "250 OK\r\n")
		case "QUIT":
			fmt.Fprintf(conn, "221 Bye\r\n")
			if len(rcpt) > 0 {
				res.Meta["rcpt_to"] = rcpt
			}
			return res, nil
		case "STARTTLS":
			// We don't actually negotiate; reply 454 so the client falls back.
			fmt.Fprintf(conn, "454 STARTTLS unavailable\r\n")
		case "":
			// empty line — ignore
		default:
			fmt.Fprintf(conn, "502 Unrecognized command\r\n")
		}
	}
	if len(rcpt) > 0 {
		res.Meta["rcpt_to"] = rcpt
	}
	return res, nil
}

// isExternalAddr reports whether an SMTP path (<user@domain>) names a
// domain other than the ones we pretend to be authoritative for. Used
// to detect open-relay probes: a relayer sends mail FROM and TO
// addresses both outside our domain. We treat example.com/.internal/
// localhost as "ours"; everything else is external.
func isExternalAddr(addr string) bool {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 {
		return false
	}
	domain := addr[at+1:]
	domain = strings.TrimRight(domain, ">")
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	switch {
	case strings.HasSuffix(domain, "example.com"),
		strings.HasSuffix(domain, ".internal"),
		strings.HasSuffix(domain, "localhost"),
		strings.HasSuffix(domain, ".local"):
		return false
	}
	return true
}

// defaultSMTPExtensions is the ESMTP keyword set a stock Postfix advertises
// in EHLO. We list only capabilities the handler actually honours (or that
// are purely declarative) so advertising stays consistent with behaviour —
// no STARTTLS, since we never negotiate TLS. Archetypes whose MTA differs
// (Exchange, sendmail) override via Profile.smtpExtensions.
var defaultSMTPExtensions = []string{
	"PIPELINING", "SIZE 10240000", "VRFY", "AUTH PLAIN LOGIN",
	"ENHANCEDSTATUSCODES", "8BITMIME", "DSN",
}

// buildSMTPEHLO renders a multiline 250 EHLO reply: the greeting host on
// the first line, then one extension per line, with the final line using
// the "250 " (space) continuation terminator per RFC 5321 §4.2.1.
func buildSMTPEHLO(host string, exts []string) string {
	lines := make([]string, 0, len(exts)+1)
	lines = append(lines, host)
	lines = append(lines, exts...)
	var b strings.Builder
	for i, l := range lines {
		if i == len(lines)-1 {
			b.WriteString("250 ")
		} else {
			b.WriteString("250-")
		}
		b.WriteString(l)
		b.WriteString("\r\n")
	}
	return b.String()
}

func splitSMTPCmd(line string) (string, string) {
	line = strings.TrimSpace(line)
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return strings.ToUpper(line[:i]), line[i+1:]
	}
	return strings.ToUpper(line), ""
}

func stripPrefixCI(s, p string) string {
	if len(s) < len(p) {
		return s
	}
	if strings.EqualFold(s[:len(p)], p) {
		return strings.TrimSpace(s[len(p):])
	}
	return s
}

func (s *smtpRecv) handleAuth(arg string, br *bufio.Reader, conn net.Conn, meta map[string]any) {
	parts := strings.Fields(arg)
	if len(parts) == 0 {
		fmt.Fprintf(conn, "501 Syntax: AUTH mechanism\r\n")
		return
	}
	mech := strings.ToUpper(parts[0])
	meta["auth_mech"] = mech
	switch mech {
	case "PLAIN":
		// May come inline as "AUTH PLAIN <b64>" or in two steps.
		var encoded string
		if len(parts) >= 2 {
			encoded = parts[1]
		} else {
			fmt.Fprintf(conn, "334 \r\n")
			line, _ := br.ReadString('\n')
			encoded = strings.TrimSpace(line)
		}
		raw, _ := base64.StdEncoding.DecodeString(encoded)
		// PLAIN body: authzid\0username\0password
		segs := strings.Split(string(raw), "\x00")
		if len(segs) >= 3 {
			meta["auth_user"] = segs[1]
			meta["auth_pass"] = segs[2]
		}
		fmt.Fprintf(conn, "535 Authentication failed\r\n")
	case "LOGIN":
		fmt.Fprintf(conn, "334 VXNlcm5hbWU6\r\n") // base64 "Username:"
		l1, _ := br.ReadString('\n')
		userB64 := strings.TrimSpace(l1)
		fmt.Fprintf(conn, "334 UGFzc3dvcmQ6\r\n") // base64 "Password:"
		l2, _ := br.ReadString('\n')
		passB64 := strings.TrimSpace(l2)
		if u, err := base64.StdEncoding.DecodeString(userB64); err == nil {
			meta["auth_user"] = string(u)
		}
		if p, err := base64.StdEncoding.DecodeString(passB64); err == nil {
			meta["auth_pass"] = string(p)
		}
		fmt.Fprintf(conn, "535 Authentication failed\r\n")
	default:
		fmt.Fprintf(conn, "504 Unsupported authentication mechanism\r\n")
	}
}

func readDATAUntilDot(br *bufio.Reader, cap int) (string, bool) {
	var b strings.Builder
	prev := byte('\n')
	for b.Len() < cap {
		c, err := br.ReadByte()
		if err != nil {
			return b.String(), false
		}
		// "<CR><LF>.<CR><LF>" terminator
		if prev == '\n' && c == '.' {
			next, err := br.Peek(2)
			if err == nil && (string(next) == "\r\n" || string(next) == "\n\r") {
				// consume CRLF
				_, _ = br.ReadByte()
				_, _ = br.ReadByte()
				return b.String(), true
			}
		}
		b.WriteByte(c)
		prev = c
	}
	return b.String(), false
}
