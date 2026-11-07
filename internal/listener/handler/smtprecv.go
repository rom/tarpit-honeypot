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
	"github.com/rom/tarpit-honeypot/internal/safe"
)

type smtpRecv struct {
	id     *identity.Identity
	jit    *jitter.Jitterer
	arch   *archetype.Profile
	tlsMgr *certManager
}

func newSMTPRecv(deps Deps) *smtpRecv {
	return &smtpRecv{id: deps.Identity, jit: deps.Jitter, arch: deps.Archetype, tlsMgr: maybeCertMgr(deps)}
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
func (s *smtpRecv) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (res Result, _ error) {
	withTimeout(conn, cfg.ReadTimeout)
	s.jit.Sleep(ctx)
	res = Result{Meta: map[string]any{}}
	// Run the CVE signature catalog over the captured SMTP transcript on every
	// exit path (parity with imap/pop3) so a catalogued mail-server exploit
	// attempt becomes a cve:<id> event.
	defer func() { cveScanMail(&res, "smtp_recv") }()

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
	// Advertise STARTTLS only when we can actually negotiate it (a cert manager
	// is wired and we're not already inside TLS), keeping the advertisement
	// honest.
	if s.tlsMgr != nil && !alreadyTLS(conn) {
		exts = withSTARTTLS(exts)
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
		line, err := readLineCapped(br, maxLineBytes)
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
			localDom := ""
			if s.id != nil {
				localDom = s.id.Domain()
			}
			if from, _ := res.Meta["mail_from"].(string); isExternalAddr(from, localDom) && isExternalAddr(to, localDom) {
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
			// Mine the message for headers + content intent (subject/from,
			// phishing links, malware attachments) — far richer intel than the
			// raw head blob alone.
			smtpClassifyMessage(&res, head)
			// Capture the (possibly in-TLS-tunnel) message content into the
			// payload too, so the full transferred plaintext — not just the
			// command verbs — is recorded and searchable.
			res.Payload = append(res.Payload, []byte("DATA\n"+head)...)
			if ended {
				fmt.Fprintf(conn, "250 OK: queued as 0xdeadbeef\r\n")
			}
		case "BDAT":
			// CHUNKING (RFC 3030): "BDAT <size> [LAST]" — read a bounded chunk,
			// capture it, then accept it like a real MTA would.
			if chunk := readBDATChunk(arg, br); chunk != "" {
				res.Meta["bdat_chunk"] = safe.SanitizeForLog(chunk)
				res.Payload = append(res.Payload, []byte(chunk)...)
			}
			fmt.Fprintf(conn, "250 OK\r\n")
		case "HELP":
			fmt.Fprintf(conn, "214 2.0.0 https://www.postfix.org/\r\n")
		case "NOOP":
			fmt.Fprintf(conn, "250 OK\r\n")
		case "ETRN":
			fmt.Fprintf(conn, "250 OK\r\n")
		case "RSET":
			fmt.Fprintf(conn, "250 OK\r\n")
		case "QUIT":
			fmt.Fprintf(conn, "221 Bye\r\n")
			if len(rcpt) > 0 {
				res.Meta["rcpt_to"] = rcpt
			}
			return res, nil
		case "STARTTLS":
			if s.tlsMgr == nil || alreadyTLS(conn) {
				fmt.Fprintf(conn, "454 4.7.0 STARTTLS unavailable\r\n")
				break
			}
			fmt.Fprintf(conn, "220 2.0.0 Ready to start TLS\r\n")
			nc, err := startTLS(ctx, conn, s.tlsMgr, cfg.ID, tlsHosts(cfg), s.arch)
			if err != nil {
				res.Meta["tls_err"] = err.Error()
				return res, nil
			}
			conn = nc
			br = bufio.NewReader(conn)
			withTimeout(conn, cfg.ReadTimeout)
			res.Meta["tls"] = true
			res.Meta["starttls"] = true
			// RFC 3207: discard any state learned before the TLS upgrade.
			delete(res.Meta, "helo")
			rcpt = rcpt[:0]
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

// smtpClassifyMessage extracts the Subject / From headers from a captured DATA
// head and classifies the content: phishing links, a malware attachment
// (base64 MIME part), or bulk-spam shape. Detection only — nothing is delivered.
func smtpClassifyMessage(res *Result, head string) {
	for _, line := range strings.Split(head, "\n") {
		line = strings.TrimRight(line, "\r")
		low := strings.ToLower(line)
		switch {
		case strings.HasPrefix(low, "subject:"):
			res.Meta["mail_subject"] = safe.SanitizeForLog(clipStr(strings.TrimSpace(line[len("subject:"):]), 300))
		case strings.HasPrefix(low, "from:"):
			res.Meta["mail_header_from"] = safe.SanitizeForLog(clipStr(strings.TrimSpace(line[len("from:"):]), 300))
		case line == "" || low == "\r":
			// end of headers — stop scanning header fields
		}
	}
	l := strings.ToLower(head)
	switch {
	case strings.Contains(l, "content-transfer-encoding: base64") &&
		(strings.Contains(l, "application/") || strings.Contains(l, "name=") || strings.Contains(l, "filename=")):
		flagAnomaly(res, "smtp-attachment")
		setIfEmpty(res.Meta, "intent", "SMTP message with a (base64) attachment — malware delivery attempt")
	case strings.Contains(l, "http://") || strings.Contains(l, "https://"):
		flagAnomaly(res, "smtp-message-link")
		if strings.Contains(l, "verify") || strings.Contains(l, "password") || strings.Contains(l, "account") ||
			strings.Contains(l, "login") || strings.Contains(l, "invoice") || strings.Contains(l, "urgent") {
			flagAnomaly(res, "smtp-phishing-content")
			setIfEmpty(res.Meta, "intent", "SMTP phishing content — credential-lure link in message body")
		} else {
			setIfEmpty(res.Meta, "intent", "SMTP message carrying a link (spam / lure)")
		}
	}
}

// isExternalAddr reports whether an SMTP path (<user@domain>) names a
// domain other than the ones we pretend to be authoritative for. Used
// to detect open-relay probes: a relayer sends mail FROM and TO
// addresses both outside our domain. We treat example.com/.internal/
// localhost as "ours"; everything else is external.
func isExternalAddr(addr string, local string) bool {
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
	// The deployment's own DNS domain counts as local (so mail within our
	// pretend org isn't mistaken for an open-relay probe).
	if local != "" && (domain == local || strings.HasSuffix(domain, "."+local)) {
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
// are purely declarative) so advertising stays consistent with behaviour.
// STARTTLS is appended at runtime by withSTARTTLS when a cert manager is wired
// (it is omitted here so a TLS-less deployment never advertises it). Archetypes
// whose MTA differs (Exchange, sendmail) override via Profile.smtpExtensions.
var defaultSMTPExtensions = []string{
	"PIPELINING", "SIZE 10240000", "VRFY", "ETRN", "AUTH PLAIN LOGIN CRAM-MD5",
	"ENHANCEDSTATUSCODES", "8BITMIME", "DSN", "CHUNKING", "SMTPUTF8",
}

// withSTARTTLS returns exts with STARTTLS appended (a fresh slice, so the
// shared default isn't mutated), unless it is already present.
func withSTARTTLS(exts []string) []string {
	for _, e := range exts {
		if strings.EqualFold(e, "STARTTLS") {
			return exts
		}
	}
	out := make([]string, len(exts), len(exts)+1)
	copy(out, exts)
	return append(out, "STARTTLS")
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
			line, _ := readLineCapped(br, maxLineBytes)
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
		l1, _ := readLineCapped(br, maxLineBytes)
		userB64 := strings.TrimSpace(l1)
		fmt.Fprintf(conn, "334 UGFzc3dvcmQ6\r\n") // base64 "Password:"
		l2, _ := readLineCapped(br, maxLineBytes)
		passB64 := strings.TrimSpace(l2)
		if u, err := base64.StdEncoding.DecodeString(userB64); err == nil {
			meta["auth_user"] = string(u)
		}
		if p, err := base64.StdEncoding.DecodeString(passB64); err == nil {
			meta["auth_pass"] = string(p)
		}
		fmt.Fprintf(conn, "535 Authentication failed\r\n")
	case "CRAM-MD5":
		// Server sends a base64 challenge; client replies base64("user
		// space hmac-md5-hex"). We can't recover the plaintext password,
		// but the username + the HMAC (offline-crackable) are worth capturing.
		fmt.Fprintf(conn, "334 PDEyMzQ1Njc4OUBtYWlsPg==\r\n") // base64 "<123456789@mail>"
		l, _ := readLineCapped(br, maxLineBytes)
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(l)); err == nil {
			if sp := strings.IndexByte(string(raw), ' '); sp > 0 {
				meta["auth_user"] = string(raw[:sp])
				meta["auth_cram_response"] = string(raw[sp+1:])
			}
		}
		fmt.Fprintf(conn, "535 Authentication failed\r\n")
	default:
		fmt.Fprintf(conn, "504 Unsupported authentication mechanism\r\n")
	}
}

// readBDATChunk consumes a CHUNKING BDAT chunk: the arg is "<size> [LAST]";
// we read up to a bounded number of the announced bytes (capturing them so the
// transferred message content is recorded) so the stream stays aligned, never
// buffering an unbounded chunk.
func readBDATChunk(arg string, br *bufio.Reader) string {
	f := strings.Fields(arg)
	if len(f) == 0 {
		return ""
	}
	n := 0
	for _, c := range f[0] {
		if c < '0' || c > '9' {
			return ""
		}
		n = n*10 + int(c-'0')
		if n > 65536 {
			n = 65536
			break
		}
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		c, err := br.ReadByte()
		if err != nil {
			break
		}
		if b.Len() < 4096 {
			b.WriteByte(c)
		}
	}
	return b.String()
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
