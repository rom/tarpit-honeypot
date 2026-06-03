package handler

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/fakefiles"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

type ftp struct {
	jit  *jitter.Jitterer
	arch *archetype.Profile
	id   *identity.Identity
}

func (f *ftp) Name() string { return "ftp" }

// defaultFTPFeatures is the FEAT (RFC 2389) set a stock vsftpd advertises.
// Archetypes whose FTP daemon differs (a NAS, ProFTPD) override it via
// Profile.ftpFeatures.
var defaultFTPFeatures = []string{"EPRT", "EPSV", "MDTM", "PASV", "REST STREAM", "SIZE", "TVFS", "UTF8"}

// FTP login flow: 220 banner, then a bounded command loop. We answer the
// pre-login commands a scanner sends (FEAT / SYST / AUTH) realistically and
// capture USER/PASS, replying 530. The FEAT reply is archetype-specific so
// the daemon behind the port is fingerprintable, not just its 220 version.
func (f *ftp) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (res Result, _ error) {
	withTimeout(conn, cfg.ReadTimeout)
	f.jit.Sleep(ctx)
	// Run the CVE signature catalog over the captured control-channel transcript
	// on every exit path so a catalogued FTP-server exploit attempt (e.g. a
	// ProFTPD mod_copy SITE CPFR/CPTO, or a path-traversal) becomes a cve:<id>.
	defer func() {
		for _, rec := range cve.MatchPayload("ftp", string(res.Payload)) {
			res.CVEHits = appendUnique(res.CVEHits, rec.ID)
		}
	}()
	banner := cfg.Banner
	if banner == "" {
		switch {
		case f.arch != nil && f.arch.FTPBanner() != "":
			banner = f.arch.FTPBanner() + "\r\n"
		case f.id != nil:
			banner = f.id.FTPBannerVariant() + "\r\n"
		default:
			banner = "220 (vsFTPd 3.0.3)\r\n"
		}
	}
	res = Result{BannerSent: banner}
	if _, err := conn.Write([]byte(banner)); err != nil {
		res.Meta = map[string]any{"write_err": err.Error()}
		return res, nil
	}
	br := bufio.NewReader(conn)

	feat := f.arch.FTPFeatures()
	if len(feat) == 0 {
		feat = defaultFTPFeatures
	}

	var user, pass string
	passAttempts := 0
	loggedIn := false
	clientIP := hostFromAddr(conn.RemoteAddr())
	var transcript []byte
	var commands []string
	res.Meta = map[string]any{}
	sess := &ftpSession{conn: conn, res: &res, files: fakefiles.Default(f.id), cwd: "/", clientIP: clientIP}
	defer sess.closeData()
loop:
	for i := 0; i < 40; i++ {
		line, err := readFTPLine(br, cfg.ReadBytes)
		if err != nil {
			break
		}
		transcript = append(transcript, line...)
		cmd, arg := splitFTPCmd(line)
		if loggedIn && cmd != "" {
			commands = append(commands, strings.TrimSpace(line))
		}
		switch cmd {
		case "USER":
			user = arg
			_, _ = conn.Write([]byte("331 Please specify the password.\r\n"))
		case "PASS":
			pass = arg
			passAttempts++
			// First attempt fails (we capture the credential); a retry is
			// accepted so the session continues and post-auth TTPs surface.
			if passAttempts == 1 {
				res.Meta["user_line"] = strings.TrimSpace(user)
				res.Meta["pass_line"] = strings.TrimSpace(pass)
				flagDefaultCred(&res, strings.TrimSpace(user), strings.TrimSpace(pass))
				_, _ = conn.Write([]byte("530 Login incorrect.\r\n"))
			} else {
				loggedIn = true
				_, _ = conn.Write([]byte("230 Login successful.\r\n"))
			}
		case "FEAT":
			_, _ = conn.Write([]byte(buildFTPFeat(feat)))
		case "SYST":
			_, _ = conn.Write([]byte("215 UNIX Type: L8\r\n"))
		case "AUTH":
			// We don't negotiate TLS; a real plaintext-only server
			// rejects AUTH TLS/SSL with 530 or 502.
			_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
		case "QUIT":
			_, _ = conn.Write([]byte("221 Goodbye.\r\n"))
			break loop
		case "":
			// ignore blank lines
		default:
			if loggedIn {
				sess.post(cmd, arg)
			} else {
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
			}
		}
	}

	if len(commands) > 0 {
		res.Meta["ftp_commands"] = commands
	}
	res.Payload = transcript
	return res, nil
}

// ftpSession carries the per-connection control + data state so the post-auth
// command handlers can change directory, open a PASV data channel, and
// list/transfer files coherently — while still flagging every abusive intent
// (upload, download, delete, SITE, FTP-bounce) for the sensor.
type ftpSession struct {
	conn     net.Conn
	res      *Result
	files    *fakefiles.Set
	cwd      string
	clientIP string
	dataLn   net.Listener // open PASV/EPSV listener awaiting the data connection
}

func (s *ftpSession) reply(line string) { _, _ = s.conn.Write([]byte(line + "\r\n")) }

func (s *ftpSession) closeData() {
	if s.dataLn != nil {
		_ = s.dataLn.Close()
		s.dataLn = nil
	}
}

// post answers one logged-in FTP command. The decoy now models a small
// virtual filesystem (internal/fakefiles): CWD/CDUP/PWD track a coherent
// working directory, and LIST/NLST/MLSD/RETR transfer believable content over
// a PASV data channel. Abusive intents are still flagged for detection; a
// retrieved bait file raises honeyfile-download; uploads are captured.
func (s *ftpSession) post(cmd, arg string) {
	switch cmd {
	case "PWD", "XPWD":
		s.reply(`257 "` + s.cwd + `" is the current directory`)
	case "CWD", "XCWD":
		s.cwd = resolveDir(s.cwd, arg)
		s.reply("250 Directory successfully changed.")
	case "CDUP":
		s.cwd = resolveDir(s.cwd, "..")
		s.reply("250 Directory successfully changed.")
	case "TYPE", "MODE", "STRU", "OPTS":
		s.reply("200 OK.")
	case "NOOP":
		s.reply("200 NOOP ok.")
	case "PASV":
		s.openPasv(false)
	case "EPSV":
		s.openPasv(true)
	case "PORT", "EPRT":
		// Active mode: a PORT/EPRT pointing at a third party is the FTP-bounce
		// scan primitive (nmap -b). We accept the command but never dial out
		// (the honeypot makes no outbound connections); a real data transfer
		// needs PASV. A third-party target is recorded as a bounce attempt.
		if ip := dataCmdIP(cmd, arg); ip != "" && ip != s.clientIP {
			flagAnomaly(s.res, "ftp-bounce-scan")
			s.res.Meta["ftp_bounce_target"] = ip
		}
		s.reply("200 " + cmd + " command successful.")
	case "LIST", "NLST", "MLSD":
		flagAnomaly(s.res, "ftp-listing")
		s.serveList(cmd)
	case "MLST":
		s.reply("250- " + s.cwd)
		s.reply("250 End")
	case "RETR":
		flagAnomaly(s.res, "ftp-download-attempt")
		s.serveRetr(arg)
	case "STOR", "STOU", "APPE":
		// Upload = malware / webshell drop attempt; capture what's pushed.
		flagAnomaly(s.res, "ftp-upload-attempt")
		s.recvStor(arg)
	case "DELE", "RMD", "XRMD":
		flagAnomaly(s.res, "ftp-delete-attempt")
		s.reply("550 Permission denied.")
	case "MKD", "XMKD":
		s.reply(`257 "` + joinPath(s.cwd, arg) + `" created.`)
	case "RNFR":
		s.reply("350 Ready for destination name.")
	case "RNTO":
		s.reply("250 Rename successful.")
	case "SITE":
		// SITE EXEC / SITE CHMOD are classic FTP RCE / privilege primitives.
		flagAnomaly(s.res, "ftp-site-command")
		s.reply("500 Unknown SITE command.")
	case "SIZE":
		if file, ok := s.files.Lookup(s.cwd, arg); ok {
			s.reply("213 " + strconv.FormatInt(file.Size, 10))
		} else {
			s.reply("550 Could not get file status.")
		}
	case "MDTM":
		if file, ok := s.files.Lookup(s.cwd, arg); ok {
			s.reply("213 " + file.ModTime.UTC().Format("20060102150405"))
		} else {
			s.reply("550 Could not get file status.")
		}
	case "STAT":
		s.reply("211 End of status.")
	case "REST":
		s.reply("350 Restart position accepted.")
	case "ALLO":
		s.reply("202 No storage allocation necessary.")
	case "ABOR":
		s.reply("226 ABOR successful.")
	default:
		s.reply("502 Command not implemented.")
	}
}

// openPasv opens the data listener and sends the 227 (PASV) or 229 (EPSV)
// reply pointing the client back at the freshly-bound ephemeral port.
func (s *ftpSession) openPasv(extended bool) {
	ln, hostPort, err := ftpPasvListen(s.conn)
	if err != nil {
		s.reply("425 Can't open data connection.")
		return
	}
	s.closeData()
	s.dataLn = ln
	if extended {
		port := ln.Addr().(*net.TCPAddr).Port
		s.reply(fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|).", port))
		return
	}
	if hostPort == "" {
		// PASV can't encode an IPv6 address (RFC 2428) — a real server tells an
		// IPv6 client to use EPSV. We keep the listener open so an immediate
		// EPSV retry can reuse it via the same data path.
		s.reply("522 Network protocol not supported, use EPSV.")
		return
	}
	s.reply("227 Entering Passive Mode (" + hostPort + ").")
}

// data accepts (and consumes) the single pending PASV data connection.
func (s *ftpSession) data() net.Conn {
	dc := ftpAcceptData(s.dataLn)
	s.dataLn = nil // PASV listener is single-use
	return dc
}

func (s *ftpSession) serveList(cmd string) {
	if s.dataLn == nil {
		s.reply("425 Use PASV first.")
		return
	}
	s.reply("150 Here comes the directory listing.")
	dc := s.data()
	if dc == nil {
		s.reply("425 Can't open data connection.")
		return
	}
	var buf bytes.Buffer
	for _, e := range s.files.List(s.cwd) {
		if e.Name == ".." {
			continue
		}
		switch cmd {
		case "NLST":
			buf.WriteString(e.Name + "\r\n")
		case "MLSD":
			buf.WriteString(formatMLSD(e) + "\r\n")
		default:
			buf.WriteString(fakefiles.FormatUnixListing(e) + "\r\n")
		}
	}
	_, _ = dc.Write(buf.Bytes())
	_ = dc.Close()
	s.reply("226 Directory send OK.")
}

func (s *ftpSession) serveRetr(name string) {
	file, ok := s.files.Lookup(s.cwd, name)
	if !ok {
		s.reply("550 Failed to open file.")
		return
	}
	// Grabbing a bait file (id_rsa, credentials.txt, …) is a far stronger
	// signal than a listing.
	if file.Bait {
		flagAnomaly(s.res, "honeyfile-download")
	}
	if s.dataLn == nil {
		s.reply("425 Use PASV first.")
		return
	}
	s.reply("150 Opening BINARY mode data connection for " + file.Name + ".")
	dc := s.data()
	if dc == nil {
		s.reply("425 Can't open data connection.")
		return
	}
	_, _ = dc.Write(file.Body(64 * 1024)) // truncated so a "48MB backup" isn't really served
	_ = dc.Close()
	s.reply("226 Transfer complete.")
}

func (s *ftpSession) recvStor(name string) {
	if s.dataLn == nil {
		s.reply("425 Use PASV first.")
		return
	}
	s.reply("150 Ok to send data.")
	dc := s.data()
	if dc == nil {
		s.reply("425 Can't open data connection.")
		return
	}
	const cap = 64 << 10
	_ = dc.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for len(buf) < cap {
		n, err := dc.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	_ = dc.Close()
	s.res.Meta["ftp_upload_name"] = safe.SanitizeForLog(joinPath(s.cwd, name))
	s.res.Meta["ftp_upload_size"] = len(buf)
	if len(buf) > 0 {
		prev := buf
		if len(prev) > 512 {
			prev = prev[:512]
		}
		s.res.Meta["ftp_upload_preview"] = safe.SanitizeForLog(string(prev))
	}
	s.reply("226 Transfer complete.")
}

// formatMLSD renders one entry as an MLSD machine-listing fact line. Our decoy
// directories use the 4096 size convention.
func formatMLSD(f fakefiles.File) string {
	typ := "file"
	if f.Size == 4096 {
		typ = "dir"
	}
	return fmt.Sprintf("type=%s;size=%d;modify=%s; %s", typ, f.Size, f.ModTime.UTC().Format("20060102150405"), f.Name)
}

// dataCmdIP extracts the dotted IP an active-mode command points at: PORT uses
// the "h1,h2,h3,h4,p1,p2" form, EPRT the "|proto|addr|port|" form.
func dataCmdIP(cmd, arg string) string {
	if cmd == "PORT" {
		return portCmdIP(arg)
	}
	parts := strings.Split(arg, "|") // EPRT |<net-prt>|<addr>|<tcp-port>|
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

// ftpPasvListen opens an ephemeral TCP listener on the control connection's
// own address family for a passive-mode data channel. It returns the listener
// and the "h1,h2,h3,h4,p1,p2" host-octet string a 227 (PASV) reply needs. The
// PASV reply format can only encode IPv4, so over an IPv6 control connection
// the host string is empty: the caller must steer the client to EPSV (229),
// which is family-agnostic. EPSV works for both families regardless.
func ftpPasvListen(conn net.Conn) (net.Listener, string, error) {
	la, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || la.IP == nil {
		la = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	}
	if v4 := la.IP.To4(); v4 != nil {
		ln, err := net.Listen("tcp", net.JoinHostPort(la.IP.String(), "0"))
		if err != nil {
			return nil, "", err
		}
		port := ln.Addr().(*net.TCPAddr).Port
		reply := fmt.Sprintf("%d,%d,%d,%d,%d,%d", v4[0], v4[1], v4[2], v4[3], port>>8, port&0xff)
		return ln, reply, nil
	}
	// IPv6 control connection — PASV can't encode the address (RFC 2428), so
	// the host string is empty to force the caller to require EPSV. Bind the
	// ephemeral data listener on the wildcard so it's reachable over whichever
	// stack the host has, without depending on a specific v6 local address.
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, "", err
	}
	return ln, "", nil
}

// ftpAcceptData accepts the single data connection on a PASV listener with a
// short deadline, then closes the listener.
func ftpAcceptData(ln net.Listener) net.Conn {
	if ln == nil {
		return nil
	}
	if tl, ok := ln.(*net.TCPListener); ok {
		_ = tl.SetDeadline(time.Now().Add(10 * time.Second))
	}
	dc, err := ln.Accept()
	_ = ln.Close()
	if err != nil {
		return nil
	}
	return dc
}

// portCmdIP extracts the dotted IP from an FTP PORT argument
// ("h1,h2,h3,h4,p1,p2"), or "" if malformed.
func portCmdIP(arg string) string {
	parts := strings.Split(arg, ",")
	if len(parts) < 4 {
		return ""
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3]
}

// buildFTPFeat renders an RFC 2389 FEAT reply: a 211-Features: header, one
// space-prefixed feature per line, then a 211 End terminator.
func buildFTPFeat(feat []string) string {
	var b strings.Builder
	b.WriteString("211-Features:\r\n")
	for _, f := range feat {
		b.WriteString(" ")
		b.WriteString(f)
		b.WriteString("\r\n")
	}
	b.WriteString("211 End\r\n")
	return b.String()
}

// splitFTPCmd splits an FTP command line into an upper-cased verb and its
// argument.
func splitFTPCmd(line string) (string, string) {
	line = strings.TrimRight(line, "\r\n")
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return strings.ToUpper(line[:i]), strings.TrimSpace(line[i+1:])
	}
	return strings.ToUpper(strings.TrimSpace(line)), ""
}

func readFTPLine(br *bufio.Reader, cap int) (string, error) {
	if cap <= 0 {
		cap = 256
	}
	var buf bytes.Buffer
	for buf.Len() < cap {
		b, err := br.ReadByte()
		if err != nil {
			return buf.String(), err
		}
		buf.WriteByte(b)
		if b == '\n' {
			break
		}
	}
	return buf.String(), nil
}
