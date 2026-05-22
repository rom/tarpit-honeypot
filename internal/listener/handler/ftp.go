package handler

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
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
func (f *ftp) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	f.jit.Sleep(ctx)
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
	res := Result{BannerSent: banner}
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
				f.handlePostAuth(conn, &res, cmd, arg, clientIP)
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

// handlePostAuth answers a logged-in FTP command believably (without ever
// opening a data connection or touching the filesystem) and flags the
// intent: uploads (malware drop), downloads, SITE EXEC, deletes, and the
// FTP-bounce PORT primitive.
func (f *ftp) handlePostAuth(conn net.Conn, res *Result, cmd, arg, clientIP string) {
	switch cmd {
	case "PWD", "XPWD":
		_, _ = conn.Write([]byte("257 \"/\" is the current directory\r\n"))
	case "CWD", "XCWD", "CDUP":
		_, _ = conn.Write([]byte("250 Directory successfully changed.\r\n"))
	case "TYPE", "MODE", "STRU", "NOOP", "OPTS":
		_, _ = conn.Write([]byte("200 OK.\r\n"))
	case "PASV", "EPSV":
		// Advertise passive mode but never actually open the data port.
		_, _ = conn.Write([]byte("227 Entering Passive Mode (127,0,0,1,0,0).\r\n"))
	case "PORT", "EPRT":
		// Active mode: a PORT pointing at a third party is the FTP-bounce
		// scan primitive (CWE-... / nmap -b).
		if ip := portCmdIP(arg); ip != "" && ip != clientIP {
			flagAnomaly(res, "ftp-bounce-scan")
			res.Meta["ftp_bounce_target"] = ip
		}
		_, _ = conn.Write([]byte("200 PORT command successful.\r\n"))
	case "LIST", "NLST", "MLSD", "MLST":
		flagAnomaly(res, "ftp-listing")
		_, _ = conn.Write([]byte("425 Failed to establish connection.\r\n"))
	case "RETR":
		flagAnomaly(res, "ftp-download-attempt")
		_, _ = conn.Write([]byte("550 Failed to open file.\r\n"))
	case "STOR", "STOU", "APPE":
		// Upload = malware / webshell drop attempt.
		flagAnomaly(res, "ftp-upload-attempt")
		_, _ = conn.Write([]byte("553 Could not create file.\r\n"))
	case "DELE", "RMD", "XRMD":
		flagAnomaly(res, "ftp-delete-attempt")
		_, _ = conn.Write([]byte("550 Permission denied.\r\n"))
	case "MKD", "XMKD":
		_, _ = conn.Write([]byte("257 Directory created.\r\n"))
	case "RNFR":
		_, _ = conn.Write([]byte("350 Ready for destination name.\r\n"))
	case "RNTO":
		_, _ = conn.Write([]byte("250 Rename successful.\r\n"))
	case "SITE":
		// SITE EXEC / SITE CHMOD are classic FTP RCE / privilege primitives.
		flagAnomaly(res, "ftp-site-command")
		_, _ = conn.Write([]byte("500 Unknown SITE command.\r\n"))
	case "SIZE", "MDTM":
		_, _ = conn.Write([]byte("550 Could not get file status.\r\n"))
	default:
		_, _ = conn.Write([]byte("502 Command not implemented.\r\n"))
	}
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
