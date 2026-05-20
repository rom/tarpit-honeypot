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
	gotUser, gotPass := false, false
	var transcript []byte
loop:
	for i := 0; i < 24; i++ {
		line, err := readFTPLine(br, cfg.ReadBytes)
		if err != nil {
			break
		}
		transcript = append(transcript, line...)
		cmd, arg := splitFTPCmd(line)
		switch cmd {
		case "USER":
			user, gotUser = arg, true
			_, _ = conn.Write([]byte("331 Please specify the password.\r\n"))
		case "PASS":
			pass, gotPass = arg, true
			_, _ = conn.Write([]byte("530 Login incorrect.\r\n"))
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
			_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
		}
		if gotUser && gotPass {
			break
		}
	}

	res.Meta = map[string]any{
		"user_line": strings.TrimSpace(user),
		"pass_line": strings.TrimSpace(pass),
	}
	res.Payload = transcript
	flagDefaultCred(&res, strings.TrimSpace(user), strings.TrimSpace(pass))
	return res, nil
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
