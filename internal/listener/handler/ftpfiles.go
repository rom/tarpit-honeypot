package handler

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/creds"
	"github.com/rom/tarpit-honeypot/internal/fakefiles"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/safe"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// ftpFiles is a medium-interaction FTP server that allows anonymous
// login (or a configured default-credential accept policy) and then
// serves a deterministic tree of decoy files from internal/fakefiles.
// Unlike the plain `ftp` handler — which captures USER/PASS and always
// rejects — this one lets the attacker actually browse + download so
// the sensor captures the full session: which directories they list,
// which files they fetch, and (high signal) whether they grab one of
// the bait files (id_rsa, credentials.txt, database_dump.sql).
//
// We implement the control channel + passive-mode (PASV) data channel.
// LIST / NLST / RETR / CWD / PWD / TYPE / SIZE / SYST / FEAT / QUIT are
// supported; everything else gets a polite 502. Active mode (PORT) is
// accepted but we still open our own listener for the data transfer
// (most clients tolerate this; scanners almost always use PASV anyway).
//
// Every retrieval of a bait file raises the `honeyfile-download`
// anomaly. A login with a known default credential raises
// `default-credential-attempt`.
type ftpFiles struct {
	id          *identity.Identity
	arch        *archetype.Profile
	acceptCreds string
	tlsMgr      *certManager // explicit FTPS (AUTH TLS / AUTH SSL); nil = plaintext only
}

func (f *ftpFiles) Name() string { return "ftp_files" }

func (f *ftpFiles) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	banner := cfg.Banner
	if banner == "" {
		if f.arch != nil && f.arch.FTPBanner() != "" {
			banner = f.arch.FTPBanner() + "\r\n"
		} else {
			banner = "220 (vsFTPd 3.0.5)\r\n"
		}
	}
	if _, err := conn.Write([]byte(banner)); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = banner

	files := fakefiles.Default(f.id)
	br := bufio.NewReader(conn)

	var (
		user       string
		pass       string
		authed     bool
		cwd        = "/"
		commands   []string
		retrieved  []string
		upload     []byte // last uploaded file, surfaced as res.Payload for YARA/classify/persist
		listenAddr string
		dataLn     net.Listener
		protP      bool // FTPS PROT P: the data channel is TLS too
	)
	defer func() {
		if dataLn != nil {
			_ = dataLn.Close()
		}
	}()
	// dataWrap secures an accepted PASV data connection when FTPS PROT P is in
	// effect; a no-op otherwise. Returns nil on a failed handshake.
	dataWrap := func(c net.Conn) net.Conn { return c }
	if f.tlsMgr != nil {
		dataWrap = func(c net.Conn) net.Conn {
			if !protP {
				return c
			}
			nc, err := startTLS(ctx, c, f.tlsMgr, cfg.ID, tlsHosts(cfg), f.arch)
			if err != nil {
				return nil
			}
			return nc
		}
	}

	// FTP sessions are short; cap the command count so a stuck client
	// can't hold the worker forever (timeouts also bound this).
	const maxCommands = 64
	for i := 0; i < maxCommands; i++ {
		line, err := readBoundedLineFromReader(br, 1024)
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		commands = append(commands, safe.SanitizeForLog(line))
		cmd, arg := splitFTPCommand(line)
		flagFTPGlobDoS(&res, cmd, arg)

		switch cmd {
		case "USER":
			user = arg
			_, _ = conn.Write([]byte("331 Please specify the password.\r\n"))
		case "PASS":
			pass = arg
			res.Meta["user"] = safe.SanitizeForLog(user)
			res.Meta["pass"] = safe.SanitizeForLog(arg)
			if c, ok := creds.Match(user, arg); ok {
				flagAnomaly(&res, "default-credential-attempt")
				res.Meta["default_cred_category"] = c.Category
			}
			// Anonymous always allowed; otherwise apply accept policy.
			anon := strings.EqualFold(user, "anonymous") || strings.EqualFold(user, "ftp")
			if anon || creds.Accepts(f.acceptCreds, user, arg) {
				authed = true
				_, _ = conn.Write([]byte("230 Login successful.\r\n"))
			} else {
				_, _ = conn.Write([]byte("530 Login incorrect.\r\n"))
			}
		case "SYST":
			_, _ = conn.Write([]byte("215 UNIX Type: L8\r\n"))
		case "FEAT":
			// Advertise the full vsftpd FEAT set (+ explicit-FTPS while plaintext)
			// so the daemon is fingerprintable, not just its 220 banner.
			fl := defaultFTPFeatures
			if f.tlsMgr != nil && !alreadyTLS(conn) {
				fl = append([]string{"AUTH TLS", "AUTH SSL", "PBSZ", "PROT"}, fl...)
			}
			_, _ = conn.Write([]byte(buildFTPFeat(fl)))
		case "AUTH":
			// Explicit FTPS (RFC 4217): AUTH TLS / AUTH SSL upgrades the control
			// channel; USER/PASS + the browse/download session are then captured
			// over the encrypted channel.
			mech := strings.ToUpper(strings.TrimSpace(arg))
			switch {
			case f.tlsMgr == nil || alreadyTLS(conn):
				_, _ = conn.Write([]byte("502 Command not implemented.\r\n"))
			case mech == "TLS" || mech == "SSL" || mech == "TLS-C" || mech == "SSL-C" || mech == "TLS-P":
				detectSTARTTLSInjection(br, &res, "CVE-2011-1430")
				_, _ = conn.Write([]byte("234 AUTH " + mech + " successful. Initializing secure connection.\r\n"))
				nc, err := startTLS(ctx, conn, f.tlsMgr, cfg.ID, tlsHosts(cfg), f.arch)
				if err != nil {
					res.Meta["tls_err"] = err.Error()
					i = maxCommands // end the session
					break
				}
				conn = nc
				br = bufio.NewReader(conn)
				withTimeout(conn, cfg.ReadTimeout)
				res.Meta["tls"] = true
				res.Meta["ftps"] = true
				res.Meta["ftps_auth"] = mech
			default:
				_, _ = conn.Write([]byte("504 Unknown security mechanism.\r\n"))
			}
		case "PBSZ":
			_, _ = conn.Write([]byte("200 PBSZ=0\r\n"))
		case "PROT":
			switch strings.ToUpper(strings.TrimSpace(arg)) {
			case "P":
				protP = true
				_, _ = conn.Write([]byte("200 PROT now Private.\r\n"))
			case "C", "":
				protP = false
				_, _ = conn.Write([]byte("200 PROT now Clear.\r\n"))
			default:
				_, _ = conn.Write([]byte("504 PROT level not supported.\r\n"))
			}
		case "PWD", "XPWD":
			_, _ = conn.Write([]byte("257 \"" + cwd + "\" is the current directory\r\n"))
		case "TYPE":
			_, _ = conn.Write([]byte("200 Switching to " + typeName(arg) + " mode.\r\n"))
		case "CWD", "XCWD":
			if !authed {
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				break
			}
			cwd = resolveDir(cwd, arg)
			_, _ = conn.Write([]byte("250 Directory successfully changed.\r\n"))
		case "CDUP":
			cwd = "/"
			_, _ = conn.Write([]byte("250 Directory successfully changed.\r\n"))
		case "PASV":
			if !authed {
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				break
			}
			ln, hostPortReply, err := ftpPasvListen(conn)
			if err != nil {
				_, _ = conn.Write([]byte("425 Can't open data connection.\r\n"))
				break
			}
			if dataLn != nil {
				_ = dataLn.Close()
			}
			dataLn = ln
			listenAddr = ln.Addr().String()
			_, _ = conn.Write([]byte("227 Entering Passive Mode (" + hostPortReply + ").\r\n"))
		case "PORT":
			// Accept but note — we still serve via our own PASV listener
			// on the next data command if the client also issued PASV.
			_, _ = conn.Write([]byte("200 PORT command successful.\r\n"))
		case "LIST", "NLST":
			if !authed {
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				break
			}
			f.serveList(conn, dataLn, dataWrap, files, cwd, cmd == "NLST")
			dataLn = nil // PASV listener is single-use
		case "SIZE":
			if file, ok := files.Lookup(cwd, arg); ok {
				_, _ = conn.Write([]byte("213 " + strconv.FormatInt(file.Size, 10) + "\r\n"))
			} else {
				_, _ = conn.Write([]byte("550 Could not get file size.\r\n"))
			}
		case "RETR":
			if !authed {
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				break
			}
			name := arg
			file, ok := files.Lookup(cwd, name)
			if !ok {
				_, _ = conn.Write([]byte("550 Failed to open file.\r\n"))
				break
			}
			retrieved = append(retrieved, safe.SanitizeForLog(joinPath(cwd, name)))
			if file.Bait {
				flagAnomaly(&res, "honeyfile-download")
			}
			f.serveRetr(conn, dataLn, dataWrap, file)
			dataLn = nil
		case "STOR", "STOU", "APPE":
			// Anonymous/authed upload: capture the dropped file so it can be
			// checksummed + classified + YARA-scanned (malware / webshell drop).
			if !authed {
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				break
			}
			flagAnomaly(&res, "ftp-upload-attempt")
			buf := f.recvUpload(conn, dataLn, dataWrap)
			dataLn = nil
			full := joinPath(cwd, arg)
			res.Meta["ftp_upload_name"] = safe.SanitizeForLog(full)
			res.Meta["ftp_upload_size"] = len(buf)
			if len(buf) > 0 {
				prev := buf
				if len(prev) > 512 {
					prev = prev[:512]
				}
				res.Meta["ftp_upload_preview"] = safe.SanitizeForLog(string(prev))
				ftpAnalyzeUpload(&res, full, buf)
				upload = buf
			}
		case "MKD", "XMKD":
			_, _ = conn.Write([]byte("257 \"" + joinPath(cwd, arg) + "\" created.\r\n"))
		case "DELE", "RMD", "XRMD":
			flagAnomaly(&res, "ftp-delete-attempt")
			_, _ = conn.Write([]byte("550 Permission denied.\r\n"))
		case "QUIT":
			_, _ = conn.Write([]byte("221 Goodbye.\r\n"))
			i = maxCommands // break the loop
		case "NOOP":
			_, _ = conn.Write([]byte("200 NOOP ok.\r\n"))
		default:
			_, _ = conn.Write([]byte("502 Command not implemented.\r\n"))
		}
		if cmd == "QUIT" {
			break
		}
	}

	if len(commands) > 0 {
		res.Meta["commands"] = commands
	}
	if len(retrieved) > 0 {
		res.Meta["retrieved"] = retrieved
	}
	res.Meta["authed"] = authed
	// Scanner / client fingerprint from the anonymous credential presented.
	if tools := toolfp.IdentifyFTP(user, pass); len(tools) > 0 {
		res.Meta["tools"] = tools
		flagAnomaly(&res, "tool:"+tools[0])
	}
	// Surface an uploaded file as the payload so the sensor classifies + YARA-
	// scans + persists it; otherwise keep the command transcript as the payload.
	if len(upload) > 0 {
		res.Payload = upload
	} else if len(commands) > 0 {
		res.Payload = []byte(strings.Join(commands, "\n"))
	}
	_ = listenAddr
	return res, nil
}

// recvUpload accepts the pending PASV data connection and drains a bounded copy
// of an uploaded file (TLS-wrapped under FTPS PROT P).
func (f *ftpFiles) recvUpload(conn net.Conn, ln net.Listener, wrap func(net.Conn) net.Conn) []byte {
	_, _ = conn.Write([]byte("150 Ok to send data.\r\n"))
	dc := ftpAcceptData(ln)
	if dc != nil {
		dc = wrap(dc)
	}
	if dc == nil {
		_, _ = conn.Write([]byte("425 Can't open data connection.\r\n"))
		return nil
	}
	buf := readUploadBytes(dc, 64<<10)
	_ = dc.Close()
	_, _ = conn.Write([]byte("226 Transfer complete.\r\n"))
	return buf
}

func (f *ftpFiles) serveList(conn net.Conn, ln net.Listener, wrap func(net.Conn) net.Conn, files *fakefiles.Set, dir string, nameOnly bool) {
	_, _ = conn.Write([]byte("150 Here comes the directory listing.\r\n"))
	dc := ftpAcceptData(ln)
	if dc != nil {
		dc = wrap(dc) // TLS-wrap under FTPS PROT P
	}
	if dc == nil {
		_, _ = conn.Write([]byte("425 Can't open data connection.\r\n"))
		return
	}
	var buf bytes.Buffer
	for _, entry := range files.List(dir) {
		if entry.Name == ".." {
			continue
		}
		if nameOnly {
			buf.WriteString(entry.Name + "\r\n")
		} else {
			buf.WriteString(fakefiles.FormatUnixListing(entry) + "\r\n")
		}
	}
	_, _ = dc.Write(buf.Bytes())
	_ = dc.Close()
	_, _ = conn.Write([]byte("226 Directory send OK.\r\n"))
}

func (f *ftpFiles) serveRetr(conn net.Conn, ln net.Listener, wrap func(net.Conn) net.Conn, file fakefiles.File) {
	_, _ = conn.Write([]byte("150 Opening BINARY mode data connection for " + file.Name + ".\r\n"))
	dc := ftpAcceptData(ln)
	if dc != nil {
		dc = wrap(dc) // TLS-wrap under FTPS PROT P
	}
	if dc == nil {
		_, _ = conn.Write([]byte("425 Can't open data connection.\r\n"))
		return
	}
	// Cap the served body so a decoy "48 MB backup" doesn't actually
	// stream 48 MB — the attacker sees the SIZE header but the
	// transfer is truncated. 64 KiB is plenty to look real.
	body := file.Body(64 * 1024)
	_, _ = dc.Write(body)
	_ = dc.Close()
	_, _ = conn.Write([]byte("226 Transfer complete.\r\n"))
}

func splitFTPCommand(line string) (cmd, arg string) {
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return strings.ToUpper(line[:i]), strings.TrimSpace(line[i+1:])
	}
	return strings.ToUpper(line), ""
}

func typeName(a string) string {
	if strings.HasPrefix(strings.ToUpper(a), "A") {
		return "ASCII"
	}
	return "Binary"
}

// resolveDir applies a CWD argument to the current directory. We only
// model the top level + the canned subdirs, so anything that isn't a
// known subdir just resolves to that path string (the next LIST will
// return empty, which is fine).
func resolveDir(cwd, arg string) string {
	if arg == "" {
		return cwd
	}
	if arg == ".." || arg == "/.." {
		return "/"
	}
	if strings.HasPrefix(arg, "/") {
		return cleanDir(arg)
	}
	return cleanDir(joinPath(cwd, arg))
}

func joinPath(dir, name string) string {
	if strings.HasPrefix(name, "/") {
		return cleanDir(name)
	}
	if dir == "/" || dir == "" {
		return "/" + name
	}
	return dir + "/" + name
}

// cleanDir collapses a path to a single leading slash + no trailing
// slash, and strips any ".." traversal so a CWD ../../etc can't escape
// our virtual root (defense-in-depth — fakefiles only knows canned
// dirs anyway).
func cleanDir(p string) string {
	parts := strings.Split(p, "/")
	var stack []string
	for _, seg := range parts {
		switch seg {
		case "", ".":
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, seg)
		}
	}
	return "/" + strings.Join(stack, "/")
}
