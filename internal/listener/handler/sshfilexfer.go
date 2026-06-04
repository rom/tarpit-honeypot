package handler

// Lightweight SFTP / SCP "beginning" emulation for the ssh_interactive handler.
// Credentials + client fingerprint are already captured by the SSH auth layer;
// these only emulate enough of the file-transfer start so an sftp/scp client
// believes it connected — long enough to record WHAT the attacker tried (the
// paths probed, the filename/size of an upload, a bounded chunk of the dropper)
// before denying. No real file content is ever served.

import (
	"bufio"
	"encoding/binary"
	"io"
	"strconv"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/safe"
)

// SFTP v3 packet types (subset we answer).
const (
	sftpFxpInit     = 1
	sftpFxpVersion  = 2
	sftpFxpOpen     = 3
	sftpFxpRead     = 5
	sftpFxpLstat    = 7
	sftpFxpOpendir  = 11
	sftpFxpRealpath = 16
	sftpFxpStat     = 17
	sftpFxpStatus   = 101
	sftpFxpName     = 104
)

const (
	sftpStatusOK         = 0
	sftpStatusPermission = 3
)

// sshReqString decodes the single SSH string at the start of an exec /
// subsystem request payload (uint32 length + bytes).
func sshReqString(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := int(binary.BigEndian.Uint32(payload))
	if n < 0 || n > len(payload)-4 {
		return ""
	}
	return string(payload[4 : 4+n])
}

// isSCPCommand reports whether an exec command line invokes scp (the server side
// of an scp transfer, e.g. `scp -t /tmp` or `scp -f /etc/passwd`).
func isSCPCommand(cmd string) bool {
	f := strings.Fields(cmd)
	return len(f) > 0 && (f[0] == "scp" || strings.HasSuffix(f[0], "/scp"))
}

// serveSFTPBeginning answers the SFTP INIT with VERSION 3, then records every
// path the client asks about and denies each operation. The client sees a live
// SFTP server (so it proceeds and reveals its intent) but never gets data.
func serveSFTPBeginning(ch io.ReadWriter, res *Result) {
	res.Meta["ssh_subsystem"] = "sftp"
	flagAnomaly(res, "sftp-session")
	br := bufio.NewReader(ch)
	var paths []string
	addPath := func(p string) {
		if p != "" && len(paths) < 64 {
			paths = append(paths, safe.SanitizeForLog(p))
		}
	}
	for i := 0; i < 64; i++ {
		ptype, body, err := readSFTPPacket(br)
		if err != nil {
			break
		}
		if ptype == sftpFxpInit {
			writeSFTPPacket(ch, sftpFxpVersion, sftpU32(3)) // we speak v3
			continue
		}
		if len(body) < 4 {
			break
		}
		reqID := binary.BigEndian.Uint32(body)
		rest := body[4:]
		switch ptype {
		case sftpFxpRealpath:
			p := cleanFxPath(sftpReadString(rest))
			addPath(p)
			writeSFTPName(ch, reqID, p)
		case sftpFxpOpen, sftpFxpOpendir, sftpFxpStat, sftpFxpLstat, sftpFxpRead:
			addPath(cleanFxPath(sftpReadString(rest)))
			writeSFTPStatus(ch, reqID, sftpStatusPermission, "Permission denied")
		default:
			writeSFTPStatus(ch, reqID, sftpStatusPermission, "Permission denied")
		}
	}
	if len(paths) > 0 {
		res.Meta["sftp_paths"] = paths
	}
}

func readSFTPPacket(br *bufio.Reader) (byte, []byte, error) {
	var lenb [4]byte
	if _, err := io.ReadFull(br, lenb[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(lenb[:])
	if n == 0 || n > 256*1024 { // bound a hostile length
		return 0, nil, io.ErrUnexpectedEOF
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(br, buf); err != nil {
		return 0, nil, err
	}
	return buf[0], buf[1:], nil
}

func writeSFTPPacket(w io.Writer, ptype byte, body []byte) {
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(body)+1))
	hdr[4] = ptype
	_, _ = w.Write(hdr[:])
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

func sftpU32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func sftpReadString(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	n := binary.BigEndian.Uint32(b)
	if int64(n) > int64(len(b)-4) || n > 4096 {
		return ""
	}
	return string(b[4 : 4+n])
}

func sftpStringBytes(s string) []byte {
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	copy(b[4:], s)
	return b
}

func cleanFxPath(p string) string {
	if p == "" || p == "." {
		return "/"
	}
	return p
}

func writeSFTPStatus(w io.Writer, reqID, code uint32, msg string) {
	body := sftpU32(reqID)
	body = append(body, sftpU32(code)...)
	body = append(body, sftpStringBytes(msg)...)
	body = append(body, sftpStringBytes("")...) // language tag
	writeSFTPPacket(w, sftpFxpStatus, body)
}

func writeSFTPName(w io.Writer, reqID uint32, path string) {
	body := sftpU32(reqID)
	body = append(body, sftpU32(1)...)            // count = 1
	body = append(body, sftpStringBytes(path)...) // filename
	body = append(body, sftpStringBytes(path)...) // longname
	body = append(body, sftpU32(0)...)            // attrs flags = 0 (none)
	writeSFTPPacket(w, sftpFxpName, body)
}

// serveSCPBeginning emulates the start of an scp transfer. For an upload
// (`scp -t`) it acks and captures the file header — and a bounded chunk of the
// content (the dropper) as loot — then ends; for a download (`scp -f`) it
// records the requested path and denies. No real file content is served.
func serveSCPBeginning(ch io.ReadWriter, res *Result, cmd string) {
	flagAnomaly(res, "scp-transfer")
	target := scpTarget(cmd)
	if target != "" {
		res.Meta["scp_path"] = safe.SanitizeForLog(target)
	}
	br := bufio.NewReader(ch)
	switch {
	case scpHasFlag(cmd, 't'): // sink: client uploads to us
		res.Meta["scp_mode"] = "upload"
		flagAnomaly(res, "scp-upload-attempt")
		_, _ = ch.Write([]byte{0}) // ready
		line, err := readSCPLine(br)
		if err != nil {
			return
		}
		mode, size, name, ok := parseSCPControl(line)
		if !ok {
			_, _ = ch.Write([]byte{1}) // warning byte — soft error
			return
		}
		res.Meta["scp_filename"] = safe.SanitizeForLog(name)
		res.Meta["scp_filemode"] = mode
		res.Meta["scp_filesize"] = size
		_, _ = ch.Write([]byte{0}) // ack header — client now streams the body
		// Capture a bounded chunk of the upload (the dropper) as loot.
		want := size
		if want <= 0 || want > 64*1024 {
			want = 64 * 1024
		}
		buf := make([]byte, want)
		if n, _ := io.ReadFull(br, buf); n > 0 {
			res.Payload = append(res.Payload, buf[:n]...)
			flagAnomaly(res, "scp-upload")
		}
		_, _ = ch.Write([]byte{1}) // end with a warning so the client stops
	case scpHasFlag(cmd, 'f'): // source: client downloads from us
		res.Meta["scp_mode"] = "download"
		flagAnomaly(res, "scp-download-attempt")
		// Error byte (\x02) + message — the client prints it and aborts.
		_, _ = ch.Write(append([]byte{2}, []byte("scp: "+target+": Permission denied\n")...))
	default:
		res.Meta["scp_mode"] = "unknown"
	}
}

func scpHasFlag(cmd string, f byte) bool {
	for _, tok := range strings.Fields(cmd) {
		if strings.HasPrefix(tok, "-") && strings.IndexByte(tok, f) > 0 {
			return true
		}
	}
	return false
}

// scpTarget returns the path argument of an scp command (the last non-flag,
// non-"scp" token).
func scpTarget(cmd string) string {
	toks := strings.Fields(cmd)
	for i := len(toks) - 1; i >= 0; i-- {
		if toks[i] != "scp" && !strings.HasPrefix(toks[i], "-") {
			return toks[i]
		}
	}
	return ""
}

func readSCPLine(br *bufio.Reader) (string, error) {
	var b []byte
	for len(b) < 1024 {
		c, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if c == '\n' {
			break
		}
		b = append(b, c)
	}
	return string(b), nil
}

// parseSCPControl parses an scp "C<mode> <size> <name>" sink header.
func parseSCPControl(line string) (mode string, size int, name string, ok bool) {
	if len(line) < 2 || line[0] != 'C' {
		return "", 0, "", false
	}
	parts := strings.SplitN(line[1:], " ", 3)
	if len(parts) != 3 {
		return "", 0, "", false
	}
	sz, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, "", false
	}
	return parts[0], sz, parts[2], true
}
