package handler

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// pjl emulates an HP JetDirect raw-print port (TCP 9100) speaking PJL
// (Printer Job Language) — the protocol network printers/MFPs expose
// there, and the primary channel printer-attack tools (PRET, the Printer
// Exploitation Toolkit) drive.
//
// It runs an interactive loop: it answers the @PJL INFO recon queries
// with a believable printer identity (so a scanner / PRET's `id` keeps
// going and reveals more), captures submitted jobs/commands, and flags a
// broad set of printer-specific abuse:
//
//   - filesystem access (FSDOWNLOAD/FSUPLOAD/FSDELETE/FSDIRLIST/...) and
//     the destructive FSINIT (format) + path-traversal escapes;
//   - panel/display defacement (RDYMSG/OPMSG/STMSG — prank/extortion);
//   - config writes (SET/DEFAULT), password set/lock + credential reads;
//   - NVRAM access, device-management commands (DMCMD/DMINFO);
//   - embedded PostScript abuse inside the job stream (exitserver
//     persistence, file ops, set*params, raw %disk%/%os% device access).
//
// Nothing is printed and no real filesystem / NVRAM is touched — every
// dangerous operation is recognized and logged, never performed.
type pjl struct{ arch *archetype.Profile }

func (p *pjl) Name() string { return "pjl" }

// Session bounds: enough to sustain a PRET session and capture a real job
// without letting a single connection grow unbounded.
const (
	pjlMaxBytes = 256 * 1024
	pjlMaxLines = 4096
	// pjlMaxSession bounds the whole connection regardless of how slowly a
	// client trickles bytes (anti-slowloris). Generous enough for a real
	// interactive PRET session.
	pjlMaxSession = 2 * time.Minute
)

func (p *pjl) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	model := p.model()

	readCap := cfg.ReadBytes
	if readCap <= 0 || readCap > 65535 {
		readCap = 8192
	}
	buf := make([]byte, readCap)

	var (
		carry    string // partial trailing line carried across reads
		jobText  strings.Builder
		total    int
		lines    int
		pjlSeen  bool
		jobSeen  bool
		infoCats []string
	)
	// Absolute session deadline. Per-read deadlines alone don't bound a
	// slowloris client that trickles one byte just before each read_timeout
	// — it could hold the goroutine/socket open until pjlMaxBytes (days at
	// the default timeout). Cap the whole interaction; legitimate scanner /
	// PRET sessions finish well within this.
	sessionEnd := time.Now().Add(pjlMaxSession)
	for total < pjlMaxBytes && lines < pjlMaxLines && time.Now().Before(sessionEnd) {
		deadline := time.Now().Add(cfg.ReadTimeout)
		if deadline.After(sessionEnd) {
			deadline = sessionEnd
		}
		_ = conn.SetReadDeadline(deadline)
		_ = conn.SetWriteDeadline(deadline)
		n, err := conn.Read(buf)
		if n > 0 {
			total += n
			if len(res.Payload) < pjlMaxBytes {
				res.Payload = append(res.Payload, buf[:n]...)
			}
			chunk := carry + string(buf[:n])
			parts := strings.Split(chunk, "\n")
			carry = parts[len(parts)-1]
			var out strings.Builder
			for _, raw := range parts[:len(parts)-1] {
				lines++
				line := strings.TrimRight(raw, "\r")
				if strings.Contains(strings.ToUpper(line), "@PJL") {
					pjlSeen = true
					p.processPJL(line, model, &out, &res, &infoCats)
				} else if line != "" {
					jobSeen = true
					appendBounded(&jobText, line)
				}
			}
			if out.Len() > 0 {
				if _, werr := conn.Write([]byte(out.String())); werr != nil {
					res.Meta["write_err"] = werr.Error()
				} else {
					res.BannerSent = out.String()
				}
			}
		}
		if err != nil {
			break
		}
	}
	// Trailing partial line (no newline before close).
	if line := strings.TrimRight(carry, "\r"); line != "" {
		if strings.Contains(strings.ToUpper(line), "@PJL") {
			pjlSeen = true
			var out strings.Builder
			p.processPJL(line, model, &out, &res, &infoCats)
			if out.Len() > 0 {
				if _, werr := conn.Write([]byte(out.String())); werr == nil {
					res.BannerSent = out.String()
				}
			}
		} else {
			jobSeen = true
			appendBounded(&jobText, line)
		}
	}

	if len(infoCats) > 0 {
		res.Meta["pjl_info"] = infoCats
		flagAnomaly(&res, "printer-info-query")
	}
	if pjlSeen {
		flagAnomaly(&res, "pjl-command")
	}
	if jobSeen {
		flagAnomaly(&res, "printer-job-received")
		job := jobText.String()
		scanPostScript(job, &res)
		scanZPL(job, &res)
		scanPCL(job, &res)
	}
	if !pjlSeen && !jobSeen {
		res.Meta["read_err"] = "no data"
	}
	return res, nil
}

func (p *pjl) model() string {
	model := "HP LaserJet"
	if p.arch != nil {
		if d := p.arch.SNMPSysDescr(); d != "" {
			model = d
		} else if t := p.arch.HTTPTitle(); t != "" {
			model = t
		}
	}
	return model
}

// processPJL classifies one @PJL command line: it appends any believable
// response to out and records the appropriate anomaly markers on res.
func (p *pjl) processPJL(line, model string, out *strings.Builder, res *Result, infoCats *[]string) {
	up := strings.ToUpper(line)
	// Keyword is the token right after @PJL.
	kw := pjlKeyword(up)

	switch kw {
	case "INFO":
		cat := pjlArg(up, "INFO")
		*infoCats = appendUnique(*infoCats, cat)
		out.WriteString(pjlInfoResponse(cat, model))
		return
	case "RDYMSG":
		res.Meta["pjl_rdymsg"] = safe.SanitizeForLog(line)
		flagAnomaly(res, "printer-rdymsg-set")
		return
	case "OPMSG", "STMSG":
		res.Meta["pjl_opmsg"] = safe.SanitizeForLog(line)
		flagAnomaly(res, "printer-message-injection")
		return
	case "FSINIT":
		// Reformat the printer's mass-storage filesystem — destructive.
		flagAnomaly(res, "printer-filesystem-format")
		flagAnomaly(res, "printer-filesystem-access")
		return
	case "FSDOWNLOAD", "FSUPLOAD", "FSDELETE", "FSDIRLIST", "FSMKDIR",
		"FSQUERY", "FSAPPEND":
		flagAnomaly(res, "printer-filesystem-access")
		if pjlPathTraversal(line) {
			flagAnomaly(res, "printer-path-traversal")
		}
		// Decoy: answer the read-style ops with believable fake contents so
		// a tool (PRET `ls` / `get` / `fuzz`) keeps walking our "filesystem"
		// and revealing intent. The honeypot has no real FS behind this.
		switch kw {
		case "FSDIRLIST":
			out.WriteString(pjlFSDirList(line))
		case "FSUPLOAD":
			out.WriteString(pjlFSUpload(line))
		case "FSQUERY":
			out.WriteString(pjlFSQuery(line))
		}
		return
	case "ENTER":
		// @PJL ENTER LANGUAGE=POSTSCRIPT|PCL — switching the stream into a
		// scripting language is how PostScript/PCL attacks get injected.
		flagAnomaly(res, "printer-language-switch")
		if lang := pjlValueOf(line, "LANGUAGE"); lang != "" {
			res.Meta["pjl_language"] = lang
		}
		return
	case "EXECUTE", "UPGRADE":
		// EXECUTE = vendor command exec; UPGRADE = firmware push.
		flagAnomaly(res, "printer-firmware-upload")
		return
	case "SET", "DEFAULT":
		switch {
		case pjlMentionsPassword(up):
			flagAnomaly(res, "printer-password-set")
		case strings.Contains(up, "SERVICEMODE") || strings.Contains(up, "SERVICE MODE"):
			flagAnomaly(res, "printer-servicemode")
		default:
			flagAnomaly(res, "printer-config-set")
		}
		return
	case "INQUIRE", "DINQUIRE":
		if pjlMentionsPassword(up) {
			flagAnomaly(res, "printer-credential-access")
		}
		return
	case "JOB", "EOJ":
		if pjlMentionsPassword(up) {
			flagAnomaly(res, "printer-auth-attempt")
			if pw := pjlPasswordValue(line); pw != "" {
				res.Meta["pjl_password"] = safe.SanitizeForLog(pw)
			}
		}
		return
	case "DMCMD", "DMINFO":
		flagAnomaly(res, "printer-dmcmd")
		return
	}
	// Catch keywords we don't switch on but still matter.
	switch {
	case strings.Contains(up, "NVRAM"):
		flagAnomaly(res, "printer-nvram-access")
	case strings.Contains(up, "PASSWORD"):
		flagAnomaly(res, "printer-password-set")
	}
}

// pjlInfoResponse returns a believable @PJL INFO reply for the queried
// category. Unknown categories get a generic empty-but-valid reply so the
// scanner doesn't error out. The trailing \x0c (FF) is the PJL response
// terminator real printers send.
func pjlInfoResponse(cat, model string) string {
	switch cat {
	case "ID":
		return "@PJL INFO ID\r\n\"" + safe.SanitizeHeader(model) + "\"\r\n\x0c"
	case "STATUS":
		return "@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY=\"Ready\"\r\nONLINE=TRUE\r\n\x0c"
	case "CONFIG":
		return "@PJL INFO CONFIG\r\nIN TRAYS [2 ENUMERATED]\r\nOUT TRAYS [1 ENUMERATED]\r\n\x0c"
	case "VARIABLES":
		return "@PJL INFO VARIABLES\r\nCOPIES=1 [2 RANGE]\r\nPAPER=LETTER [4 ENUMERATED]\r\n\x0c"
	case "FILESYS":
		return "@PJL INFO FILESYS\r\nVOLUME TOTAL SIZE FREE SPACE LOCATION LABEL STATUS\r\n0: 1048576 524288 RAM - READ-WRITE\r\n\x0c"
	case "MEMORY":
		return "@PJL INFO MEMORY\r\nTOTAL=33554432\r\nLARGEST=16777216\r\n\x0c"
	case "PAGECOUNT":
		return "@PJL INFO PAGECOUNT\r\nPAGECOUNT=18342\r\n\x0c"
	case "USTATUS":
		return "@PJL INFO USTATUS\r\nDEVICE=ON\r\nJOB=ON\r\nPAGE=ON\r\n\x0c"
	case "PRODINFO":
		return "@PJL INFO PRODINFO\r\n\"" + safe.SanitizeHeader(model) + "\"\r\n\x0c"
	}
	return "@PJL INFO " + safe.SanitizeHeader(cat) + "\r\n\x0c"
}

// scanPostScript flags PostScript abuse embedded in a raw print job.
// PostScript is a Turing-complete interpreter, so a print job can carry
// real attacks: making persistent changes (serverdict/exitserver),
// reading/writing/deleting files, rewriting system parameters, or
// touching raw storage devices. We only recognize + log; nothing runs.
func scanPostScript(job string, res *Result) {
	low := strings.ToLower(job)
	if !strings.Contains(low, "%!") && !strings.Contains(low, "exitserver") &&
		!strings.Contains(low, "currentfile") && !strings.Contains(low, "setpagedevice") &&
		!strings.Contains(low, "deletefile") && !strings.Contains(low, "setsystemparams") {
		return // not PostScript / no interesting tokens
	}
	if strings.Contains(low, "exitserver") || strings.Contains(low, "serverdict") {
		flagAnomaly(res, "printer-postscript-exitserver")
	}
	if strings.Contains(low, "deletefile") || strings.Contains(low, "renamefile") ||
		strings.Contains(low, ") file") || strings.Contains(low, ")file") {
		flagAnomaly(res, "printer-postscript-fileop")
	}
	if strings.Contains(low, "setsystemparams") || strings.Contains(low, "setdevparams") ||
		strings.Contains(low, "setuserparams") {
		flagAnomaly(res, "printer-postscript-setparams")
	}
	if strings.Contains(low, "%disk") || strings.Contains(low, "%os%") || strings.Contains(low, "(%") {
		flagAnomaly(res, "printer-postscript-device")
	}
}

// scanZPL flags Zebra Programming Language jobs (Zebra label printers
// speak ZPL on the same raw port). A ZPL stream is ^XA...^XZ or starts
// with a ~ control command. Config-saving / destructive control commands
// (~JA cancel-all, ^JU config update, ~DG/~DY object download) are the
// abuse shapes.
func scanZPL(job string, res *Result) {
	up := strings.ToUpper(job)
	if !strings.Contains(up, "^XA") && !strings.Contains(up, "^XZ") &&
		!strings.HasPrefix(strings.TrimSpace(up), "~") {
		return
	}
	flagAnomaly(res, "printer-zpl-job")
	if strings.Contains(up, "~JA") || strings.Contains(up, "^JU") ||
		strings.Contains(up, "~DG") || strings.Contains(up, "~DY") {
		flagAnomaly(res, "printer-zpl-config")
	}
}

// scanPCL flags a raw PCL job (HP Printer Control Language). PCL is mostly
// benign printing, so this is a low-signal informational marker — the
// escape sequence \x1bE (reset) / \x1b& start most PCL streams.
func scanPCL(job string, res *Result) {
	if strings.Contains(job, "\x1bE") || strings.Contains(job, "\x1b&") || strings.Contains(job, "\x1b*") {
		flagAnomaly(res, "printer-pcl-job")
	}
}

// pjlFSDirList returns a believable FSDIRLIST reply for the requested path.
func pjlFSDirList(line string) string {
	name := pjlNameArg(line)
	if name == "" {
		name = "0:\\"
	}
	return "@PJL FSDIRLIST NAME=\"" + safe.SanitizeHeader(name) + "\" ENTRY=1\r\n" +
		". TYPE=DIR\r\n.. TYPE=DIR\r\n" +
		"webServer TYPE=DIR\r\nsaveDevice TYPE=DIR\r\nPostScript TYPE=DIR\r\n" +
		"jobs TYPE=DIR\r\ndefault TYPE=DIR\r\n\x0c"
}

// pjlFSUpload returns a small believable file body for an FSUPLOAD read.
func pjlFSUpload(line string) string {
	name := pjlNameArg(line)
	data := "; printer device configuration\nMODEL=stub\nLOCATION=copy-room\n"
	return "@PJL FSUPLOAD FORMAT:BINARY NAME=\"" + safe.SanitizeHeader(name) + "\" OFFSET=0 SIZE=" +
		itoa(len(data)) + "\r\n" + data + "\x0c"
}

// pjlFSQuery returns a believable single-file FSQUERY result.
func pjlFSQuery(line string) string {
	name := pjlNameArg(line)
	return "@PJL FSQUERY NAME=\"" + safe.SanitizeHeader(name) + "\" TYPE=FILE SIZE=2048\r\n\x0c"
}

// --- small PJL parsing helpers ---

// pjlKeyword returns the command keyword (the token after @PJL) from an
// upper-cased PJL line. Returns "" when not found.
func pjlKeyword(up string) string {
	i := strings.Index(up, "@PJL")
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(up[i+4:])
	return firstToken(rest)
}

// pjlArg returns the first token after the given keyword (e.g. the INFO
// category). "" when absent.
func pjlArg(up, keyword string) string {
	i := strings.Index(up, keyword)
	if i < 0 {
		return ""
	}
	return firstToken(strings.TrimSpace(up[i+len(keyword):]))
}

func firstToken(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' || s[i] == '=' {
			return s[:i]
		}
	}
	return s
}

// pjlNameArg extracts the value of NAME="..." (or NAME=...) from a PJL
// line, preserving original case. "" when absent.
func pjlNameArg(line string) string {
	up := strings.ToUpper(line)
	i := strings.Index(up, "NAME=")
	if i < 0 {
		return ""
	}
	v := line[i+len("NAME="):]
	if len(v) > 0 && v[0] == '"' {
		v = v[1:]
		if j := strings.IndexByte(v, '"'); j >= 0 {
			return v[:j]
		}
		return v
	}
	return firstToken(v)
}

// pjlValueOf returns the value after KEY= on a PJL line (original case).
func pjlValueOf(line, key string) string {
	up := strings.ToUpper(line)
	i := strings.Index(up, strings.ToUpper(key)+"=")
	if i < 0 {
		return ""
	}
	return firstToken(strings.TrimSpace(line[i+len(key)+1:]))
}

func pjlMentionsPassword(up string) bool {
	return strings.Contains(up, "PASSWORD") || strings.Contains(up, "DISKLOCK") ||
		strings.Contains(up, "LPASSWORD")
}

// pjlPathTraversal reports whether a PJL filesystem path tries to escape
// its volume (../, ..\, or an absolute device escape like 0:\..\).
func pjlPathTraversal(line string) bool {
	l := strings.ToLower(line)
	return strings.Contains(l, "../") || strings.Contains(l, "..\\") ||
		strings.Contains(l, ":\\..") || strings.Contains(l, ":/..")
}

// pjlPasswordValue extracts the value after PASSWORD= (original case).
func pjlPasswordValue(line string) string {
	up := strings.ToUpper(line)
	i := strings.Index(up, "PASSWORD")
	if i < 0 {
		return ""
	}
	rest := line[i+len("PASSWORD"):]
	rest = strings.TrimLeft(rest, " \t")
	if !strings.HasPrefix(rest, "=") {
		return ""
	}
	return firstToken(strings.TrimSpace(rest[1:]))
}

// appendBounded appends s (+newline) to b while keeping b under the job
// capture cap, so a huge job can't exhaust memory.
func appendBounded(b *strings.Builder, s string) {
	if b.Len() >= pjlMaxBytes {
		return
	}
	b.WriteString(s)
	b.WriteByte('\n')
}
