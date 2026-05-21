package handler

import (
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// pjl emulates an HP JetDirect raw-print port (TCP 9100) speaking PJL
// (Printer Job Language) — the protocol network printers expose there.
// We answer the common @PJL INFO queries with a believable printer
// identity (nmap pjl-ready-message keys on this), capture submitted jobs /
// commands, and flag printer-specific abuse: ready-message defacement
// (@PJL RDYMSG, a classic prank/extortion vector) and filesystem access
// (@PJL FSDOWNLOAD/FSUPLOAD/FSDELETE, used to read/plant files). Nothing is
// printed and no real filesystem is touched.
type pjl struct{ arch *archetype.Profile }

func (p *pjl) Name() string { return "pjl" }

func (p *pjl) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	model := "HP LaserJet"
	if p.arch != nil {
		if d := p.arch.SNMPSysDescr(); d != "" {
			model = d
		} else if t := p.arch.HTTPTitle(); t != "" {
			model = t
		}
	}
	readCap := cfg.ReadBytes
	if readCap <= 0 || readCap > 65535 {
		readCap = 8192
	}
	buf := make([]byte, readCap)
	n, _ := conn.Read(buf)
	if n <= 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}
	in := buf[:n]
	res.Payload = append([]byte(nil), in...)

	var out strings.Builder
	pjlSeen := false
	for _, line := range strings.Split(string(in), "\n") {
		up := strings.ToUpper(strings.TrimRight(line, "\r"))
		if !strings.Contains(up, "@PJL") {
			continue
		}
		pjlSeen = true
		switch {
		case strings.Contains(up, "INFO ID"):
			out.WriteString("@PJL INFO ID\r\n\"" + safe.SanitizeHeader(model) + "\"\r\n\x0c")
		case strings.Contains(up, "INFO STATUS"):
			out.WriteString("@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY=\"Ready\"\r\nONLINE=TRUE\r\n\x0c")
		case strings.Contains(up, "INFO CONFIG"):
			out.WriteString("@PJL INFO CONFIG\r\nIN TRAYS [2 ENUMERATED]\r\nOUT TRAYS [1 ENUMERATED]\r\n\x0c")
		case strings.Contains(up, "RDYMSG"):
			res.Meta["pjl_rdymsg"] = safe.SanitizeForLog(strings.TrimRight(line, "\r"))
			flagAnomaly(&res, "printer-rdymsg-set")
		case strings.Contains(up, "FSDOWNLOAD"), strings.Contains(up, "FSUPLOAD"), strings.Contains(up, "FSDELETE"), strings.Contains(up, "FSDIRLIST"):
			flagAnomaly(&res, "printer-filesystem-access")
		}
	}
	if pjlSeen {
		flagAnomaly(&res, "pjl-command")
	} else {
		// Raw PCL / PostScript print job submitted to the JetDirect port.
		flagAnomaly(&res, "printer-job-received")
	}
	if out.Len() > 0 {
		if _, err := conn.Write([]byte(out.String())); err != nil {
			res.Meta["write_err"] = err.Error()
		}
		res.BannerSent = out.String()
	}
	return res, nil
}
