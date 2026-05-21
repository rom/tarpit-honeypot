package handler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
)

// ipp implements just enough of the Internet Printing Protocol (TCP 631,
// CUPS) to fool a printer-discovery scanner. IPP rides on HTTP — clients
// POST to /printers or /ipp/print with Content-Type:
// application/ipp and a binary body.
//
// We parse the HTTP request line + Content-Length, read the body, peek
// the IPP operation-id (e.g. 0x000B = Get-Printer-Attributes) and reply
// with an HTTP 200 wrapping an IPP successful-ok body that advertises a
// believable printer — identity taken from the bound archetype when set
// (so the IPP reply matches the SNMP/web identity), else a default MFP.
type ipp struct{ arch *archetype.Profile }

func (i *ipp) Name() string { return "ipp" }

const (
	ippVersion    uint16 = 0x0200 // 2.0
	ippOpGetAttr  uint16 = 0x000B
	ippStatusOK   uint16 = 0x0000
	ippTagOpAttr         = 0x01
	ippTagPrinter        = 0x04
	ippTagEnd            = 0x03
	ippTagCharset        = 0x47
	ippTagLang           = 0x48
	ippTagURI            = 0x45
	ippTagKeyword        = 0x44
	ippTagEnum           = 0x23
	ippTagInt            = 0x21
	ippTagBool           = 0x22
	ippTagName           = 0x42
	ippTagText           = 0x41
	ippTagMime           = 0x49
)

func (i *ipp) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	cap := cfg.ReadBytes
	if cap <= 0 {
		cap = 8192
	}
	// Read HTTP request line + headers.
	var head bytes.Buffer
	for head.Len() < cap {
		b, err := br.ReadByte()
		if err != nil {
			res.Meta["read_err"] = err.Error()
			break
		}
		head.WriteByte(b)
		if bytes.HasSuffix(head.Bytes(), []byte("\r\n\r\n")) {
			break
		}
	}
	res.Payload = head.Bytes()
	firstLine := ""
	contentLen := 0
	for idx, line := range strings.Split(head.String(), "\r\n") {
		if idx == 0 {
			firstLine = line
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "content-length:") {
			var n int
			for _, c := range strings.TrimSpace(line[15:]) {
				if c < '0' || c > '9' {
					break
				}
				n = n*10 + int(c-'0')
			}
			contentLen = n
		} else if strings.HasPrefix(lower, "user-agent:") {
			res.Meta["user_agent"] = strings.TrimSpace(line[11:])
		}
	}
	res.Meta["request_line"] = firstLine

	// Slurp body (best-effort).
	var body []byte
	if contentLen > 0 && contentLen <= cap {
		body = make([]byte, contentLen)
		_, _ = io.ReadFull(br, body)
		res.Payload = append(res.Payload, body...)
	}
	if len(body) >= 8 {
		ver := binary.BigEndian.Uint16(body[0:2])
		opID := binary.BigEndian.Uint16(body[2:4])
		reqID := binary.BigEndian.Uint32(body[4:8])
		res.Meta["ipp_version"] = ver
		res.Meta["ipp_op"] = opID
		res.Meta["ipp_request_id"] = reqID
		name, admin := ippOpName(opID)
		res.Meta["ipp_op_name"] = name
		if admin {
			// Printer-admin / job-injection / server-side-fetch ops that a
			// scanner has no business calling unauthenticated — the surface
			// the CUPS chain (add a malicious printer, then print) abuses.
			flagAnomaly(&res, "printer-ipp-admin-op")
		}
	}

	// CUPS exploit-chain + injection detection over the whole request
	// (HTTP head + IPP body). FoomaticRIPCommandLine is the foomatic-rip
	// RCE primitive (CVE-2024-47177); shell metacharacters smuggled into a
	// device-uri / command attribute are the generic injection shape.
	i.detectIPPAbuse(&res)

	// Build an IPP successful-ok body advertising a fake Brother
	// printer. operation-attributes-tag with charset + language, then
	// printer-attributes-tag with printer-name + printer-state +
	// printer-make-and-model + printer-uri-supported + printer-info,
	// then end-of-attributes-tag.
	var rid uint32
	if len(body) >= 8 {
		rid = binary.BigEndian.Uint32(body[4:8])
	}
	name, model := i.identity()
	ipp := i.buildOK(rid, name, model)
	httpResp := "HTTP/1.1 200 OK\r\n" +
		"Server: CUPS/2.4.7 IPP/2.1\r\n" +
		"Content-Type: application/ipp\r\n" +
		"Connection: close\r\n" +
		"Content-Length: " + itoa(len(ipp)) + "\r\n\r\n"
	if _, err := conn.Write(append([]byte(httpResp), ipp...)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "ipp Get-Printer-Attributes 200 OK"
	return res, nil
}

// detectIPPAbuse scans the captured request for the CUPS RCE primitive and
// command-injection metacharacters in printer/device attributes, recording
// CVE hits + anomalies. Recognition only — nothing is executed.
func (i *ipp) detectIPPAbuse(res *Result) {
	low := strings.ToLower(string(res.Payload))
	for _, rec := range cve.MatchPayload("ipp", low) {
		res.CVEHits = append(res.CVEHits, rec.ID)
	}
	if strings.Contains(low, "foomaticripcommandline") {
		flagAnomaly(res, "printer-cups-rce")
	}
	// A device-uri / command attribute carrying shell metacharacters is a
	// command-injection attempt against the print pipeline.
	if (strings.Contains(low, "device-uri") || strings.Contains(low, "commandline") ||
		strings.Contains(low, "ppd-name")) &&
		(strings.ContainsAny(low, "`;|&") || strings.Contains(low, "$(")) {
		flagAnomaly(res, "printer-ipp-cmd-injection")
	}
}

// ippOpName maps an IPP operation id to its name and whether it is a
// printer-admin / job-injection / server-fetch operation a honeypot should
// treat as abuse when seen unauthenticated. Standard ops (RFC 8011) plus
// the CUPS vendor extensions (0x4000+).
func ippOpName(op uint16) (name string, admin bool) {
	switch op {
	case 0x0002:
		return "Print-Job", false
	case 0x0003:
		return "Print-URI", true // server-side fetch (SSRF)
	case 0x0004:
		return "Validate-Job", false
	case 0x0005:
		return "Create-Job", false
	case 0x0006:
		return "Send-Document", false
	case 0x0007:
		return "Send-URI", true // server-side fetch (SSRF)
	case 0x0008:
		return "Cancel-Job", false
	case 0x0009:
		return "Get-Job-Attributes", false
	case 0x000A:
		return "Get-Jobs", false
	case 0x000B:
		return "Get-Printer-Attributes", false
	case 0x0010:
		return "Pause-Printer", true
	case 0x0011:
		return "Resume-Printer", true
	case 0x0012:
		return "Purge-Jobs", true
	case 0x0013:
		return "Set-Printer-Attributes", true
	case 0x0014:
		return "Set-Job-Attributes", false
	case 0x4003:
		return "CUPS-Add-Modify-Printer", true
	case 0x4004:
		return "CUPS-Delete-Printer", true
	case 0x4006:
		return "CUPS-Add-Modify-Class", true
	case 0x4007:
		return "CUPS-Delete-Class", true
	case 0x400A:
		return "CUPS-Set-Default", true
	case 0x400D:
		return "CUPS-Move-Job", true
	case 0x400F:
		return "CUPS-Get-PPD", true
	case 0x4027:
		return "CUPS-Get-Document", true
	}
	return "op-" + itoa(int(op)), false
}

// identity returns the printer name + make-and-model the IPP reply
// advertises, taken from the bound archetype when present so IPP, SNMP and
// the web UI all tell the same story; default is a generic office MFP.
func (i *ipp) identity() (name, model string) {
	name, model = "Brother HL-L8260CDW", "Brother HL-L8260CDW series"
	if i.arch != nil {
		if t := i.arch.HTTPTitle(); t != "" {
			name = t
		}
		if d := i.arch.SNMPSysDescr(); d != "" {
			model = d
		}
	}
	return name, model
}

func (i *ipp) buildOK(rid uint32, name, model string) []byte {
	out := make([]byte, 0, 512)
	out = binary.BigEndian.AppendUint16(out, ippVersion)
	out = binary.BigEndian.AppendUint16(out, ippStatusOK)
	out = binary.BigEndian.AppendUint32(out, rid)

	// operation-attributes-tag
	out = append(out, ippTagOpAttr)
	out = appendIPPAttr(out, ippTagCharset, "attributes-charset", "utf-8")
	out = appendIPPAttr(out, ippTagLang, "attributes-natural-language", "en")

	// printer-attributes-tag — a fuller, believable attribute set so a
	// printer-discovery client (CUPS, ipptool, AirPrint) sees a real MFP.
	out = append(out, ippTagPrinter)
	out = appendIPPAttr(out, ippTagName, "printer-name", name)
	out = appendIPPAttr(out, ippTagText, "printer-make-and-model", model)
	out = appendIPPAttr(out, ippTagText, "printer-info", "Office MFP")
	out = appendIPPAttr(out, ippTagText, "printer-location", "1st floor copy room")
	out = appendIPPAttr(out, ippTagURI, "printer-uri-supported", "ipp://printer.local:631/ipp/print")
	out = appendIPPAttr(out, ippTagURI, "printer-more-info", "http://printer.local/")
	out = appendIPPAttr(out, ippTagURI, "printer-uuid", "urn:uuid:564e4333-4e50-4831-3832-363043445720")
	out = appendIPPAttr(out, ippTagName, "printer-dns-sd-name", name)
	out = appendIPPAttr(out, ippTagKeyword, "printer-state-reasons", "none")
	out = appendIPPAttr(out, ippTagText, "printer-state-message", "Ready")
	out = appendIPPAttr(out, ippTagKeyword, "ipp-versions-supported", "2.0")
	out = appendIPPAttr(out, ippTagMime, "document-format-default", "application/pdf")
	out = appendIPPAttr(out, ippTagMime, "document-format-supported", "application/pdf")
	out = appendIPPAttr(out, ippTagMime, "document-format-supported", "application/postscript")
	out = appendIPPAttr(out, ippTagMime, "document-format-supported", "application/vnd.hp-PCL")
	out = appendIPPAttr(out, ippTagKeyword, "media-default", "iso_a4_210x297mm")
	out = appendIPPAttr(out, ippTagText, "marker-names", "Black Cartridge")
	out = appendIPPIntAttr(out, "printer-state", 3) // enum: 3 = idle
	out = appendIPPInteger(out, "queued-job-count", 0)
	out = appendIPPInteger(out, "marker-levels", 72) // toner %
	out = appendIPPBoolAttr(out, "printer-is-accepting-jobs", true)
	out = appendIPPBoolAttr(out, "color-supported", true)

	// end-of-attributes-tag
	out = append(out, ippTagEnd)
	return out
}

func appendIPPAttr(out []byte, tag byte, name, val string) []byte {
	out = append(out, tag)
	out = binary.BigEndian.AppendUint16(out, uint16(len(name)))
	out = append(out, []byte(name)...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(val)))
	out = append(out, []byte(val)...)
	return out
}

func appendIPPIntAttr(out []byte, name string, val int32) []byte {
	return appendIPPNumeric(out, ippTagEnum, name, val)
}

// appendIPPInteger appends an IPP integer (tag 0x21) attribute — used for
// counts / levels, vs appendIPPIntAttr's enum (printer-state).
func appendIPPInteger(out []byte, name string, val int32) []byte {
	return appendIPPNumeric(out, ippTagInt, name, val)
}

func appendIPPNumeric(out []byte, tag byte, name string, val int32) []byte {
	out = append(out, tag)
	out = binary.BigEndian.AppendUint16(out, uint16(len(name)))
	out = append(out, []byte(name)...)
	out = binary.BigEndian.AppendUint16(out, 4)
	out = binary.BigEndian.AppendUint32(out, uint32(val))
	return out
}

func appendIPPBoolAttr(out []byte, name string, val bool) []byte {
	out = append(out, ippTagBool)
	out = binary.BigEndian.AppendUint16(out, uint16(len(name)))
	out = append(out, []byte(name)...)
	out = binary.BigEndian.AppendUint16(out, 1)
	if val {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
