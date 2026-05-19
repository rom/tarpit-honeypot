package handler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// ipp implements just enough of the Internet Printing Protocol (TCP 631,
// CUPS) to fool a printer-discovery scanner. IPP rides on HTTP — clients
// POST to /printers or /ipp/print with Content-Type:
// application/ipp and a binary body.
//
// We parse the HTTP request line + Content-Length, read the body, peek
// the IPP operation-id (e.g. 0x000B = Get-Printer-Attributes) and reply
// with an HTTP 200 wrapping an IPP successful-ok body that advertises
// a fake "Brother HL-L8260CDW series" printer.
type ipp struct{}

func (i *ipp) Name() string { return "ipp" }

const (
	ippVersion   uint16 = 0x0200 // 2.0
	ippOpGetAttr uint16 = 0x000B
	ippStatusOK  uint16 = 0x0000
	ippTagOpAttr        = 0x01
	ippTagPrinter       = 0x04
	ippTagEnd           = 0x03
	ippTagCharset       = 0x47
	ippTagLang          = 0x48
	ippTagURI           = 0x45
	ippTagKeyword       = 0x44
	ippTagEnum          = 0x23
	ippTagInt           = 0x21
	ippTagBool          = 0x22
	ippTagName          = 0x42
	ippTagText          = 0x41
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
	}

	// Build an IPP successful-ok body advertising a fake Brother
	// printer. operation-attributes-tag with charset + language, then
	// printer-attributes-tag with printer-name + printer-state +
	// printer-make-and-model + printer-uri-supported + printer-info,
	// then end-of-attributes-tag.
	var rid uint32
	if len(body) >= 8 {
		rid = binary.BigEndian.Uint32(body[4:8])
	}
	ipp := i.buildOK(rid)
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

func (i *ipp) buildOK(rid uint32) []byte {
	out := make([]byte, 0, 256)
	out = binary.BigEndian.AppendUint16(out, ippVersion)
	out = binary.BigEndian.AppendUint16(out, ippStatusOK)
	out = binary.BigEndian.AppendUint32(out, rid)

	// operation-attributes-tag
	out = append(out, ippTagOpAttr)
	out = appendIPPAttr(out, ippTagCharset, "attributes-charset", "utf-8")
	out = appendIPPAttr(out, ippTagLang, "attributes-natural-language", "en")

	// printer-attributes-tag
	out = append(out, ippTagPrinter)
	out = appendIPPAttr(out, ippTagName, "printer-name", "Brother HL-L8260CDW")
	out = appendIPPAttr(out, ippTagText, "printer-make-and-model", "Brother HL-L8260CDW series")
	out = appendIPPAttr(out, ippTagText, "printer-info", "Office MFP")
	out = appendIPPAttr(out, ippTagText, "printer-location", "1st floor copy room")
	out = appendIPPAttr(out, ippTagURI, "printer-uri-supported", "ipp://printer.local:631/ipp/print")
	out = appendIPPAttr(out, ippTagKeyword, "printer-state-reasons", "none")
	out = appendIPPIntAttr(out, "printer-state", 3) // 3 = idle
	out = appendIPPBoolAttr(out, "printer-is-accepting-jobs", true)

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
	out = append(out, ippTagEnum)
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
