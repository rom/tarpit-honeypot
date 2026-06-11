package handler

import (
	"bufio"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Shared helpers for the CPE / device-management protocol family — TR-069
// (CWMP), TR-369 (USP), and UPnP. All three are HTTP/SOAP-fronted (USP's
// internet-facing MTP is WebSocket, an HTTP upgrade), so they share request
// parsing, SOAP-action extraction, command-injection recognition, a small
// response builder, and a CWE annotation helper.

// httpHead is a minimally-parsed HTTP request: the request-line fields, the
// lower-cased headers (last value wins), and the bounded body.
type httpHead struct {
	Method  string
	URI     string
	Proto   string
	Headers map[string]string
	Body    []byte
	Raw     []byte // full request bytes (head + body) for CVE signature scans
}

// header returns the (lower-cased) header value, or "".
func (h httpHead) header(name string) string { return h.Headers[strings.ToLower(name)] }

// readCPEHTTP reads an HTTP request from conn: the head up to CRLFCRLF (capped
// to cfg.ReadBytes) then up to Content-Length body bytes (capped to the same
// budget). The caller is expected to have set the read deadline. ok is false
// when nothing was read.
func readCPEHTTP(conn net.Conn, cfg config.Listener) (httpHead, bool) {
	capBytes := cfg.ReadBytes
	if capBytes <= 0 {
		capBytes = 8192
	}
	br := bufio.NewReader(conn)
	var head []byte
	for len(head) < capBytes {
		b, err := br.ReadByte()
		if err != nil {
			break
		}
		head = append(head, b)
		if strings.HasSuffix(string(head), "\r\n\r\n") {
			break
		}
	}
	if len(head) == 0 {
		return httpHead{}, false
	}
	h := parseHTTPHead(head)
	if n := contentLength(h.Headers); n > 0 {
		if n > capBytes {
			n = capBytes
		}
		body := make([]byte, n)
		got, _ := io.ReadFull(br, body)
		h.Body = body[:got]
		h.Raw = append(append([]byte(nil), head...), h.Body...)
	}
	return h, true
}

// parseHTTPHead parses an already-read request head (and optional inline body)
// into an httpHead. Used directly by handlers that read the raw bytes first
// (so they can branch on HTTP vs. a binary protocol).
func parseHTTPHead(buf []byte) httpHead {
	h := httpHead{Headers: map[string]string{}, Raw: buf}
	headEnd := strings.Index(string(buf), "\r\n\r\n")
	headPart := string(buf)
	if headEnd >= 0 {
		headPart = string(buf[:headEnd])
		h.Body = buf[headEnd+4:]
	}
	lines := strings.Split(headPart, "\r\n")
	if len(lines) > 0 {
		if f := strings.Fields(lines[0]); len(f) >= 1 {
			h.Method = f[0]
			if len(f) >= 2 {
				h.URI = f[1]
			}
			if len(f) >= 3 {
				h.Proto = f[2]
			}
		}
	}
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		h.Headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return h
}

func contentLength(headers map[string]string) int {
	if n, err := strconv.Atoi(strings.TrimSpace(headers["content-length"])); err == nil && n >= 0 {
		return n
	}
	return 0
}

// soapAction splits a SOAPAction header value
// ("urn:dslforum-org:service:Time:1#SetNTPServers") into its service URN and
// action local-name. Either may be "".
func soapAction(h httpHead) (service, action string) {
	sa := strings.Trim(h.header("soapaction"), `" `)
	if sa == "" {
		return "", ""
	}
	if i := strings.LastIndex(sa, "#"); i >= 0 {
		return sa[:i], sa[i+1:]
	}
	return sa, ""
}

// shellMetacharacters reports whether s carries the hallmarks of a shell
// command-injection payload (used to confirm injection inside a SOAP
// parameter like NewNTPServer1 / NewStatusURL). Conservative, near-zero-FP.
func shellMetacharacters(s string) bool {
	low := strings.ToLower(s)
	return strings.ContainsAny(s, "`;|") || strings.Contains(s, "$(") || strings.Contains(s, "&&") ||
		strings.Contains(low, "wget ") || strings.Contains(low, "curl ") ||
		strings.Contains(low, "/bin/") || strings.Contains(low, "busybox") ||
		strings.Contains(low, "chmod ")
}

// noteCWE records the weakness class(es) implied by a detected protocol misuse
// onto the result's meta as a comma-joined "cwe" string (deduped, order
// preserved). This carries CWE attribution for misuse that has no specific
// catalogued CVE — the CVE catalog otherwise being the only CWE channel.
func noteCWE(res *Result, cwes ...string) {
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	seen := map[string]bool{}
	var out []string
	if existing, _ := res.Meta["cwe"].(string); existing != "" {
		for _, c := range strings.Split(existing, ", ") {
			if c = strings.TrimSpace(c); c != "" && !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	for _, c := range cwes {
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	res.Meta["cwe"] = strings.Join(out, ", ")
}

// headerKeys returns the (lower-cased) header names present, sorted — a stable
// view of the request's header set for tool fingerprinting.
func headerKeys(h httpHead) []string {
	out := make([]string, 0, len(h.Headers))
	for k := range h.Headers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// xmlElem returns the text content of the first <tag> (namespace-prefixed or
// not) element in body, or "". Bounded, allocation-light — enough to scavenge a
// SOAP scalar, not a real XML parser.
func xmlElem(body, tag string) string {
	for _, open := range []string{"<" + tag + ">", ":" + tag + ">"} {
		i := strings.Index(body, open)
		if i < 0 {
			continue
		}
		rest := body[i+len(open):]
		j := strings.IndexByte(rest, '<')
		if j < 0 {
			j = len(rest)
		}
		if v := strings.TrimSpace(rest[:j]); v != "" {
			return v
		}
	}
	return ""
}

// writeConn writes resp to conn, recording any error in res.Meta["write_err"].
func writeConn(conn net.Conn, res *Result, resp string) {
	if _, err := conn.Write([]byte(resp)); err != nil {
		if res.Meta == nil {
			res.Meta = map[string]any{}
		}
		res.Meta["write_err"] = err.Error()
	}
}

// cpeHTTPResp builds a minimal HTTP/1.1 response. extra carries any additional
// header lines (without trailing CRLF). server / ctype may be "".
func cpeHTTPResp(status, server, ctype, body string, extra ...string) string {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + status + "\r\n")
	if server != "" {
		b.WriteString("Server: " + safe.SanitizeHeader(server) + "\r\n")
	}
	for _, e := range extra {
		if e != "" {
			b.WriteString(e + "\r\n")
		}
	}
	if ctype != "" {
		b.WriteString("Content-Type: " + ctype + "\r\n")
	}
	b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	b.WriteString("Connection: close\r\n\r\n")
	b.WriteString(body)
	return b.String()
}
