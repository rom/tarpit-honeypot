package handler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type winrm struct{}

func (w *winrm) Name() string { return "winrm" }

// WinRM (port 5985 HTTP, 5986 HTTPS). It's HTTP at the transport layer
// — a real WinRM endpoint accepts a POST /wsman with a SOAP envelope and
// challenges with WWW-Authenticate: Negotiate or Basic. Most scanners
// look for the IIS-style 401 + WWW-Authenticate response.
//
// We capture Basic credentials, and drive the NTLM (Negotiate) handshake
// one step further: when a client sends an NTLMSSP Type 1, we reply with a
// believable Type 2 challenge so the client sends its Type 3, from which we
// harvest the AD domain + username (and the NetNTLM response, offline-
// crackable) — exactly what an NTLM-spraying scanner leaks.
func (w *winrm) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	br := bufio.NewReader(conn)
	cap := cfg.ReadBytes
	if cap <= 0 {
		cap = 8192
	}

	head, err := readHTTPHead(br, cap)
	if err != nil && len(head) == 0 {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = head
	authz := winrmParseRequest(head, res.Meta)

	// NTLM (Negotiate) Type 1 -> send a Type 2 challenge and read the Type 3.
	if tok := negotiateToken(authz); tok != nil && isNTLMType(tok, 1) {
		res.Meta["ntlm_negotiate"] = true
		challenge := "HTTP/1.1 401 Unauthorized\r\n" +
			"Server: Microsoft-HTTPAPI/2.0\r\n" +
			"WWW-Authenticate: Negotiate " + base64.StdEncoding.EncodeToString(ntlmType2()) + "\r\n" +
			"Content-Length: 0\r\n\r\n"
		if _, err := conn.Write([]byte(challenge)); err != nil {
			res.Meta["write_err"] = err.Error()
			return res, nil
		}
		// Read the follow-up request carrying the NTLMSSP Type 3.
		head2, _ := readHTTPHead(br, cap)
		if len(head2) > 0 {
			res.Payload = append(res.Payload, head2...)
			authz2 := winrmParseRequest(head2, res.Meta)
			if tok3 := negotiateToken(authz2); tok3 != nil && isNTLMType(tok3, 3) {
				if dom, user, nt := parseNTLMType3(tok3); user != "" {
					res.Meta["ntlm_domain"] = dom
					res.Meta["ntlm_user"] = user
					if nt != "" {
						res.Meta["ntlm_response_hex"] = nt
					}
					flagAnomaly(&res, "winrm-ntlm-auth")
				}
			}
		}
		res.BannerSent = "winrm NTLM type2 challenge"
		return res, nil
	}

	resp := "HTTP/1.1 401 Unauthorized\r\n" +
		"Server: Microsoft-HTTPAPI/2.0\r\n" +
		"WWW-Authenticate: Negotiate\r\n" +
		"WWW-Authenticate: Basic realm=\"WSMAN\"\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "winrm 401 Negotiate+Basic"
	return res, nil
}

// readHTTPHead reads an HTTP request head (through the blank CRLFCRLF line),
// bounded by cap.
func readHTTPHead(br *bufio.Reader, cap int) ([]byte, error) {
	var buf bytes.Buffer
	for buf.Len() < cap {
		b, err := br.ReadByte()
		if err != nil {
			return buf.Bytes(), err
		}
		buf.WriteByte(b)
		if bytes.HasSuffix(buf.Bytes(), []byte("\r\n\r\n")) {
			break
		}
	}
	return buf.Bytes(), nil
}

// winrmParseRequest records the request line / User-Agent and captures any
// Basic credentials, returning the raw Authorization header value.
func winrmParseRequest(head []byte, meta map[string]any) string {
	authz := ""
	for i, line := range strings.Split(string(head), "\r\n") {
		if i == 0 {
			meta["request_line"] = line
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "authorization:"):
			authz = strings.TrimSpace(line[len("authorization:"):])
			meta["authorization"] = authz
			if strings.HasPrefix(strings.ToLower(authz), "basic ") {
				if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(authz[6:])); err == nil {
					if j := bytes.IndexByte(dec, ':'); j >= 0 {
						meta["basic_user"] = string(dec[:j])
						meta["basic_pass"] = string(dec[j+1:])
					}
				}
			}
		case strings.HasPrefix(lower, "user-agent:"):
			meta["user_agent"] = strings.TrimSpace(line[len("user-agent:"):])
		}
	}
	return authz
}

// negotiateToken decodes the base64 token from an "Authorization: Negotiate
// <b64>" (or NTLM <b64>) header, or nil if it isn't one.
func negotiateToken(authz string) []byte {
	low := strings.ToLower(authz)
	var b64 string
	switch {
	case strings.HasPrefix(low, "negotiate "):
		b64 = strings.TrimSpace(authz[len("negotiate "):])
	case strings.HasPrefix(low, "ntlm "):
		b64 = strings.TrimSpace(authz[len("ntlm "):])
	default:
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil
	}
	return raw
}

// isNTLMType reports whether tok is an NTLMSSP message of the given type.
func isNTLMType(tok []byte, msgType uint32) bool {
	if len(tok) < 12 || !bytes.Equal(tok[0:8], []byte("NTLMSSP\x00")) {
		return false
	}
	return binary.LittleEndian.Uint32(tok[8:12]) == msgType
}

// ntlmType2 builds a minimal but well-formed NTLMSSP Type 2 (CHALLENGE)
// message with a fixed server challenge — enough for a client to compute and
// send its Type 3.
func ntlmType2() []byte {
	m := make([]byte, 0, 48)
	m = append(m, []byte("NTLMSSP\x00")...)                       // signature
	m = append(m, 0x02, 0x00, 0x00, 0x00)                         // type 2
	m = append(m, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00) // TargetName buf (len 0, off 0x30)
	m = append(m, 0x05, 0x82, 0x89, 0xa2)                         // negotiate flags (unicode|ntlm|target_info|...)
	m = append(m, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef) // server challenge
	m = append(m, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // reserved
	m = append(m, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00) // TargetInfo buf (len 0, off 0x30)
	return m
}

// parseNTLMType3 extracts the domain, username, and NTLM response (hex) from
// an NTLMSSP Type 3 (AUTHENTICATE) message. Security buffers (len/maxlen/
// offset) live at fixed offsets; strings are UTF-16LE when the unicode flag
// is set (it is, for every modern client) and OEM ASCII otherwise.
func parseNTLMType3(tok []byte) (domain, user, ntHex string) {
	if len(tok) < 52 || !isNTLMType(tok, 3) {
		return "", "", ""
	}
	field := func(off int) (data []byte, ok bool) {
		if off+8 > len(tok) {
			return nil, false
		}
		l := int(binary.LittleEndian.Uint16(tok[off : off+2]))
		o := int(binary.LittleEndian.Uint32(tok[off+4 : off+8]))
		if l == 0 || o < 0 || o+l > len(tok) {
			return nil, false
		}
		return tok[o : o+l], true
	}
	// NegotiateFlags live at offset 60; default to unicode (every modern
	// client sets it) when the message is too short to carry them.
	unicode := true
	if len(tok) >= 64 {
		unicode = binary.LittleEndian.Uint32(tok[60:64])&0x00000001 != 0
	}
	decode := func(b []byte) string {
		if unicode {
			return fromUTF16le(b)
		}
		return string(b)
	}
	if nt, ok := field(20); ok { // NtChallengeResponse
		ntHex = byteToHex(nt)
	}
	if d, ok := field(28); ok { // DomainName
		domain = decode(d)
	}
	if u, ok := field(36); ok { // UserName
		user = decode(u)
	}
	return domain, user, ntHex
}
