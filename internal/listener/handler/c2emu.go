package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// c2Emulator is a fake command-and-control team-server. It answers like the
// real HTTP C2 listener of several red-team frameworks so that a beacon
// (a sandbox detonation or a misconfigured implant that resolves to us) or an
// operator/scanner hunting for an open C2 panel keeps talking and is captured.
//
// Identification is by request *shape* — the default malleable/profile URIs,
// cookies, headers and stager checksums of Cobalt Strike, Metasploit, Empire
// and PoshC2 — and, failing that, by the client's User-Agent against the
// toolfp C2-framework corpus (40+ families). Every recognized interaction is
// flagged command-and-control (ATT&CK T1071.001 / T1219) with the framework
// and profile captured; the service is never a real C2 and runs no tasking.
type c2Emulator struct{}

func (c2Emulator) Name() string { return "c2_emulator" }

func (c2Emulator) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{"service": "c2-emulator"}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 8192
	}
	head, _ := readHTTPHead(br, capN)
	res.Payload = head

	h := parseHTTPHead(head)
	ua := h.header("user-agent")
	cookie := h.header("cookie")
	res.Meta["method"] = h.Method
	res.Meta["path"] = h.URI
	if ua != "" {
		res.Meta["user_agent"] = ua
	}

	fw, kind, note := c2Identify(h)
	// Fall back to User-Agent / header fingerprinting against the C2 corpus.
	if fw == "" {
		v := toolfp.IdentifyHTTP(toolfp.HTTPSignals{
			Method: h.Method, Path: h.URI, UserAgent: ua, HeaderKeys: headerKeys(h),
		})
		for _, tool := range v.Tools {
			if toolfp.IsC2(tool) {
				fw, kind, note = tool, "beacon-checkin", "C2 framework identified by client fingerprint"
				break
			}
		}
	}

	if fw != "" {
		res.Meta["c2_framework"] = fw
		res.Meta["c2_profile"] = kind
		if cookie != "" {
			// A Cobalt Strike / Empire beacon carries its encrypted metadata in
			// the Cookie; capture it (never decrypted).
			res.Meta["c2_cookie"] = clipStr(cookie, 512)
		}
		flagAnomaly(&res, "c2-beacon-checkin")
		flagAnomaly(&res, "c2:"+fw)
		if kind == "stager" {
			flagAnomaly(&res, "c2-stager")
		}
		res.Meta["intent"] = "C2 " + kind + " consistent with " + fw + " (" + note + ")"
		c2Respond(conn, &res, fw)
		return res, nil
	}

	// No framework recognized — still answer like a plausible web endpoint so a
	// probing operator/scanner continues, and note the probe.
	flagAnomaly(&res, "c2-server-probe")
	res.Meta["intent"] = "probe of a C2 listener endpoint (no framework profile matched)"
	body := "OK"
	_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
		intToStr(len(body)) + "\r\nConnection: close\r\n\r\n" + body))
	res.BannerSent = "c2 200"
	return res, nil
}

// c2Identify recognizes a C2 framework from the HTTP request shape. Returns the
// framework, the interaction kind (stager / beacon-checkin), and a short note,
// or empty when nothing matched.
func c2Identify(h httpHead) (fw, kind, note string) {
	lpath := strings.ToLower(h.URI)

	// Cobalt Strike default checksum8 staging URI (x86/x64).
	if arch, ok := toolfp.CobaltStrikeStager(h.URI); ok {
		return "cobaltstrike", "stager", "default checksum8 staging URI (" + arch + ")"
	}
	// Cobalt Strike default malleable-profile beacon URIs.
	for _, p := range []string{"/ca", "/dpixel", "/__utm.gif", "/pixel.gif", "/pixel", "/submit.php", "/activity", "/en_us/all.js", "/ptj", "/fwlink"} {
		if lpath == p || strings.HasPrefix(lpath, p+"?") {
			return "cobaltstrike", "beacon-checkin", "default malleable-profile URI " + p
		}
	}

	// Empire HTTP listener default profile.
	for _, p := range []string{"/admin/get.php", "/news.php", "/login/process.php", "/news.asp"} {
		if lpath == p {
			return "empire", "beacon-checkin", "default Empire listener URI " + p
		}
	}

	// PoshC2 default URIs / cookie.
	if strings.HasPrefix(lpath, "/images/static/content/") || lpath == "/connect" || lpath == "/webapp" {
		return "poshc2", "beacon-checkin", "default PoshC2 URI"
	}
	if hasCookieKey(h.header("cookie"), "SessionID") {
		return "poshc2", "beacon-checkin", "PoshC2 SessionID cookie"
	}

	// Mythic / Havoc default profile headers.
	if h.header("mythic") != "" {
		return "mythic", "beacon-checkin", "Mythic profile header"
	}
	for k := range h.Headers {
		if strings.HasPrefix(k, "hx-") { // Havoc Demon default header prefix
			return "havoc", "beacon-checkin", "Havoc Demon header"
		}
	}

	// Metasploit / Meterpreter reverse-HTTP stager: a short checksum-coded URI
	// (4 alphanumeric chars) not already claimed by Cobalt Strike.
	seg := strings.Trim(h.URI, "/")
	if len(seg) == 4 && isAlnum(seg) && h.Method == "GET" {
		if sum := checksum8(seg); sum != 92 && sum != 93 {
			return "metasploit", "stager", "meterpreter reverse-HTTP checksum-coded URI pattern"
		}
	}
	return "", "", ""
}

// c2Respond writes a believable team-server reply so the client continues.
func c2Respond(conn net.Conn, res *Result, fw string) {
	server := "nginx"
	switch fw {
	case "empire":
		server = "Microsoft-IIS/7.5"
	case "cobaltstrike":
		server = "Apache"
	}
	// An opaque octet-stream body stands in for the (encrypted) tasking a real
	// team server returns; nothing is actually executed or tasked.
	body := "\x00\x00\x00\x00"
	_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: " + server +
		"\r\nContent-Type: application/octet-stream\r\nContent-Length: " +
		intToStr(len(body)) + "\r\nConnection: close\r\n\r\n" + body))
	res.BannerSent = "c2 " + fw + " 200"
}

// checksum8 sums a string's bytes modulo 256 (the Metasploit/Cobalt Strike URI
// checksum).
func checksum8(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n += int(s[i])
	}
	return n & 0xff
}

func isAlnum(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return len(s) > 0
}

// hasCookieKey reports whether a Cookie header contains the named cookie.
func hasCookieKey(cookie, key string) bool {
	for _, kv := range strings.Split(cookie, ";") {
		if k, _, ok := strings.Cut(strings.TrimSpace(kv), "="); ok && strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}
