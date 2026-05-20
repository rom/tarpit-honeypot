package handler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// mgmtWeb is a parameterized HTTP(S)-fronted management-interface
// emulator. Out-of-band management controllers and appliances all
// speak HTTP with a very distinctive Server header + auth realm +
// landing page; reproducing those is what makes a scanner classify the
// host as "Dell iDRAC" / "HP iLO" / "VMware ESXi" / "Intel AMT" /
// "Fortinet" / etc. The `kind` field selects the persona.
//
// All personas capture the request line + any Authorization header
// (Basic creds get decoded; Digest attempts get logged) and raise a
// `<kind>-login-attempt` anomaly. These are read on the *plain* TCP
// path; to present them over TLS, bind the same kind behind the https
// handler (which wraps TLS then calls serveHTTP) — for the dedicated
// management personas we serve the persona page directly.
type mgmtWeb struct {
	kind string
}

func (m *mgmtWeb) Name() string { return m.kind }

type mgmtPersona struct {
	server    string // Server: header
	realm     string // WWW-Authenticate realm
	authType  string // "Basic" | "Digest"
	title     string
	bodyHTML  string
	anomaly   string // marker raised on an auth attempt
	statusFor func(path string) int
}

func personaFor(kind string) mgmtPersona {
	switch kind {
	case "intel_amt":
		// Intel AMT / vPro web UI on 16992 (CVE-2017-5689 famous).
		return mgmtPersona{
			server:   "Intel(R) Active Management Technology 11.8.50",
			realm:    "Digest:" + "A4070000000000000000000000000000",
			authType: "Digest",
			title:    "Intel&reg; Active Management Technology",
			bodyHTML: `<html><head><title>Intel(R) Active Management Technology</title></head>` +
				`<body><h1>Intel&reg; Active Management Technology</h1>` +
				`<p>Log On</p></body></html>`,
			anomaly: "intel-amt-login-attempt",
		}
	case "ilo":
		// HP Integrated Lights-Out.
		return mgmtPersona{
			server:   "HP-iLO-Server/1.30",
			realm:    "iLO",
			authType: "Basic",
			title:    "HP Integrated Lights-Out 5",
			bodyHTML: `<html><head><title>HP Integrated Lights-Out 5</title></head>` +
				`<body><h1>iLO 5</h1><p>Firmware 2.78</p></body></html>`,
			anomaly: "ilo-login-attempt",
		}
	case "idrac":
		// Dell iDRAC.
		return mgmtPersona{
			server:   "Mbedthis-Appweb/2.4.2",
			realm:    "iDRAC",
			authType: "Basic",
			title:    "Integrated Dell Remote Access Controller 9",
			bodyHTML: `<html><head><title>iDRAC9</title></head>` +
				`<body><h1>Integrated Dell Remote Access Controller 9</h1>` +
				`<p>Firmware 6.10.30.00</p></body></html>`,
			anomaly: "idrac-login-attempt",
		}
	case "esxi":
		// VMware ESXi host management.
		return mgmtPersona{
			server:   "VMware ESXi/7.0.3 Reverse Proxy",
			realm:    "VMware HTTP server",
			authType: "Basic",
			title:    "VMware ESXi",
			bodyHTML: `<html><head><title>VMware ESXi</title></head>` +
				`<body><h1>VMware ESXi 7.0 Update 3</h1>` +
				`<p><a href="/ui/">Open the VMware Host Client</a></p>` +
				`<p><a href="/sdk">Browse vSphere API</a></p></body></html>`,
			anomaly: "esxi-login-attempt",
		}
	case "fortinet":
		// Fortinet FortiGate SSL-VPN portal.
		return mgmtPersona{
			server:   "xxxxxxxx-xxxxx", // FortiGate hides its server; this is the literal placeholder it returns
			realm:    "",
			authType: "",
			title:    "Please Login",
			bodyHTML: `<html><head><title>Please Login</title></head>` +
				`<body><form action="/remote/logincheck" method="post">` +
				`<input name="username"><input type="password" name="credential">` +
				`<input type="submit" value="Login"></form></body></html>`,
			anomaly: "fortinet-vpn-login-attempt",
		}
	case "pulse":
		// Pulse Secure / Ivanti Connect Secure VPN.
		return mgmtPersona{
			server:   "",
			authType: "",
			title:    "Welcome",
			bodyHTML: `<html><head><title>Welcome</title></head>` +
				`<body><form action="/dana-na/auth/url_default/login.cgi" method="post">` +
				`<input name="username"><input type="password" name="password">` +
				`<input type="submit" value="Sign In"></form></body></html>`,
			anomaly: "pulse-vpn-login-attempt",
		}
	case "citrix_gateway":
		// Citrix Gateway / NetScaler.
		return mgmtPersona{
			server:   "Citrix NetScaler",
			authType: "",
			title:    "Citrix Gateway",
			bodyHTML: `<html><head><title>Citrix Gateway</title></head>` +
				`<body><form action="/cgi/login" method="post">` +
				`<input name="login"><input type="password" name="passwd">` +
				`<input type="submit" value="Log On"></form></body></html>`,
			anomaly: "citrix-gateway-login-attempt",
		}
	case "horizon":
		// VMware Horizon view portal.
		return mgmtPersona{
			server:   "VMware View",
			authType: "",
			title:    "VMware Horizon",
			bodyHTML: `<html><head><title>VMware Horizon</title></head>` +
				`<body><h1>VMware Horizon</h1><a href="/portal/webclient/">HTML Access</a></body></html>`,
			anomaly: "horizon-login-attempt",
		}
	case "moxa_mgmt":
		// Moxa device-management web (e.g. NPort / EDS web admin).
		return mgmtPersona{
			server:   "MoxaHttp/1.0",
			realm:    "",
			authType: "",
			title:    "Moxa",
			bodyHTML: `<html><head><title>Moxa</title></head>` +
				`<body><h1>Moxa Web Console</h1>` +
				`<form action="/Login.asp" method="post">` +
				`<input name="Username"><input type="password" name="Password">` +
				`<input type="submit" value="Login"></form></body></html>`,
			anomaly: "moxa-mgmt-login-attempt",
		}
	}
	return mgmtPersona{server: "Server", title: "Login", authType: "Basic", realm: "admin", anomaly: "mgmt-login-attempt"}
}

func (m *mgmtWeb) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	p := personaFor(m.kind)

	br := bufio.NewReader(conn)
	capBytes := cfg.ReadBytes
	if capBytes <= 0 {
		capBytes = 4096
	}
	var buf bytes.Buffer
	for buf.Len() < capBytes {
		b, err := br.ReadByte()
		if err != nil {
			res.Meta["read_err"] = err.Error()
			break
		}
		buf.WriteByte(b)
		if bytes.HasSuffix(buf.Bytes(), []byte("\r\n\r\n")) {
			break
		}
	}
	res.Payload = buf.Bytes()

	firstLine, method, path, authz := "", "", "", ""
	for i, line := range strings.Split(buf.String(), "\r\n") {
		if i == 0 {
			firstLine = line
			if f := strings.Fields(line); len(f) >= 2 {
				method, path = f[0], f[1]
			}
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "authorization:") {
			authz = strings.TrimSpace(line[14:])
		}
	}
	res.Meta["request_line"] = safe.SanitizeForLog(firstLine)
	res.Meta["persona"] = m.kind

	// Capture credentials from Authorization or a posted login form.
	captured := false
	if authz != "" {
		res.Meta["authorization"] = safe.SanitizeForLog(authz)
		if u, pw, ok := decodeBasic(authz); ok {
			res.Meta["basic_user"] = safe.SanitizeForLog(u)
			res.Meta["basic_pass"] = safe.SanitizeForLog(pw)
			flagDefaultCred(&res, u, pw)
			captured = true
		}
	}
	if method == "POST" {
		// Drain a small body and try to parse the login form.
		body := make([]byte, 2048)
		n, _ := br.Read(body)
		if u, pw := parseLoginForm(body[:n]); u != "" || pw != "" {
			res.Meta["form_user"] = safe.SanitizeForLog(u)
			res.Meta["form_pass"] = safe.SanitizeForLog(pw)
			flagDefaultCred(&res, u, pw)
			captured = true
		}
	}
	if captured {
		flagAnomaly(&res, p.anomaly)
	}

	// Build the response. Personas with an auth realm return 401 with
	// the characteristic WWW-Authenticate header on the root unless
	// creds were supplied; the VPN portals serve their login page 200.
	var resp string
	if p.authType != "" && !captured && (path == "/" || path == "" || strings.HasPrefix(path, "/index")) {
		resp = m.build401(p)
	} else {
		resp = m.build200(p)
	}
	if _, err := conn.Write([]byte(resp)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = m.kind + " mgmt web"
	return res, nil
}

func (m *mgmtWeb) build401(p mgmtPersona) string {
	var b strings.Builder
	b.WriteString("HTTP/1.1 401 Unauthorized\r\n")
	if p.server != "" {
		b.WriteString("Server: " + safe.SanitizeHeader(p.server) + "\r\n")
	}
	switch p.authType {
	case "Digest":
		b.WriteString("WWW-Authenticate: Digest realm=\"" + safe.SanitizeHeader(p.realm) +
			"\", nonce=\"deadbeefcafebabe\", stale=\"false\", qop=\"auth\"\r\n")
	case "Basic":
		b.WriteString("WWW-Authenticate: Basic realm=\"" + safe.SanitizeHeader(p.realm) + "\"\r\n")
	}
	b.WriteString("Content-Length: 0\r\nConnection: close\r\n\r\n")
	return b.String()
}

func (m *mgmtWeb) build200(p mgmtPersona) string {
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK\r\n")
	if p.server != "" {
		b.WriteString("Server: " + safe.SanitizeHeader(p.server) + "\r\n")
	}
	b.WriteString("Content-Type: text/html\r\n")
	b.WriteString("Content-Length: " + itoa(len(p.bodyHTML)) + "\r\n")
	b.WriteString("Connection: close\r\n\r\n")
	b.WriteString(p.bodyHTML)
	return b.String()
}

// decodeBasic decodes an "Authorization: Basic <b64>" value into
// user/pass.
func decodeBasic(authz string) (string, string, bool) {
	if !strings.HasPrefix(authz, "Basic ") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(authz[6:]))
	if err != nil {
		return "", "", false
	}
	i := strings.IndexByte(string(raw), ':')
	if i < 0 {
		return "", "", false
	}
	return string(raw[:i]), string(raw[i+1:]), true
}
