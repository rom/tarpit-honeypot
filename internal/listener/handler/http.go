package handler

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/safe"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

type httpH struct {
	urlCanaries []config.URLCanary
	id          *identity.Identity
	jit         *jitter.Jitterer
	arch        *archetype.Profile
	vuln        bool
}

func (h *httpH) Name() string { return "http" }

// Plausible nginx-ish 401 response that captures the request line + headers.
// We read until \r\n\r\n (end of headers) or the read cap, whichever is first.
// Any request whose path exactly matches a configured URL canary is recorded
// in res.CanaryHits — the listener turns those into separate critical events.
// The Server: header is randomized per-deployment to defeat banner clustering,
// and JA4H is computed over the request line + headers.
func (h *httpH) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	h.jit.Sleep(ctx)
	return serveHTTP(conn, cfg, h.urlCanaries, h.id, h.arch, h.vuln)
}

func serveHTTP(conn net.Conn, cfg config.Listener, canaries []config.URLCanary, id *identity.Identity, arch *archetype.Profile, vuln bool) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}

	br := bufio.NewReader(conn)
	cap := cfg.ReadBytes
	if cap <= 0 {
		cap = 4096
	}
	// HTTP/2 cleartext with prior knowledge: the connection opens with the h2c
	// preface. Branch to the HTTP/2 capture path (real HPACK + multiplexed-
	// stream reconstruction) instead of the line-based HTTP/1.x parser.
	if pre, _ := br.Peek(len(http2Preface)); bytes.Equal(pre, http2Preface) {
		_, _ = br.Discard(len(http2Preface))
		captureHTTP2(conn, br, cfg, &res)
		return res, nil
	}
	var buf bytes.Buffer
	for buf.Len() < cap {
		b, err := br.ReadByte()
		if err != nil {
			res.Meta = map[string]any{"read_err": err.Error()}
			break
		}
		buf.WriteByte(b)
		if bytes.HasSuffix(buf.Bytes(), []byte("\r\n\r\n")) {
			break
		}
	}
	res.Payload = buf.Bytes()

	firstLine := ""
	host := ""
	userAgent := ""
	var headerKeys []string
	allHeaders := map[string]string{}
	authHeader := ""
	cookieHeader := ""
	referer := ""
	contentLen := 0
	contentType := ""
	malformedHeader := false
	hostCount := 0
	transferEnc := false
	sawBlank := false
	for i, line := range strings.Split(string(buf.Bytes()), "\r\n") {
		if i == 0 {
			firstLine = line
			continue
		}
		if line == "" {
			sawBlank = true // end of the header section
			continue
		}
		if sawBlank {
			continue // body bytes — not headers
		}
		lower := strings.ToLower(line)
		k := strings.IndexByte(lower, ':')
		if k <= 0 {
			// A non-empty header line with no name:value colon is malformed
			// (header smuggling / a non-HTTP client).
			malformedHeader = true
			continue
		}
		headerKeys = append(headerKeys, lower[:k])
		// Capture every header (name -> value) for the detail page, bounded so
		// a hostile client can't blow up memory with thousands of headers.
		if len(allHeaders) < 64 {
			name := strings.TrimSpace(lower[:k])
			if _, dup := allHeaders[name]; !dup {
				allHeaders[name] = safe.SanitizeForLog(clipStr(strings.TrimSpace(line[k+1:]), 1024))
			}
		}
		// Control bytes embedded in a header line are a smuggling / evasion
		// tell (the line was already split on CRLF, so any control byte here
		// is illegitimate).
		if hasNonPrintable(line) {
			malformedHeader = true
		}
		switch {
		case strings.HasPrefix(lower, "host:"):
			hostCount++
			host = strings.TrimSpace(line[5:])
		case strings.HasPrefix(lower, "user-agent:"):
			userAgent = strings.TrimSpace(line[11:])
		case strings.HasPrefix(lower, "authorization:"):
			authHeader = strings.TrimSpace(line[14:])
		case strings.HasPrefix(lower, "cookie:"):
			cookieHeader = strings.TrimSpace(line[7:])
		case strings.HasPrefix(lower, "referer:"):
			referer = strings.TrimSpace(line[8:])
		case strings.HasPrefix(lower, "content-length:"):
			n := 0
			for _, c := range strings.TrimSpace(line[15:]) {
				if c < '0' || c > '9' {
					break
				}
				n = n*10 + int(c-'0')
				if n > 1<<20 { // 1 MiB cap on body
					n = 1 << 20
					break
				}
			}
			contentLen = n
		case strings.HasPrefix(lower, "content-type:"):
			contentType = strings.TrimSpace(line[13:])
		case strings.HasPrefix(lower, "transfer-encoding:"):
			transferEnc = true
		}
	}
	// Read the request body (capped) so POSTed login-form credentials
	// land in res.Meta.
	var body []byte
	if contentLen > 0 && contentLen <= cap {
		body = make([]byte, contentLen)
		// Best-effort read; we don't care if it short-reads.
		_, _ = io.ReadFull(br, body)
		res.Payload = append(res.Payload, body...)
	}
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	res.Meta["request_line"] = firstLine
	res.Meta["host"] = host
	if userAgent != "" {
		res.Meta["user_agent"] = safe.SanitizeForLog(userAgent)
	}

	// Full request capture: method, the full URI + parsed query params, every
	// request header, cookies, and any bearer/basic credential. The detail page
	// renders these; cookies + tokens additionally surface on the captures page
	// (extractCreds keys off "cookie" / "authorization" / "bearer_token").
	if m := extractMethod(firstLine); m != "" {
		res.Meta["http_method"] = m
	}
	if tgt := extractTarget(firstLine); tgt != "" {
		res.Meta["http_uri"] = safe.SanitizeForLog(clipStr(tgt, 2048))
		if qp := parseQueryParams(tgt); len(qp) > 0 {
			res.Meta["http_query_params"] = qp
		}
	}
	if len(allHeaders) > 0 {
		res.Meta["http_headers"] = allHeaders
	}
	if cookieHeader != "" {
		res.Meta["cookie"] = safe.SanitizeForLog(clipStr(cookieHeader, 2048))
		if cm := parseCookies(cookieHeader); len(cm) > 0 {
			res.Meta["http_cookies"] = cm
		}
	}
	if authHeader != "" {
		res.Meta["authorization"] = safe.SanitizeForLog(clipStr(authHeader, 1024))
		if tok := bearerToken(authHeader); tok != "" {
			res.Meta["bearer_token"] = safe.SanitizeForLog(clipStr(tok, 1024))
		}
	}
	if referer != "" {
		res.Meta["referer"] = safe.SanitizeForLog(clipStr(referer, 1024))
	}
	// JavaScript carried in the request (stored-XSS / SSTI / template-injection
	// payloads) — capture the snippets and flag, never execute.
	if js := extractJavaScript(string(res.Payload)); len(js) > 0 {
		res.Meta["http_javascript"] = js
		flagAnomaly(&res, "http-javascript-payload")
	}

	// Tool fingerprinting + human-vs-automation heuristic.
	verdict := toolfp.IdentifyHTTP(toolfp.HTTPSignals{
		Method:     extractMethod(firstLine),
		Path:       extractPath(firstLine),
		UserAgent:  userAgent,
		HeaderKeys: headerKeys,
	})
	if len(verdict.Tools) > 0 {
		res.Meta["tools"] = verdict.Tools
		flagAnomaly(&res, "tool:"+verdict.Tools[0])
	}
	if verdict.Confidence > 0 {
		res.Meta["tool_confidence"] = verdict.Confidence
		res.Meta["tool_confidence_label"] = toolfp.ConfidenceLabel(verdict.Confidence)
	}
	if verdict.Scanner {
		flagAnomaly(&res, "vulnerability-scanner")
	}
	switch verdict.Category {
	case "c2":
		flagAnomaly(&res, "c2-framework")
	case "headless":
		flagAnomaly(&res, "headless-browser")
	}
	// Cobalt Strike default checksum8 staging URI — record the beacon stager
	// architecture (high-signal, malleable-profile-independent).
	if arch, ok := toolfp.CobaltStrikeStager(extractPath(firstLine)); ok {
		flagAnomaly(&res, "cobaltstrike-stager")
		res.Meta["cobaltstrike_stager_arch"] = arch
	}
	res.Meta["automation"] = verdict.Automation
	res.Meta["automation_reason"] = verdict.Reason
	if verdict.Automation {
		flagAnomaly(&res, "automation-client")
	}

	// Behavioral HTTP anomalies.
	if malformedHeader {
		flagAnomaly(&res, "http-malformed-header")
	}
	if hostCount > 1 {
		// Multiple Host headers is a request-smuggling / cache-poisoning tell.
		flagAnomaly(&res, "http-duplicate-host")
	}
	if transferEnc && contentLen > 0 {
		// Both Transfer-Encoding and Content-Length present = the CL.TE / TE.CL
		// ambiguity front-ends and back-ends disagree on — HTTP request smuggling.
		flagAnomaly(&res, "http-request-smuggling")
	}
	if extractMethod(firstLine) == "CONNECT" {
		// CONNECT to an origin server (not a proxy) = open-proxy / tunnel abuse.
		flagAnomaly(&res, "http-connect-proxy")
	}
	if impossibleBrowser(userAgent, headerKeys) {
		// The UA claims a full browser but the request is missing the
		// Accept-* header set every real browser sends — a spoofed UA.
		flagAnomaly(&res, "http-impossible-browser")
	}

	// JA4H fingerprint over method+version+header order/values.
	if raw, hash := fingerprint.JA4H(buf.Bytes()); hash != "" {
		res.Meta["ja4h"] = hash
		res.Meta["ja4h_raw"] = raw
	}

	// URL canary match: parse the path out of the request line.
	if path := extractPath(firstLine); path != "" {
		for _, c := range canaries {
			if c.Path == path {
				res.CanaryHits = append(res.CanaryHits, c.ID)
			}
		}
		if marker := suspiciousURI(path); marker != "" {
			flagAnomaly(&res, marker)
		}
		// DNS-over-HTTPS (RFC 8484): a DoH client targets /dns-query (or
		// carries the application/dns-message media type). Tunnelling DNS
		// inside HTTPS evades DNS monitoring (T1572 / T1071.004).
		if isDoHRequest(path, headerKeys, res.Payload) {
			flagAnomaly(&res, "dns-over-https")
		}
	}
	// Also scan the full request line — Log4Shell / RCE payloads
	// frequently live in the query string, which extractPath
	// strips off.
	if marker := suspiciousURI(firstLine); marker != "" {
		flagAnomaly(&res, marker)
	}

	// CVE exploit-attempt recognition. Scan the whole request (line +
	// headers + body) for known exploit signatures. Detection only —
	// we never execute the exploit. Each hit becomes a separate
	// cve:<id> event at the listener.
	for _, rec := range cve.MatchPayload("http", string(res.Payload)) {
		res.CVEHits = appendUnique(res.CVEHits, rec.ID)
		flagAnomaly(&res, "cve:"+rec.ID)
	}

	// Web-attack-class detection over the whole request — SSTI / XXE / SSRF /
	// deserialization / NoSQLi / GraphQL introspection / JWT-none — classes the
	// path-only and CVE-signature checks don't catch.
	for _, marker := range httpAttackClasses(string(res.Payload)) {
		flagAnomaly(&res, marker)
	}

	// Method-level anomaly: legit clients use a small set; everything
	// else (binary blobs, "ATTACK", junk) is a worth-tagging.
	if method := extractMethod(firstLine); method != "" && !isKnownHTTPMethod(method) {
		flagAnomaly(&res, "http-method-unknown")
	}
	if hasNonPrintable(firstLine) {
		flagAnomaly(&res, "http-request-line-non-printable")
	}

	server := "nginx/1.18.0"
	switch {
	case arch != nil && arch.HTTPServer() != "":
		server = arch.HTTPServer()
	case id != nil:
		server = id.HTTPServerHeader()
	}
	// Vulnerable-banner emulation: when enabled, prefer the archetype's
	// deliberately-unpatched HTTP banner and surface the fake patch
	// level so a version scanner records an exploitable box.
	if vuln && arch != nil {
		if vb := arch.VulnBanner("http"); vb != "" {
			server = vb
		}
		if pl := arch.PatchLevel(); pl != "" {
			res.Meta["patch_level"] = pl
		}
		if cves := arch.VulnCVEs(); len(cves) > 0 {
			res.Meta["emulated_vuln_cves"] = cves
		}
	}
	banner := cfg.Banner
	if banner == "" && cfg.Webapp {
		// Full fake-vulnerable web application mode: a self-contained
		// multi-page app that detects (never executes) the web-attack
		// families. Works over both http and https (https calls serveHTTP).
		banner = serveWebappVariant(firstLine, body, server, id, &res, cfg.WebappVariant, cfg.WebappBrand)
	}
	if banner == "" {
		method := extractMethod(firstLine)
		path := extractPath(firstLine)
		// Web-deception trio: robots.txt / security.txt / sitemap.xml, plus
		// detection of probes against the bait Disallow / sitemap paths. A
		// sitemap page may be delivered slowly (tarpit) by serveWebDeception
		// itself, in which case it returns the sentinel and we skip our write.
		if wd := serveWebDeception(conn, cfg.WebDeception, method, path, server, &res); wd != "" {
			if wd == sentinelHandled {
				return res, nil
			}
			banner = wd
		}
		// Fake web shell: detect c99/r57/wso/China-Chopper-style paths and
		// command parameters. Always capture + flag; serve a working-looking
		// shell (canned output, never executed) only when vuln emulation is
		// on — active deception is opt-in and loud by design.
		if wsHit, wsCmd := detectWebshell(extractTarget(firstLine), body, contentType); wsHit {
			if page := handleWebshell(&res, arch, wsCmd, vuln); page != "" {
				banner = renderHTTPResponse(server, 200, "text/html; charset=utf-8", page)
			}
		}
		if banner != "" {
			// served the fake shell above
		} else if method == "POST" && isLoginPath(path) && isFormBody(contentType) {
			user, pass := parseLoginForm(body)
			if user != "" || pass != "" {
				res.Meta["http_login_user"] = safe.SanitizeForLog(user)
				res.Meta["http_login_pass"] = safe.SanitizeForLog(pass)
				flagAnomaly(&res, "http-login-attempt")
			}
			banner = renderHTTPResponse(server, 401, "text/html; charset=utf-8",
				loginRetryPage(arch))
		} else if arch != nil && method == "GET" && isSwitchInfoPath(path) && hasSwitchTopology(arch) {
			// Switch-class archetypes expose an OT topology view
			// (MRP rings / PROFINET device tree / VLANs / HMIs) on
			// the device-info / status paths their web UI uses.
			banner = renderHTTPResponse(server, 200, "text/html; charset=utf-8",
				switchTopologyHTML(arch))
		} else if arch != nil && method == "GET" && isLoginPath(path) {
			// GET on a login path returns an archetype-shaped
			// login form so an unauth scanner sees the field
			// names + form action it would expect.
			banner = renderHTTPResponse(server, 200, "text/html; charset=utf-8",
				loginFormPage(arch))
		} else if arch != nil && arch.HTTPBodyHTML() != "" {
			// Default: archetype's index page.
			banner = renderHTTPResponse(server, 200, "text/html; charset=utf-8",
				arch.HTTPBodyHTML())
		} else {
			// No archetype web body: emulate the resolved server
			// flavor (Apache / nginx) with its version-appropriate
			// default pages. GET / -> 200 "It works!"/welcome;
			// any other path -> a flavored 404 whose error-page
			// footer matches the Server header — defeating the
			// "404 body doesn't match the Server" honeypot tell.
			flavor := flavorFromServer(server)
			hostForFooter := host
			if hostForFooter == "" {
				hostForFooter = "localhost"
			}
			switch {
			case flavor == flavorGeneric:
				// Unknown flavor: keep the v1.0 nginx-ish 401 realm.
				banner = "HTTP/1.1 401 Unauthorized\r\n" +
					"Server: " + server + "\r\n" +
					"WWW-Authenticate: Basic realm=\"admin\"\r\n" +
					"Content-Length: 0\r\n" +
					"Connection: close\r\n\r\n"
			case path == "/" || path == "":
				idxBody, idxCT := defaultIndexPage(flavor, server)
				banner = renderHTTPResponse(server, 200, idxCT, idxBody)
			default:
				banner = buildErrorResponse(flavor, 404, server, hostForFooter, id)
			}
		}
	}
	// Inject the archetype's extra response headers (X-Powered-By, vendor
	// Set-Cookie, custom realm, ...) into responses we generated, so each
	// device presents its distinctive header set.
	if arch != nil {
		banner = applyArchHeaders(banner, arch.HTTPHeaders())
	}
	if _, err := conn.Write([]byte(banner)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = banner
	return res, nil
}

// applyArchHeaders inserts extra headers into an HTTP response before the
// blank-line body separator. No-op when there are no headers, the response
// isn't one we generated (HTTP/...), or it has no header/body boundary.
func applyArchHeaders(resp string, headers map[string]string) string {
	if len(headers) == 0 || !strings.HasPrefix(resp, "HTTP/") {
		return resp
	}
	sep := strings.Index(resp, "\r\n\r\n")
	if sep < 0 {
		return resp
	}
	var b strings.Builder
	for k, v := range headers {
		b.WriteString(safe.SanitizeHeader(k))
		b.WriteString(": ")
		b.WriteString(safe.SanitizeHeader(v))
		b.WriteString("\r\n")
	}
	return resp[:sep+2] + b.String() + resp[sep+2:]
}

// renderHTTPResponse builds a complete HTTP response with the given
// status, body, and Server header. The Server header value is run
// through safe.SanitizeHeader as defense-in-depth.
func renderHTTPResponse(server string, status int, contentType, body string) string {
	statusLine := ""
	switch status {
	case 200:
		statusLine = "200 OK"
	case 401:
		statusLine = "401 Unauthorized"
	case 403:
		statusLine = "403 Forbidden"
	case 404:
		statusLine = "404 Not Found"
	default:
		statusLine = "200 OK"
	}
	return "HTTP/1.1 " + statusLine + "\r\n" +
		"Server: " + safe.SanitizeHeader(server) + "\r\n" +
		"Content-Type: " + safe.SanitizeHeader(contentType) + "\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" +
		body
}

// isLoginPath returns true when the request path matches any of the
// well-known login URIs used by the archetype family or generic
// web-admin software. The set is intentionally broad so a scanner
// that pokes "/admin/login.php" gets credentials-captured the same
// way a Moxa-aware scanner poking "/main.htm" does.
func isLoginPath(p string) bool {
	switch p {
	case "/", "/login", "/login.html", "/login.htm", "/login.php",
		"/admin", "/admin/", "/admin/login", "/admin/login.php",
		"/main.htm", "/main.html",
		"/cgi-bin/luci", "/cgi-bin/login",
		"/Portal/Login.html", "/Portal/Portal.mwsl",
		"/wp-login.php",
		"/manager/html",
		"/users/sign_in":
		return true
	}
	return false
}

// isFormBody reports whether the Content-Type indicates a urlencoded
// or multipart form (the two shapes login pages submit).
func isFormBody(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.HasPrefix(lower, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(lower, "multipart/form-data")
}

// parseLoginForm extracts the user / pass fields from a urlencoded
// form body. We accept the common names (username/user/login/name and
// password/pass/passwd). Returns ("","") when the body doesn't look
// like a form.
func parseLoginForm(body []byte) (user, pass string) {
	if len(body) == 0 {
		return "", ""
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", ""
	}
	for _, k := range []string{"username", "user", "login", "name", "uname", "u"} {
		if v := values.Get(k); v != "" {
			user = v
			break
		}
	}
	for _, k := range []string{"password", "pass", "passwd", "pwd", "p"} {
		if v := values.Get(k); v != "" {
			pass = v
			break
		}
	}
	return user, pass
}

// loginFormPage returns the archetype's login HTML body, falling
// back to a generic form. Used for GET on a login path.
func loginFormPage(arch *archetype.Profile) string {
	if arch != nil && arch.HTTPBodyHTML() != "" {
		// The default index page already contains a login form for
		// Moxa / SCALANCE / S7. Just serve it.
		return arch.HTTPBodyHTML()
	}
	return `<html><head><title>Login</title></head><body>` +
		`<h2>Sign in</h2>` +
		`<form method="POST" action="/login">` +
		`<label>Username: <input name="username"></label><br>` +
		`<label>Password: <input type="password" name="password"></label><br>` +
		`<input type="submit" value="Login"></form></body></html>`
}

// loginRetryPage is what we show after a failed credential POST. A
// real device wouldn't tell the scanner WHY auth failed — it'd just
// re-render the form with a generic "wrong credentials" line.
func loginRetryPage(arch *archetype.Profile) string {
	title := "Login"
	if arch != nil && arch.HTTPTitle() != "" {
		title = arch.HTTPTitle()
	}
	return `<html><head><title>` + safe.SanitizeForLog(title) + `</title></head><body>` +
		`<h2>` + safe.SanitizeForLog(title) + `</h2>` +
		`<p style="color:red">Authentication failed. Please try again.</p>` +
		`<form method="POST" action="/login">` +
		`<label>Username: <input name="username"></label><br>` +
		`<label>Password: <input type="password" name="password"></label><br>` +
		`<input type="submit" value="Login"></form></body></html>`
}

// extractPath returns the path portion of an HTTP request line like
// "GET /admin?x=1 HTTP/1.1". The query string is stripped because canary
// matching should be path-only.
func extractPath(reqLine string) string {
	parts := strings.SplitN(reqLine, " ", 3)
	if len(parts) < 2 {
		return ""
	}
	p := parts[1]
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return p
}

// impossibleBrowser reports whether a User-Agent claims a full graphical
// browser (Mozilla/5.0 token) while the request omits the Accept-* header
// set every real browser sends — a strong UA-spoofing / masquerade tell.
func impossibleBrowser(ua string, headerKeys []string) bool {
	if !strings.Contains(strings.ToLower(ua), "mozilla/5.0") {
		return false
	}
	has := make(map[string]bool, len(headerKeys))
	for _, k := range headerKeys {
		has[k] = true
	}
	missing := 0
	for _, h := range []string{"accept", "accept-language", "accept-encoding"} {
		if !has[h] {
			missing++
		}
	}
	return missing >= 2
}

// isDoHRequest reports whether an HTTP request looks like DNS-over-HTTPS
// (RFC 8484): the well-known /dns-query path, or the application/dns-message
// media type in an Accept / Content-Type header.
func isDoHRequest(path string, headerKeys []string, payload []byte) bool {
	if strings.Contains(strings.ToLower(path), "/dns-query") {
		return true
	}
	hasCT := false
	for _, k := range headerKeys {
		if k == "content-type" || k == "accept" {
			hasCT = true
			break
		}
	}
	return hasCT && strings.Contains(strings.ToLower(string(payload)), "application/dns-message")
}

// extractMethod returns the first whitespace-separated token of the
// request line. The HTTP spec restricts method tokens to a small
// printable set; the anomaly detector flags anything outside our
// known list.
// extractTarget returns the request target (path + query) — unlike
// extractPath it keeps the query string, which web-shell command
// parameters live in.
func extractTarget(reqLine string) string {
	parts := strings.SplitN(reqLine, " ", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func extractMethod(reqLine string) string {
	if i := strings.IndexByte(reqLine, ' '); i > 0 {
		return reqLine[:i]
	}
	return ""
}

// clipStr bounds a captured string so a hostile client can't bloat an event.
func clipStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// parseQueryParams pulls the query string off a request target and returns its
// decoded key->value(s) as sanitized strings, bounded so a huge query can't
// blow up the event. Multi-valued keys are joined with ", ".
func parseQueryParams(target string) map[string]string {
	i := strings.IndexByte(target, '?')
	if i < 0 || i == len(target)-1 {
		return nil
	}
	vals, err := url.ParseQuery(target[i+1:])
	if err != nil || len(vals) == 0 {
		return nil
	}
	out := make(map[string]string, len(vals))
	for k, vs := range vals {
		if len(out) >= 64 {
			break
		}
		out[safe.SanitizeForLog(clipStr(k, 256))] = safe.SanitizeForLog(clipStr(strings.Join(vs, ", "), 1024))
	}
	return out
}

// parseCookies splits a Cookie header into individual name->value pairs.
func parseCookies(header string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		if name == "" || len(out) >= 64 {
			continue
		}
		out[safe.SanitizeForLog(clipStr(name, 256))] = safe.SanitizeForLog(clipStr(strings.TrimSpace(val), 1024))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// bearerToken returns the token from a "Bearer <token>" Authorization header
// (the high-value credential to surface on the captures page); "" otherwise.
func bearerToken(auth string) string {
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

// extractJavaScript returns up to a few <script>…</script> bodies and
// javascript:/on*= handler snippets found in the request — stored-XSS / SSTI
// payloads worth capturing verbatim. Detection only; nothing is ever executed.
func extractJavaScript(payload string) []string {
	low := strings.ToLower(payload)
	if !strings.Contains(low, "<script") && !strings.Contains(low, "javascript:") && !strings.Contains(low, "onerror=") && !strings.Contains(low, "onload=") {
		return nil
	}
	var out []string
	// <script ...>BODY</script>
	rest := payload
	restLow := low
	for len(out) < 5 {
		open := strings.Index(restLow, "<script")
		if open < 0 {
			break
		}
		gt := strings.IndexByte(rest[open:], '>')
		if gt < 0 {
			break
		}
		bodyStart := open + gt + 1
		end := strings.Index(restLow[bodyStart:], "</script")
		var snippet string
		if end < 0 {
			snippet = rest[open:]
		} else {
			snippet = rest[open : bodyStart+end+len("</script>")]
		}
		out = append(out, safe.SanitizeForLog(clipStr(strings.TrimSpace(snippet), 2048)))
		if end < 0 {
			break
		}
		adv := bodyStart + end + len("</script")
		if adv >= len(rest) {
			break
		}
		rest = rest[adv:]
		restLow = restLow[adv:]
	}
	// Inline handlers / javascript: URIs (only if no <script> blocks captured).
	if len(out) == 0 {
		for _, marker := range []string{"javascript:", "onerror=", "onload="} {
			if idx := strings.Index(low, marker); idx >= 0 {
				snippet := payload[idx:]
				out = append(out, safe.SanitizeForLog(clipStr(strings.TrimSpace(snippet), 512)))
			}
		}
	}
	return out
}
