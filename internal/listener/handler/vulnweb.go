package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// vulnweb implements a "full" fake-vulnerable web application, enabled per
// listener with `webapp: true` on an http / https listener. It serves a
// believable multi-page PHP/MySQL-flavored app (login, search, product,
// file download, a JSON API, plus the juicy paths scanners probe) whose
// endpoints LOOK exploitable so an attacker engages and reveals TTPs — but
// nothing is ever executed. Every request is classified for the web-attack
// families (SQLi / XSS / LFI / RFI / SSRF / command injection / SSTI /
// Log4Shell / XXE / insecure deserialization) and the attempt is flagged;
// some endpoints return deliberately fake "loot" (a fake /etc/passwd, a
// fake .env) as active deception. Reflected input is always HTML-escaped so
// the honeypot itself is never a real XSS vector.

// webAttackClass is one detected attack family + the substrings that
// identify it (matched case-insensitively over the request target + body).
type webAttackClass struct {
	name     string
	patterns []string
}

var webAttackClasses = []webAttackClass{
	{"sqli", []string{
		"' or ", "\" or ", "' or '", " or 1=1", "or 1=1--", "union select",
		"union all select", "information_schema", "' --", "'--", "'#",
		" and 1=1", "' and ", "sleep(", "benchmark(", "waitfor delay",
		"extractvalue(", "updatexml(", "group_concat", "concat(", "%27 or",
		"' union", "1=1#", "admin'--", "pg_sleep(",
	}},
	{"xss", []string{
		"<script", "</script", "onerror=", "onload=", "onmouseover=",
		"javascript:", "<svg", "<img ", "alert(", "prompt(", "document.cookie",
		"%3cscript", "onfocus=", "<iframe",
	}},
	{"lfi", []string{
		"../", "..\\", "..%2f", "%2e%2e%2f", "..%5c", "....//", "/etc/passwd",
		"/etc/shadow", "/proc/self/environ", "/proc/self/cmdline", "win.ini",
		"php://filter", "php://input", "file://", "/var/log/", "boot.ini",
	}},
	{"rfi_ssrf", []string{
		"=http://", "=https://", "=ftp://", "gopher://", "dict://", "=//",
		"169.254.169.254", "metadata.google", "localhost:", "127.0.0.1:",
	}},
	{"cmdi", []string{
		";id", "|id", "$(", "`id`", ";cat ", ";ls", ";uname", "|whoami",
		"wget ", "curl ", "nc -", "bash -i", "/bin/sh", "/bin/bash", "%0acat",
		";sleep ", "&&cat", "|nc ",
	}},
	{"ssti", []string{
		"{{7*7}}", "{{7*'7'}}", "${7*7}", "<%= 7*7", "#{7*7}", "{{config",
		"${jndi", "{{request", "*{7*7}", "@(7*7)",
	}},
	{"log4shell", []string{"${jndi:", "jndi:ldap", "jndi:rmi", "jndi:dns", "${env:", "${lower:j}"}},
	{"xxe", []string{"<!entity", "<!doctype", "system \"file:", "system \"http:", "system 'file:"}},
	{"deserialize", []string{"ro0ab", "aced0005", "o:8:\"", "a:2:{", "__proto__", "constructor.prototype"}},
}

// classifyWebAttacks returns the distinct attack-family names whose
// signatures appear in s (already lower-cased by the caller).
func classifyWebAttacks(low string) []string {
	var hits []string
	for _, c := range webAttackClasses {
		for _, p := range c.patterns {
			if strings.Contains(low, p) {
				hits = append(hits, c.name)
				break
			}
		}
	}
	return hits
}

// serveWebapp routes one request through the fake app and returns the full
// HTTP response. It records detected attack classes + captured credentials
// into res. id/arch supply per-deployment identity (app name, version,
// session cookie) so two sensors don't look identical.
func serveWebapp(reqLine string, body []byte, server string, id *identity.Identity, res *Result) string {
	method := extractMethod(reqLine)
	target := extractTarget(reqLine)
	path := extractPath(reqLine)
	rawQuery := ""
	if i := strings.IndexByte(target, '?'); i >= 0 {
		rawQuery = target[i+1:]
	}

	// Attack classification over the decoded target + body. Decode percent-
	// encoding once so "%2e%2e%2f" and "../" both match.
	decTarget, _ := url.QueryUnescape(target)
	scanText := strings.ToLower(decTarget + "\n" + target + "\n" + string(body))
	if attacks := classifyWebAttacks(scanText); len(attacks) > 0 {
		res.Meta["webapp_attacks"] = attacks
		for _, a := range attacks {
			flagAnomaly(res, "webapp:"+a)
		}
	}

	app := webappName(id)
	hc := webappHoneyCreds(id)
	cookie := "Set-Cookie: PHPSESSID=" + webappSessionID(id) + "; path=/; HttpOnly"
	q := parseQuery(rawQuery)

	switch {
	case path == "/" || path == "/index.php" && rawQuery == "":
		// index.php with a ?page= is the LFI surface; bare index is the home.
		if page := q.Get("page"); page != "" {
			return webappFileResponse(server, page, app, cookie, res)
		}
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", webappHome(app), []string{cookie})

	case isWebappLoginPath(path):
		if method == "POST" {
			return webappLogin(server, body, app, cookie, res)
		}
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", webappLoginPage(app, ""), []string{cookie})

	case path == "/search" || path == "/search.php":
		return webappSearch(server, q.Get("q"), app, cookie)

	case path == "/product.php" || path == "/product" || path == "/item.php":
		return webappProduct(server, q.Get("id"), app, cookie, res)

	case path == "/download" || path == "/download.php" || path == "/view.php" || path == "/index.php":
		f := q.Get("file")
		if f == "" {
			f = q.Get("page")
		}
		return webappFileResponse(server, f, app, cookie, res)

	case path == "/api/users" || path == "/api/user" || path == "/api/user.php":
		return webappAPIUser(server, q.Get("id"))

	case path == "/robots.txt":
		body := "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /config.php.bak\nDisallow: /.env\nDisallow: /api/\n"
		return webappResponse(server, 200, "OK", "text/plain", body, nil)

	case path == "/.env" || path == "/.env.bak":
		flagAnomaly(res, "webapp:secret-file-probe")
		res.Meta["honeytoken"] = hc.dbPass
		return webappResponse(server, 200, "OK", "text/plain", webappFakeEnv(app, hc), nil)

	case path == "/.git/config":
		flagAnomaly(res, "webapp:secret-file-probe")
		body := "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://git.internal/" + app + ".git\n"
		return webappResponse(server, 200, "OK", "text/plain", body, nil)

	case path == "/config.php.bak" || path == "/config.php~" || path == "/backup.zip":
		flagAnomaly(res, "webapp:secret-file-probe")
		res.Meta["honeytoken"] = hc.dbPass
		return webappResponse(server, 200, "OK", "text/plain", webappFakeConfig(app, hc), nil)

	case path == "/phpinfo.php" || path == "/info.php":
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", webappPhpinfo(id), nil)

	case strings.HasPrefix(path, "/admin"):
		// Unauthenticated admin → bounce to login (believable).
		return webappResponse(server, 302, "Found", "text/html", "", []string{"Location: /login.php", cookie})
	}
	// Unknown path → a PHP-app-flavored 404.
	return webappResponse(server, 404, "Not Found", "text/html; charset=UTF-8",
		"<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL "+
			htmlEscape(path)+" was not found on this server.</p></body></html>", nil)
}

// webappLogin captures credentials, flags default-cred + SQLi auth-bypass
// attempts, and returns a believable failure (or a fake MySQL error when
// the input is a SQLi probe — the "this field is injectable" deception).
func webappLogin(server string, body []byte, app, cookie string, res *Result) string {
	user, pass := parseLoginForm(body)
	if user != "" || pass != "" {
		res.Meta["http_login_user"] = safe.SanitizeForLog(user)
		res.Meta["http_login_pass"] = safe.SanitizeForLog(pass)
		flagAnomaly(res, "http-login-attempt")
		flagDefaultCred(res, user, pass)
	}
	low := strings.ToLower(user + " " + pass)
	if hits := classifyWebAttacks(low); slices.Contains(hits, "sqli") {
		// Return a fake MySQL syntax error — exactly what a real injectable
		// login leaks, drawing the attacker deeper. Still 200, no execution.
		errBody := webappMySQLError(user)
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", errBody, []string{cookie})
	}
	return webappResponse(server, 200, "OK", "text/html; charset=UTF-8",
		webappLoginPage(app, "Invalid username or password."), []string{cookie})
}

// webappSearch reflects the query (HTML-escaped — never a real XSS sink)
// and renders a fake results table.
func webappSearch(server, qstr, app, cookie string) string {
	esc := htmlEscape(qstr)
	body := "<!DOCTYPE html><html><head><title>" + app + " — Search</title></head><body>" +
		"<h2>Search results for: " + esc + "</h2>" +
		"<form method=GET action=/search.php><input name=q value=\"" + esc + "\"><input type=submit value=Search></form>"
	if qstr == "" {
		body += "<p>Enter a search term.</p>"
	} else {
		body += "<ul><li>Q3 Financial Report (restricted)</li><li>Employee Handbook v4</li>" +
			"<li>VPN Setup Guide</li></ul><p>3 results.</p>"
	}
	body += "</body></html>"
	return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", body, []string{cookie})
}

// webappProduct treats id as a numeric DB lookup; a non-numeric / SQLi id
// yields a fake MySQL error (injectable-parameter deception).
func webappProduct(server, id, app, cookie string, res *Result) string {
	low := strings.ToLower(id)
	if hits := classifyWebAttacks(low); slices.Contains(hits, "sqli") {
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", webappMySQLError(id), []string{cookie})
	}
	name := "Widget"
	body := "<!DOCTYPE html><html><head><title>" + app + " — Product</title></head><body>" +
		"<h2>" + htmlEscape(name) + " #" + htmlEscape(id) + "</h2>" +
		"<p>Price: $19.99 — In stock.</p></body></html>"
	return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", body, []string{cookie})
}

// webappFileResponse is the LFI/RFI surface. Path-traversal toward a
// well-known file returns fake-but-believable contents (active deception);
// everything else is a fake "file not found".
func webappFileResponse(server, f, app, cookie string, res *Result) string {
	dec, _ := url.QueryUnescape(f)
	low := strings.ToLower(dec)
	switch {
	case strings.Contains(low, "passwd"):
		flagAnomaly(res, "webapp:lfi")
		return webappResponse(server, 200, "OK", "text/plain", webappFakePasswd(), []string{cookie})
	case strings.Contains(low, "win.ini"):
		flagAnomaly(res, "webapp:lfi")
		return webappResponse(server, 200, "OK", "text/plain",
			"; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n", []string{cookie})
	case f == "":
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", webappHome(app), []string{cookie})
	}
	return webappResponse(server, 404, "Not Found", "text/html; charset=UTF-8",
		"<html><body><h1>Not Found</h1><p>include("+htmlEscape(f)+"): failed to open stream.</p></body></html>", []string{cookie})
}

// webappAPIUser returns a fake JSON user record (IDOR surface).
func webappAPIUser(server, id string) string {
	if id == "" {
		id = "1"
	}
	body := `{"id":"` + jsonEscape(id) + `","username":"jdoe","email":"jdoe@corp.internal","role":"user","active":true}`
	return webappResponse(server, 200, "OK", "application/json", body, nil)
}

func isWebappLoginPath(p string) bool {
	switch p {
	case "/login", "/login.php", "/login.html", "/admin/login.php", "/signin", "/auth/login":
		return true
	}
	return false
}

// --- fake content (never real; pure deception) ---

func webappFakePasswd() string {
	return "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n" +
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n" +
		"mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false\n" +
		"webadmin:x:1000:1000:Web Admin:/home/webadmin:/bin/bash\n"
}

func webappFakeEnv(app string, hc honeyCreds) string {
	return "APP_NAME=" + app + "\nAPP_ENV=production\nAPP_DEBUG=false\n" +
		"DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=intranet\n" +
		"DB_USERNAME=intranet_app\nDB_PASSWORD=" + hc.dbPass + "\n" +
		"APP_KEY=" + hc.appKey + "\n" +
		"AWS_ACCESS_KEY_ID=" + hc.awsKeyID + "\nAWS_SECRET_ACCESS_KEY=" + hc.awsSecret + "\n"
}

func webappFakeConfig(app string, hc honeyCreds) string {
	return "<?php\n// " + app + " configuration (backup)\n" +
		"$DB_HOST = '127.0.0.1';\n$DB_USER = 'intranet_app';\n" +
		"$DB_PASS = '" + hc.dbPass + "';\n$DB_NAME = 'intranet';\n" +
		"define('SECRET_KEY', '" + hc.secretKey + "');\n"
}

// honeyCreds is a set of believable-but-fake secrets planted in the
// webapp's decoy files (/.env, config backups). Every value is derived
// deterministically from the deployment identity, so it is unique per
// deployment — an attacker who scraped one sensor's ".env" can't grep the
// internet for the literal string to fingerprint every tarpit-honeypot
// (the old static "Tr4pP3d-D3c0y-2024" was exactly that tell). Because
// each value is stable + unique, it doubles as a trackable honeytoken: the
// served DB password is stamped on the event meta (honeytoken) so a SOC
// can register it and alert if it ever shows up in real auth logs.
type honeyCreds struct {
	dbPass    string
	appKey    string // Laravel-style "base64:..."
	awsKeyID  string // "AKIA..." (20 chars, AWS access-key-id shape)
	awsSecret string // 40-char AWS secret-access-key shape
	secretKey string
}

func webappHoneyCreds(id *identity.Identity) honeyCreds {
	return honeyCreds{
		dbPass:    encodeAlpha(idBytes(id, "webapp-db-pass", 20), honeyAlnum),
		appKey:    "base64:" + base64.StdEncoding.EncodeToString(idBytes(id, "webapp-app-key", 32)),
		awsKeyID:  "AKIA" + encodeAlpha(idBytes(id, "webapp-aws-id", 16), honeyAWSAlpha),
		awsSecret: encodeAlpha(idBytes(id, "webapp-aws-secret", 40), honeyB64Alpha),
		secretKey: encodeAlpha(idBytes(id, "webapp-secret-key", 32), honeyAlnum),
	}
}

const (
	honeyAlnum    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	honeyAWSAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" // AWS key-id charset
	honeyB64Alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

// idBytes returns n deterministic bytes for a label from the deployment
// identity, falling back to a label hash when no identity is configured so
// the decoy still renders (just not per-deployment unique).
func idBytes(id *identity.Identity, label string, n int) []byte {
	if id != nil {
		return id.Bytes(label, n)
	}
	h := sha256.Sum256([]byte(label))
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = h[i%len(h)]
	}
	return out
}

// encodeAlpha maps each byte onto an alphabet, yielding a fixed-length
// token of len(b) characters drawn from alpha.
func encodeAlpha(b []byte, alpha string) string {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = alpha[int(b[i])%len(alpha)]
	}
	return string(out)
}

func webappMySQLError(input string) string {
	return "<!DOCTYPE html><html><body><b>Warning</b>: mysqli_fetch_array() expects parameter 1 " +
		"to be mysqli_result, boolean given.<br><b>Database error:</b> You have an error in your SQL " +
		"syntax; check the manual that corresponds to your MySQL server version for the right syntax " +
		"to use near '" + htmlEscape(input) + "' at line 1</body></html>"
}

func webappPhpinfo(id *identity.Identity) string {
	ver := "7.4.33"
	return "<!DOCTYPE html><html><head><title>phpinfo()</title></head><body>" +
		"<h1>PHP Version " + ver + "</h1><table>" +
		"<tr><td>System</td><td>Linux web01 5.4.0-91-generic x86_64</td></tr>" +
		"<tr><td>Server API</td><td>FPM/FastCGI</td></tr>" +
		"<tr><td>Loaded Configuration File</td><td>/etc/php/7.4/fpm/php.ini</td></tr>" +
		"</table></body></html>"
}

func webappHome(app string) string {
	return "<!DOCTYPE html><html><head><title>" + app + "</title></head><body>" +
		"<h1>" + app + "</h1><p>Welcome to the company intranet.</p><ul>" +
		"<li><a href=\"/login.php\">Sign in</a></li>" +
		"<li><a href=\"/search.php?q=\">Search</a></li>" +
		"<li><a href=\"/product.php?id=1\">Catalog</a></li>" +
		"<li><a href=\"/api/users\">Directory API</a></li></ul></body></html>"
}

func webappLoginPage(app, errMsg string) string {
	e := ""
	if errMsg != "" {
		e = "<p style=\"color:red\">" + htmlEscape(errMsg) + "</p>"
	}
	return "<!DOCTYPE html><html><head><title>" + app + " — Sign in</title></head><body>" +
		"<h2>" + app + "</h2>" + e +
		"<form method=POST action=/login.php>" +
		"<label>Username <input name=username></label><br>" +
		"<label>Password <input type=password name=password></label><br>" +
		"<input type=submit value=\"Sign in\"></form></body></html>"
}

// webappName / webappSessionID / webappVersion derive per-deployment values
// so two sensors' fake apps don't cluster on identical strings.
func webappName(id *identity.Identity) string {
	pool := []string{"Acme Intranet", "Contoso Portal", "Globex WebDesk", "Initech HelpDesk", "Northwind Portal", "Corporate Intranet"}
	if id == nil {
		return pool[0]
	}
	return pool[int(id.Uint32("webapp/name"))%len(pool)]
}

func webappSessionID(id *identity.Identity) string {
	if id == nil {
		return "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
	}
	return hex.EncodeToString(id.Bytes("webapp/session", 13))
}

// webappResponse builds a full HTTP/1.1 response with a PHP-app-flavored
// header set. extra holds any Set-Cookie / Location header lines.
func webappResponse(server string, status int, reason, contentType, body string, extra []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, reason)
	b.WriteString("Server: " + safe.SanitizeHeader(server) + "\r\n")
	b.WriteString("X-Powered-By: PHP/7.4.33\r\n")
	for _, h := range extra {
		b.WriteString(safe.SanitizeHeader(h) + "\r\n")
	}
	if contentType != "" {
		b.WriteString("Content-Type: " + safe.SanitizeHeader(contentType) + "\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	b.WriteString("Connection: close\r\n\r\n")
	b.WriteString(body)
	return b.String()
}

// parseQuery is a bounded url.Values parser that never errors.
func parseQuery(raw string) url.Values {
	v, err := url.ParseQuery(raw)
	if err != nil {
		return url.Values{}
	}
	return v
}

// jsonEscape escapes a string for inclusion in a JSON string literal.
func jsonEscape(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r", "\t", "\\t")
	return r.Replace(s)
}
