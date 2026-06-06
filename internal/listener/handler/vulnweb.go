package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// webBrand is the resolved branding for the generic fake-web persona: a name,
// accent colour, short logo mark and intro text. Built by resolveBrand from the
// operator's config.WebappBrand, falling back to deployment-derived defaults.
type webBrand struct {
	Name    string
	Accent  string
	Logo    string
	Tagline string
}

// resolveBrand turns the operator's (optional) brand config into a webBrand,
// filling blanks with the deployment-derived defaults so an un-branded webapp
// looks exactly as before.
func resolveBrand(b config.WebappBrand, id *identity.Identity) webBrand {
	name := strings.TrimSpace(b.Name)
	if name == "" {
		name = webappName(id)
	}
	accent := safeCSSColor(b.Color)
	if accent == "" {
		accent = webappAccent(name)
	}
	logo := strings.TrimSpace(b.Logo)
	if logo == "" && name != "" {
		logo = strings.ToUpper(name[:1])
	}
	if len(logo) > 4 {
		logo = logo[:4]
	}
	tag := strings.TrimSpace(b.Tagline)
	if tag == "" {
		tag = "The company intranet — staff directory, document search, and the product catalog."
	}
	return webBrand{Name: name, Accent: accent, Logo: logo, Tagline: tag}
}

// safeCSSColor returns c when it's a safe CSS colour (#rgb / #rrggbb, or a
// letters-only colour name), else "" so the caller derives an accent. Guards
// the operator-set colour against CSS/style injection when echoed to attackers.
func safeCSSColor(c string) string {
	c = strings.TrimSpace(c)
	if c == "" {
		return ""
	}
	if c[0] == '#' && (len(c) == 4 || len(c) == 7) {
		for _, ch := range c[1:] {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
				return ""
			}
		}
		return c
	}
	if len(c) <= 20 {
		for _, ch := range c {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
				return ""
			}
		}
		return strings.ToLower(c)
	}
	return ""
}

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
// serveWebapp serves the generic (default) fake web application. Kept as a
// thin wrapper so existing callers/tests stay unchanged.
func serveWebapp(reqLine string, body []byte, server string, id *identity.Identity, res *Result) string {
	return serveWebappVariant(reqLine, body, server, id, res, "", config.WebappBrand{})
}

// serveWebappVariant routes a request through the fake web app. variant
// selects a decoy persona ("wordpress", "phpmyadmin", …); empty/"generic"
// is the default PHP/MySQL intranet. Attack-class detection + login capture
// are shared across every variant.
func serveWebappVariant(reqLine string, body []byte, server string, id *identity.Identity, res *Result, variant string, brandCfg config.WebappBrand) string {
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

	brand := resolveBrand(brandCfg, id)
	app := brand.Name
	hc := webappHoneyCreds(id)
	cookie := "Set-Cookie: PHPSESSID=" + webappSessionID(id) + "; path=/; HttpOnly"
	q := parseQuery(rawQuery)

	// Variant personas get first crack at their distinctive paths; anything
	// they don't claim falls through to the shared generic routes below.
	if variant != "" && variant != "generic" {
		if resp, handled := serveWebappPersona(variant, method, path, server, body, app, cookie, id, res); handled {
			return resp
		}
	}

	switch {
	case path == "/" || path == "/index.php" && rawQuery == "":
		// index.php with a ?page= is the LFI surface; bare index is the home.
		if page := q.Get("page"); page != "" {
			return webappFileResponse(server, page, brand, cookie, res)
		}
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", webappHome(brand), []string{cookie})

	case isWebappLoginPath(path):
		if method == "POST" {
			return webappLogin(server, body, brand, cookie, res)
		}
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", webappLoginPage(brand, ""), []string{cookie})

	case path == "/search" || path == "/search.php":
		return webappSearch(server, q.Get("q"), brand, cookie)

	case path == "/product.php" || path == "/product" || path == "/item.php":
		return webappProduct(server, q.Get("id"), brand, cookie, res)

	case path == "/download" || path == "/download.php" || path == "/view.php" || path == "/index.php":
		f := q.Get("file")
		if f == "" {
			f = q.Get("page")
		}
		return webappFileResponse(server, f, brand, cookie, res)

	case path == "/api/users" || path == "/api/user" || path == "/api/user.php":
		return webappAPIUser(server, q.Get("id"))

	case path == "/api" || path == "/api/" || path == "/api/v1" || path == "/api/v1/" || path == "/api/v2" || path == "/api/v2/":
		// REST API discovery root — a scanner hitting this is mapping the API.
		flagAnomaly(res, "webapp:api-probe")
		return webappAPIIndex(server, brand)

	case path == "/openapi.json" || path == "/openapi.yaml" || path == "/swagger.json" ||
		path == "/v3/api-docs" || path == "/v2/api-docs" || path == "/api-docs" || path == "/api/swagger.json":
		// Machine-readable API contract — high-signal recon (it enumerates
		// every endpoint, parameter, and auth scheme for the attacker).
		flagAnomaly(res, "webapp:api-spec-probe")
		return webappOpenAPISpec(server, brand)

	case path == "/swagger" || path == "/swagger/" || path == "/swagger-ui" || path == "/swagger-ui/" ||
		path == "/swagger-ui.html" || path == "/swagger/index.html" || path == "/api/docs" || path == "/docs/api":
		flagAnomaly(res, "webapp:api-spec-probe")
		return webappSwaggerUI(server, brand)

	case path == "/graphql" || path == "/graphql/" || path == "/api/graphql" || path == "/v1/graphql" || path == "/query":
		// GraphQL endpoint: POST runs the (introspection) query; GET serves the
		// GraphiQL playground. Introspection bodies are flagged upstream by
		// classifyWebAttacks (webapp:graphql-introspection).
		if method == "POST" {
			return webappGraphQL(server, body, res)
		}
		return webappGraphiQL(server, brand)

	case path == "/graphiql" || path == "/graphiql/":
		return webappGraphiQL(server, brand)

	case path == "/robots.txt":
		body := "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /config.php.bak\nDisallow: /.env\nDisallow: /api/\nDisallow: /swagger/\nDisallow: /graphql\n"
		return webappResponse(server, 200, "OK", "text/plain", body, nil)

	case path == "/.env" || path == "/.env.bak":
		recordProbedFile(res, path)
		res.Meta["honeytoken"] = hc.dbPass
		return webappResponse(server, 200, "OK", "text/plain", webappFakeEnv(app, hc), nil)

	case path == "/.git/config":
		recordProbedFile(res, path)
		body := "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://git.internal/" + app + ".git\n"
		return webappResponse(server, 200, "OK", "text/plain", body, nil)

	case path == "/config.php.bak" || path == "/config.php~" || path == "/backup.zip":
		recordProbedFile(res, path)
		res.Meta["honeytoken"] = hc.dbPass
		return webappResponse(server, 200, "OK", "text/plain", webappFakeConfig(app, hc), nil)

	// --- 20 more emulated vulnerabilities: exposed VCS metadata, secret files,
	// management/diagnostic endpoints, and framework debug consoles. Each returns
	// believable "loot" (active deception) and flags the probe; nothing real is
	// exposed and the planted secrets are per-deployment honeytokens.
	case path == "/.git/HEAD" || path == "/.git/index":
		recordProbedFile(res, path)
		return webappResponse(server, 200, "OK", "text/plain", "ref: refs/heads/main\n", nil)
	case path == "/.svn/entries" || path == "/.svn/wc.db":
		recordProbedFile(res, path)
		return webappResponse(server, 200, "OK", "text/plain", "12\n\ndir\nhttps://svn.internal/"+app+"\n", nil)
	case path == "/.hg/store" || path == "/.bzr/branch/branch.conf":
		recordProbedFile(res, path)
		return webappResponse(server, 200, "OK", "text/plain", "default = https://hg.internal/"+app+"\n", nil)
	case path == "/.htpasswd":
		recordProbedFile(res, path)
		res.Meta["honeytoken"] = hc.secretKey
		return webappResponse(server, 200, "OK", "text/plain", "admin:$apr1$"+shortToken(hc.secretKey)+"\n", nil)
	case path == "/.htaccess":
		recordProbedFile(res, path)
		return webappResponse(server, 200, "OK", "text/plain", "AuthType Basic\nAuthName \"Restricted\"\nAuthUserFile /var/www/.htpasswd\nRequire valid-user\n", nil)
	case path == "/web.config":
		recordProbedFile(res, path)
		res.Meta["honeytoken"] = hc.dbPass
		return webappResponse(server, 200, "OK", "text/xml", webappWebConfig(hc), nil)
	case path == "/WEB-INF/web.xml" || path == "/WEB-INF/classes/application.properties":
		recordProbedFile(res, path)
		res.Meta["honeytoken"] = hc.dbPass
		return webappResponse(server, 200, "OK", "text/xml", "<web-app>\n  <context-param><param-name>jdbc.url</param-name><param-value>jdbc:mysql://127.0.0.1:3306/intranet?user=intranet_app&amp;password="+hc.dbPass+"</param-value></context-param>\n</web-app>\n", nil)
	case path == "/.aws/credentials" || path == "/.aws/config":
		recordProbedFile(res, path)
		res.Meta["honeytoken"] = hc.awsSecret
		return webappResponse(server, 200, "OK", "text/plain", "[default]\naws_access_key_id = "+hc.awsKeyID+"\naws_secret_access_key = "+hc.awsSecret+"\nregion = us-east-1\n", nil)
	case path == "/.ssh/id_rsa" || path == "/id_rsa" || path == "/.ssh/id_ed25519":
		recordProbedFile(res, path)
		return webappResponse(server, 200, "OK", "text/plain", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA"+shortToken(hc.secretKey)+"\n-----END OPENSSH PRIVATE KEY-----\n", nil)
	case path == "/docker-compose.yml" || path == "/.dockercfg" || path == "/.npmrc" || path == "/.netrc":
		recordProbedFile(res, path)
		res.Meta["honeytoken"] = hc.dbPass
		return webappResponse(server, 200, "OK", "text/plain", "version: '3'\nservices:\n  db:\n    image: mysql:5.7\n    environment:\n      MYSQL_ROOT_PASSWORD: "+hc.dbPass+"\n", nil)
	case path == "/.env.local" || path == "/.env.production" || path == "/.env.dev" || path == "/.env.example":
		recordProbedFile(res, path)
		res.Meta["honeytoken"] = hc.dbPass
		return webappResponse(server, 200, "OK", "text/plain", webappFakeEnv(app, hc), nil)
	case path == "/server-status" || path == "/server-status/":
		flagAnomaly(res, "webapp:apache-status-exposed")
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", "<html><head><title>Apache Status</title></head><body><h1>Apache Server Status for "+brand.Name+"</h1><dl><dt>Server Version: Apache/2.4.29 (Ubuntu)</dt><dt>Total accesses: 184213 - Total Traffic: 2.1 GB</dt></dl></body></html>", nil)
	case path == "/server-info":
		flagAnomaly(res, "webapp:apache-info-exposed")
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", "<html><body><h1>Apache Server Information</h1><dl><dt>Server Version: Apache/2.4.29</dt><dt>Server Built: 2018-09-26</dt></dl></body></html>", nil)
	case path == "/actuator" || strings.HasPrefix(path, "/actuator/"):
		flagAnomaly(res, "webapp:spring-actuator-exposed")
		res.Meta["honeytoken"] = hc.dbPass
		return webappResponse(server, 200, "OK", "application/json", webappActuator(path, hc), nil)
	case path == "/jolokia" || strings.HasPrefix(path, "/jolokia/"):
		flagAnomaly(res, "webapp:jolokia-exposed")
		return webappResponse(server, 200, "OK", "application/json", `{"request":{"type":"version"},"value":{"agent":"1.6.2","protocol":"7.2","config":{"agentId":"`+webappSessionID(id)+`"}},"status":200}`, nil)
	case path == "/solr/" || strings.HasPrefix(path, "/solr/admin"):
		flagAnomaly(res, "webapp:solr-admin-exposed")
		return webappResponse(server, 200, "OK", "application/json", `{"responseHeader":{"status":0},"status":{"intranet":{"name":"intranet","instanceDir":"/var/solr/intranet"}}}`, nil)
	case strings.HasPrefix(path, "/debug/pprof"):
		flagAnomaly(res, "webapp:pprof-exposed")
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", "<html><head><title>/debug/pprof/</title></head><body>/debug/pprof/<br><a href=\"heap\">heap</a> <a href=\"goroutine\">goroutine</a> <a href=\"profile\">profile</a></body></html>", nil)
	case path == "/metrics":
		flagAnomaly(res, "webapp:metrics-exposed")
		return webappResponse(server, 200, "OK", "text/plain", "# HELP process_open_fds Number of open file descriptors.\nprocess_open_fds 18\n# HELP go_goroutines Number of goroutines.\ngo_goroutines 42\n", nil)
	case strings.HasPrefix(path, "/telescope"):
		flagAnomaly(res, "webapp:laravel-telescope-exposed")
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", webappShell(brand, "Telescope", "<div class=\"nw-card\"><h2>Laravel Telescope</h2><p>Requests · Queries · Mail · Cache</p></div>"), nil)
	case strings.HasPrefix(path, "/_profiler"):
		flagAnomaly(res, "webapp:symfony-profiler-exposed")
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", "<html><head><title>Symfony Profiler</title></head><body><h1>Symfony Profiler</h1></body></html>", nil)
	case path == "/manager/html" || path == "/host-manager/html":
		flagAnomaly(res, "webapp:tomcat-manager-probe")
		return webappResponse(server, 401, "Unauthorized", "text/html", "", []string{`WWW-Authenticate: Basic realm="Tomcat Manager Application"`})

	case path == "/phpinfo.php" || path == "/info.php":
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", webappPhpinfo(id), nil)

	case strings.HasPrefix(path, "/admin"):
		// Unauthenticated admin → bounce to login (believable).
		return webappResponse(server, 302, "Found", "text/html", "", []string{"Location: /login.php", cookie})
	}
	// Unknown path → a PHP-app-flavored 404 in the portal chrome.
	inner := "<div class=\"nw-card\"><h1>404 — Not Found</h1>" +
		"<p>The requested URL " + htmlEscape(path) + " was not found on this server.</p>" +
		"<p><a href=\"/\">&larr; Return home</a></p></div>"
	return webappResponse(server, 404, "Not Found", "text/html; charset=UTF-8", webappShell(brand, "404 Not Found", inner), nil)
}

// webappLogin captures credentials, flags default-cred + SQLi auth-bypass
// attempts, and returns a believable failure (or a fake MySQL error when
// the input is a SQLi probe — the "this field is injectable" deception).
func webappLogin(server string, body []byte, brand webBrand, cookie string, res *Result) string {
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
		webappLoginPage(brand, "Invalid username or password."), []string{cookie})
}

// webappSearch reflects the query (HTML-escaped — never a real XSS sink)
// and renders a fake results table.
func webappSearch(server, qstr string, brand webBrand, cookie string) string {
	esc := htmlEscape(qstr) // reflected HTML-escaped — detects XSS without being a sink
	inner := "<div class=\"nw-card\"><h2>Search</h2>" +
		"<form class=\"nw-search\" method=GET action=/search.php><input name=q value=\"" + esc + "\" placeholder=\"Search documents…\"> " +
		"<button class=\"nw-btn\" style=\"width:auto;margin-top:0\" type=submit>Search</button></form>"
	if qstr == "" {
		inner += "<p>Enter a search term.</p>"
	} else {
		inner += "<h3>Results for: " + esc + "</h3>" +
			"<ul class=\"nw-list\"><li>Q3 Financial Report (restricted)</li><li>Employee Handbook v4</li>" +
			"<li>VPN Setup Guide</li></ul><p>3 results.</p>"
	}
	inner += "</div>"
	return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", webappShell(brand, brand.Name+" — Search", inner), []string{cookie})
}

// webappProduct treats id as a numeric DB lookup; a non-numeric / SQLi id
// yields a fake MySQL error (injectable-parameter deception).
func webappProduct(server, id string, brand webBrand, cookie string, res *Result) string {
	low := strings.ToLower(id)
	if hits := classifyWebAttacks(low); slices.Contains(hits, "sqli") {
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", webappMySQLError(id), []string{cookie})
	}
	name := "Widget"
	inner := "<div class=\"nw-card\"><h2>" + htmlEscape(name) + " #" + htmlEscape(id) + "</h2>" +
		"<p><strong>Price:</strong> $19.99 &mdash; In stock.</p>" +
		"<p><a href=\"/search.php?q=\">&larr; Back to catalog</a></p></div>"
	return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", webappShell(brand, brand.Name+" — Product", inner), []string{cookie})
}

// webappFileResponse is the LFI/RFI surface. Path-traversal toward a
// well-known file returns fake-but-believable contents (active deception);
// everything else is a fake "file not found".
func webappFileResponse(server, f string, brand webBrand, cookie string, res *Result) string {
	dec, _ := url.QueryUnescape(f)
	low := strings.ToLower(dec)
	switch {
	case strings.Contains(low, "passwd"):
		flagAnomaly(res, "webapp:lfi")
		recordProbedFile(res, dec)
		return webappResponse(server, 200, "OK", "text/plain", webappFakePasswd(), []string{cookie})
	case strings.Contains(low, "win.ini"):
		flagAnomaly(res, "webapp:lfi")
		recordProbedFile(res, dec)
		return webappResponse(server, 200, "OK", "text/plain",
			"; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n", []string{cookie})
	case f == "":
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", webappHome(brand), []string{cookie})
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

// recordProbedFile stamps the specific sensitive file a request tried to read
// (an /.env, config backup, .git/config, or an LFI traversal target) onto the
// event meta so the operator can see WHICH files were targeted — the secret-
// file-probe / LFI anomalies on their own only say "a secret file was probed".
// The probed_file values are aggregated per source on the attacker profile.
func recordProbedFile(res *Result, name string) {
	flagAnomaly(res, "webapp:secret-file-probe")
	if name == "" {
		return
	}
	res.Meta["probed_file"] = safe.SanitizeForLog(clipStr(name, 256))
}

// webappAPIIndex is a believable REST API discovery root: a JSON document
// listing the (fake) endpoints, which is exactly what an API scanner expects
// to find at /api.
func webappAPIIndex(server string, b webBrand) string {
	body := `{"name":"` + jsonEscape(b.Name) + ` API","version":"v1","status":"ok",` +
		`"documentation":"/swagger","openapi":"/openapi.json","graphql":"/graphql",` +
		`"endpoints":["/api/users","/api/login","/api/orders","/api/admin","/api/health"]}`
	return webappResponse(server, 200, "OK", "application/json", body, nil)
}

// webappOpenAPISpec returns a minimal-but-believable OpenAPI 3.0 contract that
// enumerates a handful of endpoints + a bearer-auth scheme. A scanner pulling
// this is fingerprinting the API attack surface.
func webappOpenAPISpec(server string, b webBrand) string {
	name := jsonEscape(b.Name)
	body := `{"openapi":"3.0.1",` +
		`"info":{"title":"` + name + ` Internal API","version":"1.4.2","description":"` + name + ` service API (internal use only)"},` +
		`"servers":[{"url":"/api/v1"}],` +
		`"components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer","bearerFormat":"JWT"}}},` +
		`"security":[{"bearerAuth":[]}],` +
		`"paths":{` +
		`"/login":{"post":{"summary":"Authenticate and obtain a JWT","tags":["auth"]}},` +
		`"/users":{"get":{"summary":"List users","tags":["users"]}},` +
		`"/users/{id}":{"get":{"summary":"Get a user by id","tags":["users"]}},` +
		`"/orders":{"get":{"summary":"List orders","tags":["orders"]}},` +
		`"/admin/config":{"get":{"summary":"Read service configuration","tags":["admin"]}}` +
		`}}`
	return webappResponse(server, 200, "OK", "application/json", body, nil)
}

// webappSwaggerUI returns a Swagger-UI HTML page (the familiar interactive API
// browser) that loads the decoy /openapi.json spec.
func webappSwaggerUI(server string, b webBrand) string {
	html := "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">" +
		"<title>" + htmlEscape(b.Name) + " API — Swagger UI</title>" +
		"<link rel=\"stylesheet\" href=\"https://unpkg.com/swagger-ui-dist/swagger-ui.css\"></head>" +
		"<body><div id=\"swagger-ui\"></div>" +
		"<script src=\"https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js\"></script>" +
		"<script>window.onload=function(){window.ui=SwaggerUIBundle({url:'/openapi.json',dom_id:'#swagger-ui'});};</script>" +
		"</body></html>"
	return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", html, nil)
}

// webappGraphiQL returns the GraphiQL in-browser IDE shell pointed at /graphql.
func webappGraphiQL(server string, b webBrand) string {
	html := "<!DOCTYPE html><html><head><title>" + htmlEscape(b.Name) + " — GraphiQL</title>" +
		"<link rel=\"stylesheet\" href=\"https://unpkg.com/graphiql/graphiql.min.css\"></head>" +
		"<body style=\"margin:0\"><div id=\"graphiql\" style=\"height:100vh\">Loading GraphiQL…</div>" +
		"<script src=\"https://unpkg.com/graphiql/graphiql.min.js\"></script>" +
		"<script>GraphiQL.createFetcher&&GraphiQL.createFetcher({url:'/graphql'});</script>" +
		"</body></html>"
	return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", html, nil)
}

// webappGraphQL answers a POST to the GraphQL endpoint. An introspection query
// gets a believable (fake) schema so the scanner records a juicy, enumerable
// API; any other query gets a generic validation error. Never executes
// anything. Introspection is flagged upstream by classifyWebAttacks.
func webappGraphQL(server string, body []byte, res *Result) string {
	low := strings.ToLower(string(body))
	if strings.Contains(low, "__schema") || strings.Contains(low, "introspectionquery") {
		flagAnomaly(res, "webapp:graphql-introspection")
		schema := `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},` +
			`"types":[` +
			`{"kind":"OBJECT","name":"Query","fields":[` +
			`{"name":"me","type":{"name":"User"}},{"name":"users","type":{"name":"User"}},{"name":"orders","type":{"name":"Order"}}]},` +
			`{"kind":"OBJECT","name":"User","fields":[{"name":"id","type":{"name":"ID"}},{"name":"email","type":{"name":"String"}},{"name":"role","type":{"name":"String"}}]},` +
			`{"kind":"OBJECT","name":"Mutation","fields":[{"name":"login","type":{"name":"AuthPayload"}}]}]}}}`
		return webappResponse(server, 200, "OK", "application/json", schema, nil)
	}
	if len(bytesTrimSpace(body)) == 0 {
		return webappResponse(server, 400, "Bad Request", "application/json",
			`{"errors":[{"message":"Must provide query string."}]}`, nil)
	}
	return webappResponse(server, 200, "OK", "application/json",
		`{"errors":[{"message":"Cannot query field on type \"Query\"."}]}`, nil)
}

func bytesTrimSpace(b []byte) []byte { return []byte(strings.TrimSpace(string(b))) }

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

// shortToken returns a short slice of a secret for use inside fake .htpasswd /
// private-key blobs (believable shape, never a real secret).
func shortToken(s string) string {
	if len(s) > 22 {
		return s[:22]
	}
	return s
}

// webappWebConfig is a fake IIS/.NET web.config exposing a connection string
// (the planted DB password / machine key are per-deployment honeytokens).
func webappWebConfig(hc honeyCreds) string {
	return "<?xml version=\"1.0\"?>\n<configuration>\n  <connectionStrings>\n" +
		"    <add name=\"Intranet\" connectionString=\"Server=127.0.0.1;Database=intranet;User Id=intranet_app;Password=" + hc.dbPass + ";\" providerName=\"System.Data.SqlClient\"/>\n" +
		"  </connectionStrings>\n  <appSettings>\n    <add key=\"MachineKey\" value=\"" + hc.secretKey + "\"/>\n  </appSettings>\n</configuration>\n"
}

// webappActuator fakes a Spring Boot Actuator endpoint; /actuator/env leaks a
// (honeytoken) datasource password — the classic actuator-exposure loot.
func webappActuator(path string, hc honeyCreds) string {
	switch {
	case strings.Contains(path, "/env"):
		return `{"activeProfiles":["prod"],"propertySources":[{"name":"applicationConfig","properties":{"spring.datasource.url":{"value":"jdbc:mysql://127.0.0.1:3306/intranet"},"spring.datasource.password":{"value":"` + hc.dbPass + `"}}}]}`
	case strings.Contains(path, "/health"):
		return `{"status":"UP","components":{"db":{"status":"UP"},"diskSpace":{"status":"UP"}}}`
	case strings.Contains(path, "/mappings") || strings.Contains(path, "/beans"):
		return `{"contexts":{"application":{"mappings":{"dispatcherServlet":[{"predicate":"/api/**"}]}}}}`
	}
	return `{"_links":{"self":{"href":"/actuator"},"env":{"href":"/actuator/env"},"health":{"href":"/actuator/health"},"beans":{"href":"/actuator/beans"},"mappings":{"href":"/actuator/mappings"}}}`
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

// webappAccent returns a stable corporate accent colour for the portal,
// derived (FNV-1a) from its name so each deployment is internally consistent
// while different sensors don't all render the same blue.
func webappAccent(app string) string {
	palette := []string{"#1f6feb", "#2563eb", "#0f766e", "#7c3aed", "#b91c1c", "#b45309", "#0e7490", "#15803d"}
	var h uint32 = 2166136261
	for i := 0; i < len(app); i++ {
		h = (h ^ uint32(app[i])) * 16777619
	}
	return palette[int(h)%len(palette)]
}

// webappLogoSVG is a small inline-SVG wordmark: a rounded tile carrying the
// portal's initial in its accent colour. Inline (no external asset) keeps the
// deception self-contained — the sensor host serves no real logo file.
func webappLogoSVG(b webBrand) string {
	mark := b.Logo
	if mark == "" {
		mark = "•"
	}
	// Shrink the glyph as the mark gets longer so 1–4 chars all fit the tile.
	fs := 15
	switch {
	case len(mark) >= 4:
		fs = 8
	case len(mark) == 3:
		fs = 10
	case len(mark) == 2:
		fs = 12
	}
	return "<svg width=\"26\" height=\"26\" viewBox=\"0 0 26 26\" role=\"img\" aria-label=\"logo\">" +
		"<rect width=\"26\" height=\"26\" rx=\"6\" fill=\"#ffffff\"/>" +
		fmt.Sprintf("<text x=\"13\" y=\"18\" text-anchor=\"middle\" font-size=\"%d\" font-weight=\"700\" font-family=\"sans-serif\" fill=\"%s\">%s</text></svg>", fs, b.Accent, htmlEscape(mark))
}

// brandOf builds a default brand for a fixed persona name (e.g. the WordPress /
// phpMyAdmin variants), so the persona path can reuse the branded helpers.
func brandOf(name string) webBrand { return resolveBrand(config.WebappBrand{Name: name}, nil) }

// webappShell wraps page content in a professional, self-contained corporate
// intranet chrome: inline CSS + an inline SVG logo, a coloured header bar with
// nav, a content card, and a footer. No external assets (the sensor host is a
// target). This is deception polish only — every attack-detection surface
// (login field names, search/product params, escaped reflections, error pages)
// keeps its exact names and behaviour.
func webappShell(b webBrand, title, inner string) string {
	accent := b.Accent
	style := "<style>" +
		":root{--nw:" + accent + "}" +
		"*{box-sizing:border-box}" +
		"body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1f2933;background:#eef1f5;line-height:1.5}" +
		"a{color:var(--nw);text-decoration:none}a:hover{text-decoration:underline}" +
		".nw-top{background:var(--nw);color:#fff;display:flex;align-items:center;gap:.7rem;padding:.7rem 1.3rem;box-shadow:0 1px 4px rgba(0,0,0,.15)}" +
		".nw-logo{display:flex;align-items:center;gap:.55rem;font-weight:600;font-size:1.15rem}" +
		".nw-nav{margin-left:auto;display:flex;gap:1.2rem}.nw-nav a{color:#fff;opacity:.92;font-size:.92rem}.nw-nav a:hover{opacity:1}" +
		".nw-main{max-width:880px;margin:1.8rem auto;padding:0 1.2rem}" +
		".nw-card{background:#fff;border:1px solid #dde3ea;border-radius:8px;padding:1.5rem 1.8rem;box-shadow:0 1px 3px rgba(20,30,50,.06)}" +
		"h1,h2,h3{color:#15212e;margin-top:0}" +
		".nw-login{max-width:360px;margin:3rem auto}" +
		".nw-login label{display:block;margin:.7rem 0 .2rem;font-size:.82rem;color:#52606d}" +
		".nw-login input{width:100%;padding:.55rem .6rem;border:1px solid #cbd2d9;border-radius:5px;font-size:1rem}" +
		".nw-btn{margin-top:1.1rem;width:100%;background:var(--nw);color:#fff;border:0;border-radius:5px;padding:.6rem;font-size:1rem;cursor:pointer}" +
		".nw-btn:hover{filter:brightness(1.07)}" +
		".nw-err{background:#fdecec;border:1px solid #f5b5b5;color:#9b1c1c;padding:.5rem .7rem;border-radius:5px;font-size:.9rem}" +
		".nw-search input{padding:.5rem .6rem;border:1px solid #cbd2d9;border-radius:5px;min-width:16rem}" +
		"ul.nw-list{list-style:none;padding:0;margin:.6rem 0 0}ul.nw-list li{padding:.6rem .2rem;border-bottom:1px solid #eceff3}ul.nw-list li:last-child{border-bottom:0}" +
		".nw-foot{max-width:880px;margin:2rem auto;padding:1rem 1.2rem;color:#7b8794;font-size:.8rem;border-top:1px solid #dde3ea}" +
		"</style>"
	logo := "<span class=\"nw-logo\">" + webappLogoSVG(b) + " " + htmlEscape(b.Name) + "</span>"
	nav := "<nav class=\"nw-nav\"><a href=\"/\">Home</a><a href=\"/search.php?q=\">Search</a><a href=\"/product.php?id=1\">Catalog</a><a href=\"/login.php\">Sign in</a></nav>"
	return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">" +
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
		"<title>" + htmlEscape(title) + "</title>" + style + "</head><body>" +
		"<div class=\"nw-top\">" + logo + nav + "</div>" +
		"<div class=\"nw-main\">" + inner + "</div>" +
		"<div class=\"nw-foot\">&copy; " + htmlEscape(b.Name) + " · Confidential — internal use only · Powered by IntranetCMS 4.2</div>" +
		"</body></html>"
}

func webappHome(b webBrand) string {
	inner := "<div class=\"nw-card\"><h1>Welcome to " + htmlEscape(b.Name) + "</h1>" +
		"<p>" + htmlEscape(b.Tagline) + "</p>" +
		"<ul class=\"nw-list\">" +
		"<li><a href=\"/login.php\">Sign in to your account</a></li>" +
		"<li><a href=\"/search.php?q=\">Search documents</a></li>" +
		"<li><a href=\"/product.php?id=1\">Browse the catalog</a></li>" +
		"<li><a href=\"/api/users\">Directory API</a></li>" +
		"</ul></div>"
	return webappShell(b, b.Name, inner)
}

func webappLoginPage(b webBrand, errMsg string) string {
	e := ""
	if errMsg != "" {
		e = "<p class=\"nw-err\">" + htmlEscape(errMsg) + "</p>"
	}
	inner := "<div class=\"nw-card nw-login\"><h2>Sign in to " + htmlEscape(b.Name) + "</h2>" + e +
		"<form method=POST action=/login.php>" +
		"<label>Username</label><input name=username autocomplete=username>" +
		"<label>Password</label><input type=password name=password autocomplete=current-password>" +
		"<button class=\"nw-btn\" type=submit>Sign in</button></form></div>"
	return webappShell(b, b.Name+" — Sign in", inner)
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

// serveWebappPersona handles the paths distinctive to a decoy variant
// (WordPress, phpMyAdmin, …). It returns handled=false for paths the
// persona doesn't own, letting the shared generic routes take over so
// secret-file probes, search/LFI surfaces, and attack-class detection keep
// working for every variant.
func serveWebappPersona(variant, method, path, server string, body []byte, app, cookie string, id *identity.Identity, res *Result) (string, bool) {
	switch variant {
	case "wordpress":
		return serveWordPress(method, path, server, body, cookie, res)
	case "phpmyadmin":
		return servePhpMyAdmin(method, path, server, body, cookie, res)
	case "jenkins":
		return serveJenkins(method, path, server, res)
	}
	return "", false
}

// serveWordPress emulates a WordPress site's recognizable surface
// (wp-login.php, wp-admin, xmlrpc.php, readme). Credential POSTs to
// wp-login.php are captured like any other login.
func serveWordPress(method, path, server string, body []byte, cookie string, res *Result) (string, bool) {
	switch {
	case path == "/" || path == "/index.php":
		h := "<!DOCTYPE html><html><head><title>My Blog</title><meta name=\"generator\" content=\"WordPress 6.4.2\"></head>" +
			"<body><h1>My Blog</h1><p>Just another WordPress site</p>" +
			"<p><a href=\"/wp-login.php\">Log in</a> · <a href=\"/wp-admin/\">Dashboard</a></p></body></html>"
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", h, []string{cookie}), true
	case path == "/wp-login.php":
		if method == "POST" {
			res.Meta["webapp_variant"] = "wordpress"
			return webappLogin(server, body, brandOf("WordPress"), cookie, res), true
		}
		p := "<!DOCTYPE html><html><head><title>Log In ‹ My Blog — WordPress</title></head><body>" +
			"<form name=loginform id=loginform action=/wp-login.php method=post>" +
			"<label>Username or Email Address<input type=text name=log></label>" +
			"<label>Password<input type=password name=pwd></label>" +
			"<input type=submit name=wp-submit value=\"Log In\"></form></body></html>"
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", p, []string{cookie}), true
	case strings.HasPrefix(path, "/wp-admin"):
		flagAnomaly(res, "uri-mgmt-endpoint-probe")
		return webappResponse(server, 302, "Found", "text/html", "", []string{"Location: /wp-login.php?redirect_to=" + path, cookie}), true
	case path == "/xmlrpc.php":
		flagAnomaly(res, "webapp:wordpress-xmlrpc")
		b := "XML-RPC server accepts POST requests only."
		return webappResponse(server, 405, "Method Not Allowed", "text/plain", b, nil), true
	case path == "/readme.html":
		return webappResponse(server, 200, "OK", "text/html", "<h1>WordPress</h1><p>Version 6.4.2</p>", nil), true
	case path == "/wp-json" || strings.HasPrefix(path, "/wp-json/"):
		flagAnomaly(res, "webapp:wordpress-rest")
		return webappResponse(server, 200, "OK", "application/json", `{"name":"My Blog","description":"Just another WordPress site","gmt_offset":0}`, nil), true
	}
	return "", false
}

// servePhpMyAdmin emulates the phpMyAdmin login surface — a perennial scan
// magnet. Credential POSTs are captured.
func servePhpMyAdmin(method, path, server string, body []byte, cookie string, res *Result) (string, bool) {
	switch {
	case path == "/" || path == "/index.php" || strings.HasPrefix(path, "/phpmyadmin") || strings.HasPrefix(path, "/pma"):
		flagAnomaly(res, "uri-mgmt-endpoint-probe")
		if method == "POST" {
			res.Meta["webapp_variant"] = "phpmyadmin"
			return webappLogin(server, body, brandOf("phpMyAdmin"), cookie, res), true
		}
		p := "<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body>" +
			"<h1>phpMyAdmin <span>5.2.1</span></h1>" +
			"<form method=post action=index.php name=login_form>" +
			"<label>Username:<input type=text name=pma_username></label>" +
			"<label>Password:<input type=password name=pma_password></label>" +
			"<select name=server><option value=1>localhost</option></select>" +
			"<input type=submit value=Go></form></body></html>"
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", p, []string{cookie}), true
	case strings.HasPrefix(path, "/setup"):
		flagAnomaly(res, "uri-mgmt-endpoint-probe")
		return webappResponse(server, 200, "OK", "text/html", "<h1>phpMyAdmin setup</h1>", nil), true
	}
	return "", false
}

// serveJenkins emulates a Jenkins CI dashboard surface (login + the
// X-Jenkins version header scanners look for).
func serveJenkins(method, path, server string, res *Result) (string, bool) {
	switch {
	case path == "/" || path == "/login" || strings.HasPrefix(path, "/login?"):
		flagAnomaly(res, "uri-mgmt-endpoint-probe")
		h := "<!DOCTYPE html><html><head><title>Dashboard [Jenkins]</title></head><body>" +
			"<h1>Welcome to Jenkins!</h1><a href=\"/login\">log in</a></body></html>"
		return webappResponse(server, 200, "OK", "text/html; charset=UTF-8", h, []string{"X-Jenkins: 2.426.1", "X-Jenkins-Session: " + webappSessionID(nil)}), true
	case strings.HasPrefix(path, "/script") || strings.HasPrefix(path, "/manage"):
		flagAnomaly(res, "webapp:cmdi")
		return webappResponse(server, 403, "Forbidden", "text/html", "<h1>403</h1>", nil), true
	}
	return "", false
}
