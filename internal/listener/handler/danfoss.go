package handler

import (
	"bufio"
	"context"
	"net"
	"net/url"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// danfoss emulates the Danfoss AK-SM 8xxA "StoreView" refrigeration system
// manager web interface (TCP 80 plaintext; bind behind `https` / the
// danfoss_aksms TLS variant for 443). The AK-SM aggregates supermarket
// refrigeration field controllers and exposes an nginx-fronted xml.cgi
// management API that technicians administer remotely — which is why
// thousands end up internet-facing (Claroty Team82 counted ~2,765 exposed).
//
// The handler fingerprints the device with assets captured verbatim from a
// live, internet-facing AK-SM — the "StoreView" Angular landing page, its
// favicon.ico and logo.png, and the exact nginx response-header set (Server
// banner, StoreView CORS policy, no-store caching); see danfoss_assets.go. It
// captures credentials and *recognizes* — never executes — the documented
// exploit request shapes:
//
//   - CVE-2025-41450 (DSA-2025-03-01): the hidden date-derived "code-of-the-day"
//     authentication bypass on xml.cgi?action=getauth. The real generation
//     algorithm and bypass attribute names were redacted by the researchers and
//     are NOT reproduced; the handler detects the documented request *shape*
//     (extra auth attributes beyond username/password, or a short all-numeric
//     "code" password).
//   - CVE-2025-41451 (DSA-2025-08-01): post-auth OS command injection through the
//     alarm-to-mail SMTP password (config item 0x1be1).
//   - CVE-2025-41452 (DSA-2025-08-01): post-auth nginx headers.conf replacement
//     via action=load_nginx_headers (config injection → sm_app crash DoS).
//   - CVE-2023-25914 (DSA-2023-08-01): AK-SM 800A xml.cgi path traversal.
//   - CVE-2026-15203 (DSA-2026-08-01): Danfoss iC7 debug/engineering interfaces
//     exposed with improper access control by default — flagged generically when
//     a debug/engineering/service endpoint is reached.
//
// Nothing is ever executed and no session is really granted; the handler
// records the attempt, raises a high-severity cve:<id> event, and harvests the
// payload for analysis.
type danfoss struct {
	id   *identity.Identity
	vuln bool
}

func (d *danfoss) Name() string { return "danfoss_aksm" }

// danfossFirmware returns the advertised firmware string: a deliberately
// unpatched build when vulnerable-emulation is on (so a version scanner records
// an exploitable box), else a patched release.
func (d *danfoss) firmware() string {
	if d.vuln {
		return "G09_181" // < R4.2 / R4.3.1 family — vulnerable to the three CVEs
	}
	return "G10_431" // R4.3.1 — patched
}

func (d *danfoss) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 8192
	}
	head, _ := readHTTPHead(br, capN)
	res.Payload = head

	method, path, query, authz, ua := svcHTTPReqLine(head)
	res.Meta["method"] = method
	res.Meta["path"] = safe.SanitizeForLog(path)
	if ua != "" {
		res.Meta["user_agent"] = safe.SanitizeForLog(ua)
	}
	flagAnomaly(&res, "danfoss-aksm-access")

	// Credentials in an Authorization header (rare on this device, but captured).
	if u, p, ok := decodeBasic(authz); ok {
		res.Meta["basic_user"] = safe.SanitizeForLog(u)
		res.Meta["basic_pass"] = safe.SanitizeForLog(p)
		flagDefaultCred(&res, u, p)
	}

	// The body carries the getauth XML and the config-save form fields.
	var body []byte
	if method == "POST" || method == "PUT" {
		body = svcHTTPBody(br, head, capN)
		res.Payload = append(res.Payload, body...)
	}

	lowPath := strings.ToLower(path)
	// action= may live in the query string or (rarely) the body.
	action := strings.ToLower(danfossAction(query, string(body)))
	if action != "" {
		res.Meta["xml_action"] = safe.SanitizeForLog(action)
	}

	status, ctype, respBody := "200 OK", "text/html; charset=UTF-8", ""

	switch {
	case strings.Contains(lowPath, "xml.cgi") && action == "getauth":
		respBody = d.handleGetAuth(string(body), &res)
		status, ctype = "200 OK", "text/xml; charset=UTF-8"

	case strings.Contains(lowPath, "xml.cgi") && (action == "set_email_config" || strings.Contains(action, "email")):
		respBody = d.handleEmailConfig(string(body), &res)
		status, ctype = "200 OK", "text/xml; charset=UTF-8"

	case strings.Contains(lowPath, "xml.cgi") && action == "load_nginx_headers":
		respBody = d.handleNginxHeaders(string(body), &res)
		status, ctype = "200 OK", "text/xml; charset=UTF-8"

	case strings.Contains(lowPath, "xml.cgi"):
		// Any other xml.cgi call: check for the path-traversal variant, then
		// answer a generic OK envelope.
		d.checkXMLTraversal(path, query, &res)
		respBody = "<?xml version=\"1.0\"?><response status=\"ok\"/>"
		ctype = "text/xml; charset=UTF-8"

	case danfossEngineeringPath(lowPath):
		flagAnomaly(&res, "danfoss-engineering-interface-access")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2026-15203")
		flagAnomaly(&res, "cve:CVE-2026-15203")
		setIfEmpty(res.Meta, "intent", "Danfoss debug/engineering/service interface access — improper-access-control surface (DSA-2026-08-01)")
		respBody = "<html><head><title>Service</title></head><body>Service interface</body></html>"

	case lowPath == "/favicon.ico":
		// Real device favicon — served verbatim so favicon-hash fingerprints match.
		res.Meta["asset_served"] = "favicon.ico"
		status, ctype, respBody = "200 OK", "image/x-icon", danfossFavicon

	case strings.HasSuffix(lowPath, "/danfoss-logo.png"):
		// The red Danfoss wordmark shown on the login page, served verbatim.
		res.Meta["asset_served"] = "Danfoss-logo.png"
		status, ctype, respBody = "200 OK", "image/png", danfossWordmark

	case lowPath == "/assets/images/logo.png" || strings.HasSuffix(lowPath, "/logo.png"):
		// Real StoreView logo bitmap, served verbatim.
		res.Meta["asset_served"] = "logo.png"
		status, ctype, respBody = "200 OK", "image/png", danfossLogo

	default:
		// Landing page — the genuine StoreView Angular shell, which fingerprints
		// the device (title, favicon/logo refs, Server banner). Record which
		// unpatched/patched firmware build the honeypot is emulating.
		setIfEmpty(res.Meta, "emulated_firmware", d.firmware())
		status, ctype, respBody = "200 OK", "text/html", d.landingPage()
	}

	// Always run the path-traversal check (covers non-xml.cgi traversal too).
	d.checkXMLTraversal(path, query, &res)

	// Generic CVE corpus: the Danfoss-specific records plus the shared HTTP
	// exploit corpus (SSRF / traversal probes arrive here too). Detection only.
	for _, rec := range cve.MatchPayload("danfoss_aksm", string(res.Payload)) {
		res.CVEHits = appendUnique(res.CVEHits, rec.ID)
		flagAnomaly(&res, "cve:"+rec.ID)
	}
	for _, rec := range cve.MatchPayload("http", string(res.Payload)) {
		res.CVEHits = appendUnique(res.CVEHits, rec.ID)
		flagAnomaly(&res, "cve:"+rec.ID)
	}

	// Exact response-header set the live AK-SM nginx emits on every path
	// (Server banner + StoreView CORS policy + no-store caching).
	extra := danfossRespHeaders
	if _, err := conn.Write([]byte(svcHTTPResp(status, extra, ctype, respBody))); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "danfoss aksm " + status
	return res, nil
}

// handleGetAuth captures the login and recognizes the code-of-the-day auth
// bypass (CVE-2025-41450) from the request shape. Detection only — no session
// is really issued and the redacted algorithm is not reproduced.
func (d *danfoss) handleGetAuth(body string, res *Result) string {
	flagAnomaly(res, "danfoss-aksm-login-attempt")
	user := danfossXMLField(body, "username")
	pass := danfossXMLField(body, "password")
	if user == "" && pass == "" {
		// Url-encoded login (e.g. from the served HTML login form, whose fields
		// are user/pwd, or a tool that posts form fields rather than the
		// device's getauth XML).
		if user = danfossFormField(body, "username"); user == "" {
			user = danfossFormField(body, "user")
		}
		if pass = danfossFormField(body, "password"); pass == "" {
			pass = danfossFormField(body, "pwd")
		}
	}
	if user != "" || pass != "" {
		res.Meta["login_user"] = safe.SanitizeForLog(user)
		res.Meta["login_pass"] = safe.SanitizeForLog(pass)
		flagDefaultCred(res, user, pass)
	}

	// Bypass tell #1: auth request carries attributes beyond username/password
	// (the real bypass is routed by extra, redacted attributes set to 1).
	extraAttrs := danfossExtraAuthElements(body)
	// Bypass tell #2: the password is a short all-numeric code (the
	// code-of-the-day is date-derived, not a real passphrase).
	numericCode := danfossShortNumeric(pass)

	if len(extraAttrs) > 0 || numericCode {
		flagAnomaly(res, "danfoss-aksm-auth-bypass")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2025-41450")
		flagAnomaly(res, "cve:CVE-2025-41450")
		if len(extraAttrs) > 0 {
			res.Meta["auth_bypass_attrs"] = extraAttrs
		}
		if numericCode {
			res.Meta["auth_bypass_numeric_code"] = true
		}
		res.Meta["intent"] = "Danfoss AK-SM code-of-the-day authentication bypass attempt (CVE-2025-41450)"
	}
	// Believable rejection — the honeypot never grants a real session.
	return "<?xml version=\"1.0\"?><response status=\"error\" code=\"auth_failed\"/>"
}

// handleEmailConfig recognizes the alarm-to-mail command injection
// (CVE-2025-41451): shell metacharacters in the SMTP auth password field
// (config item 0x1be1). Detection only — nothing is executed.
func (d *danfoss) handleEmailConfig(body string, res *Result) string {
	flagAnomaly(res, "danfoss-aksm-email-config")
	// The password lands in item 0x1be1; also accept common field aliases.
	val := danfossFormField(body, "item_0x1be1")
	if val == "" {
		val = danfossFormField(body, "0x1be1")
	}
	if val == "" {
		val = danfossFormField(body, "smtp_pass")
	}
	lowBody := strings.ToLower(body)
	hasItem := strings.Contains(lowBody, "0x1be1")
	if (val != "" && danfossShellMeta(val)) || (hasItem && danfossShellMeta(body)) {
		flagAnomaly(res, "danfoss-aksm-cmd-injection")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2025-41451")
		flagAnomaly(res, "cve:CVE-2025-41451")
		if val != "" {
			res.Meta["cmd_injection_value"] = safe.SanitizeForLog(clipStr(val, 256))
		}
		res.Meta["intent"] = "Danfoss AK-SM alarm-to-mail OS command injection via item 0x1be1 (CVE-2025-41451)"
	}
	return "<?xml version=\"1.0\"?><response status=\"ok\"/>"
}

// handleNginxHeaders recognizes the headers.conf replacement (CVE-2025-41452):
// any call to load_nginx_headers is the weaponized surface. Detection only.
func (d *danfoss) handleNginxHeaders(body string, res *Result) string {
	flagAnomaly(res, "danfoss-aksm-nginx-config-injection")
	res.CVEHits = appendUnique(res.CVEHits, "CVE-2025-41452")
	flagAnomaly(res, "cve:CVE-2025-41452")
	res.Meta["intent"] = "Danfoss AK-SM nginx headers.conf replacement — config injection / sm_app crash DoS (CVE-2025-41452)"
	low := strings.ToLower(body)
	for _, dir := range []string{"location ", "location\t", "proxy_pass", "rewrite ", "add_header"} {
		if strings.Contains(low, dir) {
			flagAnomaly(res, "danfoss-aksm-nginx-directive-injected")
			break
		}
	}
	return "<?xml version=\"1.0\"?><response status=\"ok\"/>"
}

// checkXMLTraversal flags the AK-SM 800A xml.cgi path traversal (CVE-2023-25914)
// when a traversal sequence appears in the path or query.
func (d *danfoss) checkXMLTraversal(path, query string, res *Result) {
	hay := strings.ToLower(path + "?" + query)
	dec, _ := url.QueryUnescape(hay)
	hay = hay + "\n" + strings.ToLower(dec)
	if strings.Contains(hay, "xml.cgi") &&
		(strings.Contains(hay, "../") || strings.Contains(hay, "..%2f") || strings.Contains(hay, "..\\")) {
		flagAnomaly(res, "danfoss-aksm-xml-traversal")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2023-25914")
		flagAnomaly(res, "cve:CVE-2023-25914")
		setIfEmpty(res.Meta, "intent", "Danfoss AK-SM 800A xml.cgi path traversal (CVE-2023-25914)")
	}
}

// landingPage returns the byte-exact "StoreView Web" landing document captured
// from a live AK-SM (see danfoss_assets.go). The login itself happens over
// xml.cgi?action=getauth, which the handler recognizes and captures.
func (d *danfoss) landingPage() string {
	return danfossIndexHTML
}

// --- parsing helpers (bounded, never error) ------------------------------

// danfossAction extracts the action= value from the query string (preferred)
// or the body.
func danfossAction(query, body string) string {
	if v := danfossFormField(query, "action"); v != "" {
		return v
	}
	return danfossFormField(body, "action")
}

// danfossFormField pulls a key=value from a url-encoded query/body (bounded;
// value percent-decoded). Returns "" when absent.
func danfossFormField(s, key string) string {
	for _, kv := range strings.Split(s, "&") {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			if strings.EqualFold(strings.TrimSpace(kv[:i]), key) {
				v, err := url.QueryUnescape(kv[i+1:])
				if err != nil {
					return kv[i+1:]
				}
				return v
			}
		}
	}
	return ""
}

// danfossXMLField does a minimal <tag>value</tag> extraction (no full XML
// parse), case-insensitive on the tag name.
func danfossXMLField(body, tag string) string {
	// Case-insensitive search over the original bytes (asciiIndexFold), not an
	// index into a strings.ToLower copy: ToLower is not length-preserving, so an
	// index from a lowercased copy can mis-slice or panic a body[i:] slice.
	open := "<" + tag + ">"
	i := asciiIndexFold(body, open)
	if i < 0 {
		return ""
	}
	start := i + len(open)
	j := asciiIndexFold(body[start:], "</"+tag+">")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(body[start : start+j])
}

// danfossExtraAuthElements returns the XML element names in a getauth body
// other than the expected username/password (the request-shape tell of the
// code-of-the-day bypass, which is routed by extra attributes).
func danfossExtraAuthElements(body string) []string {
	var out []string
	s := body
	for {
		i := strings.IndexByte(s, '<')
		if i < 0 {
			break
		}
		j := strings.IndexByte(s[i:], '>')
		if j < 0 {
			break
		}
		name := s[i+1 : i+j]
		s = s[i+j+1:]
		name = strings.TrimSpace(name)
		// Skip closing tags, the XML declaration, and the request wrapper.
		if name == "" || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "?") ||
			strings.HasPrefix(name, "!") {
			continue
		}
		// Strip any attributes, keep the element name.
		if sp := strings.IndexAny(name, " \t"); sp >= 0 {
			name = name[:sp]
		}
		ln := strings.ToLower(name)
		if ln == "username" || ln == "password" || ln == "request" || ln == "auth" {
			continue
		}
		out = appendUnique(out, safe.SanitizeForLog(clipStr(ln, 32)))
		if len(out) >= 8 {
			break
		}
	}
	return out
}

// danfossShortNumeric reports whether s is a short all-digit code (5-8 digits),
// the signature of a date-derived code-of-the-day rather than a real password.
func danfossShortNumeric(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 5 || len(s) > 8 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// danfossShellMeta reports whether s carries OS-shell metacharacters that have
// no place in a legitimate SMTP password — the command-injection tell.
func danfossShellMeta(s string) bool {
	low := strings.ToLower(s)
	for _, m := range []string{";", "|", "`", "$(", "&&", "\n", "%0a", "%3b", "%7c", "%60", "%24%28"} {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// danfossEngineeringPath reports whether a path reaches a debug / engineering /
// service interface (the DSA-2026-08-01 improper-access-control surface).
func danfossEngineeringPath(lowPath string) bool {
	for _, p := range []string{"/debug", "/engineering", "/service", "/factory", "/eeprom", "/diag", "/swupdate", "/firmware"} {
		if strings.HasPrefix(lowPath, p) || strings.Contains(lowPath, p+"/") {
			return true
		}
	}
	return false
}
