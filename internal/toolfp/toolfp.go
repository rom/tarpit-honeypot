// Package toolfp identifies the scanning / attack tool behind a
// connection and estimates whether the client is automation or a
// human at a keyboard. It works from cheap, already-captured signals
// (User-Agent, request path, header set, JA3/JA4 fingerprints, banner
// shape) — no extra round-trips. Handlers feed it what they captured;
// it returns tool tags + an automation verdict that the listener
// promotes to event meta + anomalies, so a SIEM can pivot on
// "tool=nmap" or "automation=true".
package toolfp

import "strings"

// HTTPSignals is what the http/mgmt-web handlers hand toolfp.
type HTTPSignals struct {
	Method    string
	Path      string
	UserAgent string
	// HeaderKeys is the ordered list of header names seen (lower-case).
	HeaderKeys []string
}

// Verdict bundles the result.
type Verdict struct {
	// Tools is the set of tool/scanner names identified (e.g.
	// ["nmap"], ["sqlmap"], ["metasploit"]). Empty when unrecognized.
	Tools []string
	// Automation is true when the client looks like a script/scanner
	// rather than an interactive browser.
	Automation bool
	// Reason is a short human-readable explanation of the verdict.
	Reason string
}

// uaSignatures maps a lower-cased User-Agent substring to a tool name.
// These are the literal UA strings the named tools send by default.
var uaSignatures = map[string]string{
	"nmap scripting engine": "nmap",
	"masscan":               "masscan",
	"zgrab":                 "zgrab",
	"zmap":                  "zmap",
	"censysinspect":         "censys",
	"sqlmap":                "sqlmap",
	"nikto":                 "nikto",
	"dirbuster":             "dirbuster",
	"gobuster":              "gobuster",
	"feroxbuster":           "feroxbuster",
	"wpscan":                "wpscan",
	"hydra":                 "hydra",
	"nuclei":                "nuclei",
	"metasploit":            "metasploit",
	"acunetix":              "acunetix",
	"nessus":                "nessus",
	"openvas":               "openvas",
	"qualys":                "qualys",
	"go-http-client":        "go-scanner",
	"python-requests":       "python-script",
	"python-urllib":         "python-script",
	"curl/":                 "curl",
	"wget/":                 "wget",
	"libwww-perl":           "perl-script",
	"okhttp":                "okhttp-script",
}

// pathSignatures maps a request-path substring to a tool/probe — used
// when the UA is spoofed or absent (most scanners send a benign UA but
// hit tool-specific paths).
var pathSignatures = map[string]string{
	"/nmaplowercheck":  "nmap",   // nmap http-probe
	"/nice%20ports%2c": "nmap",   // nmap service-scan path
	"/sdk/../":         "sqlmap", // traversal probe
	"/?search=sqlmap":  "sqlmap",
	"/wp-login.php":    "wpscan", // also legit, low confidence
	"/.git/head":       "scanner-recon",
	"/actuator/":       "scanner-recon",
	"/solr/":           "scanner-recon",
	"/manager/html":    "scanner-recon",
	"/boaform/admin":   "router-exploit",
	"/cgi-bin/luci":    "router-exploit",
	"/hnap1/":          "router-exploit",
	"/shell?":          "mirai-exploit", // common Mirai/Gafgyt RCE path
	"/setup.cgi":       "router-exploit",
}

// browserUASubstrings are tokens that, when present, indicate a real
// browser (or something faithfully impersonating one). Used in the
// automation heuristic.
var browserUASubstrings = []string{
	"mozilla/5.0", "applewebkit", "gecko/", "chrome/", "safari/",
	"firefox/", "edg/", "opr/",
}

// IdentifyHTTP returns the tool/automation verdict for an HTTP request.
func IdentifyHTTP(s HTTPSignals) Verdict {
	v := Verdict{}
	ua := strings.ToLower(s.UserAgent)
	path := strings.ToLower(s.Path)

	for needle, tool := range uaSignatures {
		if strings.Contains(ua, needle) {
			v.Tools = appendUnique(v.Tools, tool)
		}
	}
	for needle, tool := range pathSignatures {
		if strings.Contains(path, needle) {
			v.Tools = appendUnique(v.Tools, tool)
		}
	}

	// Automation heuristic.
	switch {
	case len(v.Tools) > 0:
		v.Automation = true
		v.Reason = "matched tool signature"
	case s.UserAgent == "":
		// A browser always sends a User-Agent; its absence on an HTTP/1.1
		// request is a strong automation signal.
		v.Automation = true
		v.Reason = "no User-Agent header"
	case !looksLikeBrowserUA(ua):
		v.Automation = true
		v.Reason = "non-browser User-Agent"
	case !hasBrowserHeaderSet(s.HeaderKeys):
		// A real browser sends Accept / Accept-Language / Accept-Encoding;
		// scripts impersonating a browser UA usually omit them.
		v.Automation = true
		v.Reason = "browser UA but missing Accept-* headers"
	default:
		v.Automation = false
		v.Reason = "browser-like"
	}
	return v
}

// known scanner JA3 hashes (md5 of the JA3 string). A small, curated
// set — the common scanners' default TLS stacks produce stable JA3s.
var ja3Signatures = map[string]string{
	// (illustrative — operators extend this from their own corpus)
	"a0e9f5d64349fb13191bc781f81f42e1": "java-tls", // generic Java client (metasploit/burp)
	"e7d705a3286e19ea42f587b344ee6865": "go-tls",   // Go crypto/tls (many scanners)
}

// IdentifyTLS maps a JA3 hash to a known TLS-stack/tool name, or "".
func IdentifyTLS(ja3 string) string {
	return ja3Signatures[strings.TrimSpace(ja3)]
}

func looksLikeBrowserUA(ua string) bool {
	for _, b := range browserUASubstrings {
		if strings.Contains(ua, b) {
			return true
		}
	}
	return false
}

func hasBrowserHeaderSet(keys []string) bool {
	hasAccept, hasLang := false, false
	for _, k := range keys {
		switch k {
		case "accept":
			hasAccept = true
		case "accept-language":
			hasLang = true
		}
	}
	return hasAccept && hasLang
}

func appendUnique(list []string, item string) []string {
	for _, e := range list {
		if e == item {
			return list
		}
	}
	return append(list, item)
}
