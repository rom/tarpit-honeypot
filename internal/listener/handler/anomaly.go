package handler

import (
	"strings"

	"github.com/rom/tarpit-honeypot/internal/creds"
)

// flagDefaultCred checks a captured (user, pass) against the
// default-credential corpus and, on a match, raises the
// default-credential-attempt anomaly + records the device category.
// Every auth-capturing handler calls this so a default-credential
// sweep is detected uniformly regardless of protocol. Returns true on
// a match.
func flagDefaultCred(res *Result, user, pass string) bool {
	c, ok := creds.Match(user, pass)
	if !ok {
		return false
	}
	flagAnomaly(res, "default-credential-attempt")
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	res.Meta["default_cred_category"] = c.Category
	return true
}

// flagAnomaly appends an anomaly marker to a handler's Result if the
// marker isn't already present. Handlers use this for protocol-misuse
// detection: e.g. an SSH client whose identification string contains
// non-printable bytes, or an HTTP request with a method we've never
// heard of. The router translates Result.Meta["anomalies"] into
// event.Anomalies which a SIEM rule can route separately.
func flagAnomaly(res *Result, marker string) {
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	list, _ := res.Meta["anomalies"].([]string)
	for _, m := range list {
		if m == marker {
			return
		}
	}
	res.Meta["anomalies"] = append(list, marker)
}

// hasNonPrintable returns true if s contains any byte outside the
// printable ASCII range (excluding tab / CR / LF, which are common in
// protocol headers). Used to detect SSH identification strings,
// FTP usernames, and HTTP method tokens that have been smuggled
// raw bytes.
func hasNonPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' || c == '\r' || c == '\n' {
			continue
		}
		if c < 0x20 || c == 0x7F {
			return true
		}
	}
	return false
}

// isKnownHTTPMethod returns true if m is one of the common HTTP / WebDAV
// methods we'd expect from a legitimate or even a typical scanner.
// Methods outside this set are anomaly-flagged (e.g. "PROPFIND",
// "ATTACK", a raw binary blob that fits the request-line spot).
func isKnownHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE":
		return true
	// WebDAV — common in real-world scanning.
	case "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK":
		return true
	// Cloud / orchestration probes.
	case "REPORT", "SEARCH", "VERSION-CONTROL":
		return true
	}
	return false
}

// suspiciousURI flags request paths that look like exploit attempts
// even though we don't model the underlying vulnerability — these
// patterns are widely-scanned ones the operator wants to see in the
// anomalies list.
func suspiciousURI(p string) string {
	low := strings.ToLower(p)
	switch {
	case strings.Contains(low, "../"), strings.Contains(low, "..%2f"):
		return "uri-path-traversal"
	case strings.Contains(low, "/wp-admin"), strings.Contains(low, "/xmlrpc.php"):
		return "uri-wordpress-probe"
	case strings.Contains(low, "/cgi-bin/.%2e"), strings.Contains(low, "/.git/"):
		return "uri-source-leak-probe"
	case strings.Contains(low, "/actuator/env"), strings.Contains(low, "/manager/html"):
		return "uri-mgmt-endpoint-probe"
	case strings.Contains(low, "${jndi:"), strings.Contains(low, "%24%7bjndi"):
		return "uri-log4shell-jndi"
	case strings.Contains(low, "eval("), strings.Contains(low, "<script>"):
		return "uri-xss-or-rce-payload"
	case strings.Contains(low, "/.env"), strings.Contains(low, "/.aws/"):
		return "uri-secret-file-probe"
	}
	return ""
}
