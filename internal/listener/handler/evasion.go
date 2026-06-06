package handler

import "strings"

// Evasion + enumeration detection shared across the HTTP-family handlers.
//
// Attackers routinely obfuscate web payloads to slip past signature filters:
// percent-encoding (and double/triple percent-encoding), overlong-UTF-8 and
// %u-style Unicode for "../", null-byte truncation, backslash path separators,
// and SQL-comment splitting. The detection here decodes the request through
// successive percent-decoding layers so the path-only / attack-class checks
// (suspiciousURI / httpAttackClasses) see through the encoding, and separately
// flags the *encoding itself* as an evasion technique.

// percentDecodeLayers returns the raw string plus each distinct successive
// percent-decoding (raw -> decoded once -> twice -> thrice), stopping when a
// decode no longer changes the string. Lets callers run signature checks
// against the de-obfuscated form of a single- or multiply-encoded payload.
func percentDecodeLayers(s string) []string {
	layers := []string{s}
	cur := s
	for i := 0; i < 3; i++ {
		dec := pctDecodeOnce(cur)
		if dec == cur {
			break
		}
		layers = append(layers, dec)
		cur = dec
	}
	return layers
}

// pctDecodeOnce performs one tolerant pass of %XX decoding (leaving malformed
// sequences intact). It does not treat '+' as space — the callers re-run on
// both raw and decoded forms, and a literal '+' is valid in a path.
func pctDecodeOnce(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHexDigit(s[i+1]) && isHexDigit(s[i+2]) {
			b.WriteByte(unhexByte(s[i+1])<<4 | unhexByte(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func unhexByte(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// evasionMarkers flags obfuscation/encoding evasion techniques present in the
// raw request (the encoding artifacts themselves — independent of whether the
// decoded payload turns out to be malicious). Returns `evasion:*` markers,
// which map to ATT&CK T1027 (Obfuscated Files or Information) / defense-evasion.
func evasionMarkers(raw string) []string {
	low := strings.ToLower(raw)
	var out []string
	add := func(m string) { out = appendUnique(out, m) }

	// Double / triple percent-encoding: an encoded '%' (%25) preceding more hex
	// is the canonical IIS/WAF-bypass double-encoding ("..%252f", "%252e%252e").
	if strings.Contains(low, "%25") &&
		(strings.Contains(low, "%252e") || strings.Contains(low, "%252f") ||
			strings.Contains(low, "%255c") || strings.Contains(low, "%2531") ||
			strings.Contains(low, "%2553") || strings.Contains(low, "%2500")) {
		add("evasion:double-encoding")
	}

	// Null-byte injection (extension/path truncation): "%00" or a literal NUL.
	if strings.Contains(low, "%00") || strings.IndexByte(raw, 0x00) >= 0 {
		add("evasion:null-byte")
	}

	// Overlong-UTF-8 / Unicode encodings of '.' and '/' for traversal evasion:
	// %c0%ae %c0%af %c1%9c %e0%80%ae, and %u-style (%u002e %u2215 %uff0e %c0%2f).
	for _, s := range []string{"%c0%ae", "%c0%af", "%c1%9c", "%e0%80%ae", "%e0%80%af", "%c0%2f", "%c1%1c"} {
		if strings.Contains(low, s) {
			add("evasion:overlong-utf8")
			break
		}
	}
	for _, s := range []string{"%u002e", "%u2215", "%u2216", "%uff0e", "%uff0f", "%u00"} {
		if strings.Contains(low, s) {
			add("evasion:unicode-encoding")
			break
		}
	}

	// Backslash / mixed-slash path obfuscation ("..\\", "..%5c", "....//").
	if strings.Contains(low, "..%5c") || strings.Contains(low, "..\\") ||
		strings.Contains(low, "....//") || strings.Contains(low, "..%2f..%2f") {
		add("evasion:path-obfuscation")
	}

	// SQL-comment / inline-comment splitting to break up keywords
	// ("UNION/**/SELECT", "or/**/1=1", "--+", "%2f%2a").
	if strings.Contains(low, "/**/") || strings.Contains(low, "%2f%2a") ||
		strings.Contains(low, "/*!") || strings.Contains(low, "--+") {
		add("evasion:sql-comment")
	}

	return out
}

// enumerationMethods are the HTTP verbs whose use is itself an enumeration /
// discovery signal: WebDAV/option discovery (OPTIONS/PROPFIND), cross-site
// tracing (TRACE/TRACK), and the legacy debug verbs.
var enumerationMethods = map[string]bool{
	"OPTIONS": true, "TRACE": true, "TRACK": true, "PROPFIND": true,
	"PROPPATCH": true, "MKCOL": true, "DEBUG": true, "SEARCH": true,
}

// httpEnumerationMarkers flags active-enumeration techniques visible in a
// single request: method/verb enumeration (OPTIONS/TRACE/PROPFIND/DEBUG) and
// HTTP user/account-enumeration parameters paired with a login endpoint.
// Maps to ATT&CK T1595 (Active Scanning) / T1087 (Account Discovery).
func httpEnumerationMarkers(method, payload string) []string {
	var out []string
	add := func(m string) { out = appendUnique(out, m) }

	if enumerationMethods[strings.ToUpper(method)] {
		add("http-method-enumeration")
	}
	low := strings.ToLower(payload)
	// Account/user enumeration: a login/auth endpoint touched with a
	// username-style parameter (the precursor to a username-oracle sweep).
	authEndpoint := strings.Contains(low, "login") || strings.Contains(low, "signin") ||
		strings.Contains(low, "auth") || strings.Contains(low, "wp-login") ||
		strings.Contains(low, "account") || strings.Contains(low, "register")
	userParam := strings.Contains(low, "username=") || strings.Contains(low, "user=") ||
		strings.Contains(low, "email=") || strings.Contains(low, "login=") ||
		strings.Contains(low, "uid=") || strings.Contains(low, "account=")
	if authEndpoint && userParam {
		add("http-account-enumeration")
	}
	return out
}
