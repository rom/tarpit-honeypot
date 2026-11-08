package cve

import "strings"

// inferredCWEIDs records the CVE ids whose CWE was derived from the vulnerability
// class (name/description) rather than carried explicitly on the record or in
// cveExtra. Populated in init(); read via CWEInferred.
var inferredCWEIDs = map[string]bool{}

// CWEInferred reports whether a catalog record's CWE was inferred from its
// vulnerability class rather than authored/curated. (Docs and exports can mark
// these as best-effort rather than authoritative.)
func CWEInferred(id string) bool { return inferredCWEIDs[id] }

// cweRule maps a set of name/description needles to a weakness class.
type cweRule struct {
	needles []string
	id      string
}

// cweRules classify a vulnerability into a CWE from its name/description. Ordered
// most-specific first; the first match wins. Every id here must have a name in
// cwe.go (cweNames) so the referenced-CWE integrity test stays green.
var cweRules = []cweRule{
	{[]string{"sql injection", "sqli", "nosql injection"}, "CWE-89"},
	{[]string{"command injection", "os command", "command inject"}, "CWE-78"},
	{[]string{"deserialization", "deserialisation", "object injection"}, "CWE-502"},
	{[]string{"server-side template injection", "ssti", "template injection"}, "CWE-1336"},
	{[]string{"server-side request forgery", "ssrf"}, "CWE-918"},
	{[]string{"xml external entity", "xxe"}, "CWE-611"},
	{[]string{"cross-site scripting", "xss"}, "CWE-79"},
	{[]string{"cross-site request forgery", "csrf"}, "CWE-352"},
	{[]string{"jndi"}, "CWE-917"},
	{[]string{"path traversal", "directory traversal", "traversal", "path-based"}, "CWE-22"},
	{[]string{"file inclusion", "local file inclusion", "lfi", "remote file inclusion"}, "CWE-98"},
	{[]string{"file upload", "unrestricted upload", "arbitrary file write", "arbitrary plugin upload"}, "CWE-434"},
	{[]string{"file read", "file disclosure", "arbitrary file read", "file-read"}, "CWE-22"},
	{[]string{"missing authentication", "missing authorization", "unauthenticated"}, "CWE-306"},
	{[]string{"authentication bypass", "auth bypass", "improper authentication", "authorization bypass"}, "CWE-287"},
	{[]string{"broken access control", "access control", "improper access", "incorrect authorization"}, "CWE-284"},
	{[]string{"privilege escalation", "elevation of privilege"}, "CWE-269"},
	{[]string{"hardcoded", "hard-coded", "default credential", "default login", "default password"}, "CWE-798"},
	{[]string{"information disclosure", "info disclosure", "sensitive information", "exposure", "token exposure", "disclosure"}, "CWE-200"},
	{[]string{"buffer overflow", "out-of-bounds", "stack overflow", "heap overflow"}, "CWE-787"},
	{[]string{"open redirect"}, "CWE-601"},
	{[]string{"code execution", "code injection", "remote code execution", "rce", "arbitrary code"}, "CWE-94"},
	{[]string{"denial of service", "resource exhaustion", "dos"}, "CWE-400"},
	{[]string{"cache poisoning", "spoofing", "impersonation"}, "CWE-345"},
}

// inferCWE returns a weakness class inferred from a record's name/description,
// or ("", false) when nothing matches.
func inferCWE(name, desc string) (string, bool) {
	hay := strings.ToLower(name + " " + desc)
	for _, r := range cweRules {
		for _, n := range r.needles {
			if strings.Contains(hay, n) {
				return r.id, true
			}
		}
	}
	return "", false
}
