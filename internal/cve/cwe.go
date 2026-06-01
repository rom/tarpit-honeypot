package cve

import "sort"

// cweNames maps a CWE id to its short human-readable weakness-class name, so
// the CLI / UI / docs can render "CWE-89 — SQL Injection" rather than a bare
// id. Covers every CWE the catalog's records reference (plus a few common
// classes for forward-compatibility); the CVE→CWE links themselves live in
// cveExtra. This is the CWE analogue of mitre.Describe for ATT&CK techniques.
var cweNames = map[string]string{
	"CWE-20":   "Improper Input Validation",
	"CWE-22":   "Path Traversal",
	"CWE-44":   "Path Equivalence",
	"CWE-77":   "Command Injection",
	"CWE-78":   "OS Command Injection",
	"CWE-79":   "Cross-site Scripting (XSS)",
	"CWE-88":   "Argument Injection",
	"CWE-89":   "SQL Injection",
	"CWE-94":   "Code Injection",
	"CWE-119":  "Improper Restriction of Memory Buffer Bounds",
	"CWE-120":  "Classic Buffer Overflow",
	"CWE-121":  "Stack-based Buffer Overflow",
	"CWE-122":  "Heap-based Buffer Overflow",
	"CWE-190":  "Integer Overflow or Wraparound",
	"CWE-200":  "Exposure of Sensitive Information",
	"CWE-203":  "Observable Discrepancy",
	"CWE-222":  "Truncation of Security-relevant Information",
	"CWE-269":  "Improper Privilege Management",
	"CWE-284":  "Improper Access Control",
	"CWE-285":  "Improper Authorization",
	"CWE-287":  "Improper Authentication",
	"CWE-288":  "Authentication Bypass Using an Alternate Path or Channel",
	"CWE-290":  "Authentication Bypass by Spoofing",
	"CWE-300":  "Channel Accessible by Non-Endpoint (Adversary-in-the-Middle)",
	"CWE-306":  "Missing Authentication for Critical Function",
	"CWE-321":  "Use of Hard-coded Cryptographic Key",
	"CWE-330":  "Use of Insufficiently Random Values",
	"CWE-345":  "Insufficient Verification of Data Authenticity",
	"CWE-352":  "Cross-Site Request Forgery (CSRF)",
	"CWE-354":  "Improper Validation of Integrity Check Value",
	"CWE-364":  "Signal Handler Race Condition",
	"CWE-400":  "Uncontrolled Resource Consumption",
	"CWE-404":  "Improper Resource Shutdown or Release",
	"CWE-416":  "Use After Free",
	"CWE-420":  "Unprotected Alternate Channel",
	"CWE-425":  "Direct Request (Forced Browsing)",
	"CWE-434":  "Unrestricted Upload of File with Dangerous Type",
	"CWE-502":  "Deserialization of Untrusted Data",
	"CWE-522":  "Insufficiently Protected Credentials",
	"CWE-611":  "XML External Entity (XXE)",
	"CWE-640":  "Weak Password Recovery Mechanism",
	"CWE-674":  "Uncontrolled Recursion",
	"CWE-787":  "Out-of-bounds Write",
	"CWE-798":  "Use of Hard-coded Credentials",
	"CWE-824":  "Access of Uninitialized Pointer",
	"CWE-835":  "Loop with Unreachable Exit Condition (Infinite Loop)",
	"CWE-862":  "Missing Authorization",
	"CWE-863":  "Incorrect Authorization",
	"CWE-913":  "Improper Control of Dynamically-Managed Code Resources",
	"CWE-917":  "Expression Language Injection",
	"CWE-918":  "Server-Side Request Forgery (SSRF)",
	"CWE-924":  "Improper Enforcement of Message Integrity During Transmission",
	"CWE-1188": "Insecure Default Initialization of Resource",
	"CWE-1336": "Server-Side Template Injection (SSTI)",
	"CWE-1390": "Weak Authentication",
}

// CWEName returns the human-readable name for a CWE id ("CWE-89" ->
// "SQL Injection"), or "" if the id is unknown.
func CWEName(id string) string { return cweNames[id] }

// CWEEntry is one weakness class with the count of catalog CVEs that map to it.
type CWEEntry struct {
	ID    string
	Name  string
	Count int
}

// CWEs returns the CWE classes referenced by the CVE catalog, each annotated
// with its name and the number of CVEs that map to it, sorted by count (then
// id). It is the weakness-class coverage surface for `list-cves --cwe` and the
// attribution docs.
func CWEs() []CWEEntry {
	counts := map[string]int{}
	for _, r := range catalog {
		for _, c := range r.CWE {
			counts[c]++
		}
	}
	out := make([]CWEEntry, 0, len(counts))
	for id, n := range counts {
		out = append(out, CWEEntry{ID: id, Name: cweNames[id], Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].ID < out[j].ID
	})
	return out
}
