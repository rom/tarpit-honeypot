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
	"CWE-74":   "Improper Neutralization in Output (Injection)",
	"CWE-77":   "Command Injection",
	"CWE-78":   "OS Command Injection",
	"CWE-79":   "Cross-site Scripting (XSS)",
	"CWE-88":   "Argument Injection",
	"CWE-89":   "SQL Injection",
	"CWE-91":   "XML Injection (Blind XPath Injection)",
	"CWE-94":   "Code Injection",
	"CWE-116":  "Improper Encoding or Escaping of Output",
	"CWE-119":  "Improper Restriction of Memory Buffer Bounds",
	"CWE-134":  "Use of Externally-Controlled Format String",
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
	"CWE-328":  "Use of Weak Hash",
	"CWE-330":  "Use of Insufficiently Random Values",
	"CWE-345":  "Insufficient Verification of Data Authenticity",
	"CWE-352":  "Cross-Site Request Forgery (CSRF)",
	"CWE-354":  "Improper Validation of Integrity Check Value",
	"CWE-364":  "Signal Handler Race Condition",
	"CWE-400":  "Uncontrolled Resource Consumption",
	"CWE-406":  "Insufficient Control of Network Message Volume (Network Amplification)",
	"CWE-404":  "Improper Resource Shutdown or Release",
	"CWE-610":  "Externally Controlled Reference to a Resource in Another Sphere",
	"CWE-415":  "Double Free",
	"CWE-416":  "Use After Free",
	"CWE-426":  "Untrusted Search Path",
	"CWE-420":  "Unprotected Alternate Channel",
	"CWE-425":  "Direct Request (Forced Browsing)",
	"CWE-434":  "Unrestricted Upload of File with Dangerous Type",
	"CWE-502":  "Deserialization of Untrusted Data",
	"CWE-506":  "Embedded Malicious Code",
	"CWE-522":  "Insufficiently Protected Credentials",
	"CWE-611":  "XML External Entity (XXE)",
	"CWE-617":  "Reachable Assertion",
	"CWE-640":  "Weak Password Recovery Mechanism",
	"CWE-674":  "Uncontrolled Recursion",
	"CWE-732":  "Incorrect Permission Assignment for Critical Resource",
	"CWE-770":  "Allocation of Resources Without Limits or Throttling",
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
	"CWE-1392": "Use of Default Credentials",
	"CWE-358":  "Improperly Implemented Security Check for Standard",
	"CWE-749":  "Exposed Dangerous Method or Function",
	"CWE-757":  "Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')",
	"CWE-943":  "Improper Neutralization of Special Elements in Data Query Logic",

	// Broader weakness-class coverage (forward-compatibility for custom rules
	// and future catalog entries).
	"CWE-23":  "Relative Path Traversal",
	"CWE-36":  "Absolute Path Traversal",
	"CWE-59":  "Improper Link Resolution Before File Access (Link Following)",
	"CWE-73":  "External Control of File Name or Path",
	"CWE-90":  "LDAP Injection",
	"CWE-93":  "Improper Neutralization of CRLF Sequences (CRLF Injection)",
	"CWE-95":  "Eval Injection",
	"CWE-98":  "PHP Remote File Inclusion",
	"CWE-209": "Generation of Error Message Containing Sensitive Information",
	"CWE-250": "Execution with Unnecessary Privileges",
	"CWE-294": "Authentication Bypass by Capture-replay",
	"CWE-295": "Improper Certificate Validation",
	"CWE-307": "Improper Restriction of Excessive Authentication Attempts",
	"CWE-312": "Cleartext Storage of Sensitive Information",
	"CWE-319": "Cleartext Transmission of Sensitive Information",
	"CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
	"CWE-338": "Use of Cryptographically Weak PRNG",
	"CWE-347": "Improper Verification of Cryptographic Signature",
	"CWE-384": "Session Fixation",
	"CWE-427": "Uncontrolled Search Path Element",
	"CWE-470": "Use of Externally-Controlled Input to Select Class (Unsafe Reflection)",
	"CWE-476": "NULL Pointer Dereference",
	"CWE-494": "Download of Code Without Integrity Check",
	"CWE-552": "Files or Directories Accessible to External Parties",
	"CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
	"CWE-639": "Authorization Bypass Through User-Controlled Key (IDOR)",
	"CWE-643": "XPath Injection",
	"CWE-776": "Improper Restriction of Recursive Entity References (XML Entity Expansion)",
	"CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
	"CWE-843": "Access of Resource Using Incompatible Type (Type Confusion)",

	// Memory-safety, crypto, auth, concurrency and logging classes common in
	// IoT/embedded/OT firmware and appliances.
	"CWE-117": "Improper Output Neutralization for Logs",
	"CWE-125": "Out-of-bounds Read",
	"CWE-129": "Improper Validation of Array Index",
	"CWE-131": "Incorrect Calculation of Buffer Size",
	"CWE-191": "Integer Underflow (Wrap or Wraparound)",
	"CWE-193": "Off-by-one Error",
	"CWE-256": "Plaintext Storage of a Password",
	"CWE-259": "Use of Hard-coded Password",
	"CWE-276": "Incorrect Default Permissions",
	"CWE-297": "Improper Validation of Certificate with Host Mismatch",
	"CWE-311": "Missing Encryption of Sensitive Data",
	"CWE-322": "Key Exchange without Entity Authentication",
	"CWE-323": "Reusing a Nonce, Key Pair in Encryption",
	"CWE-326": "Inadequate Encryption Strength",
	"CWE-346": "Origin Validation Error",
	"CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)",
	"CWE-367": "Time-of-check Time-of-use (TOCTOU) Race Condition",
	"CWE-369": "Divide By Zero",
	"CWE-401": "Missing Release of Memory after Effective Lifetime",
	"CWE-409": "Improper Handling of Highly Compressed Data (Data Amplification)",
	"CWE-444": "Inconsistent Interpretation of HTTP Requests (Request Smuggling)",
	"CWE-451": "User Interface Misrepresentation of Critical Information (Clickjacking)",
	"CWE-489": "Active Debug Code",
	"CWE-497": "Exposure of Sensitive System Information to an Unauthorized Control Sphere",
	"CWE-521": "Weak Password Requirements",
	"CWE-532": "Insertion of Sensitive Information into Log File",
	"CWE-613": "Insufficient Session Expiration",
	"CWE-665": "Improper Initialization",
	"CWE-754": "Improper Check for Unusual or Exceptional Conditions",
	"CWE-759": "Use of a One-Way Hash without a Salt",
	"CWE-805": "Buffer Access with Incorrect Length Value",
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
