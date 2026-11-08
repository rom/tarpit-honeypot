// Package creds holds the default-credential corpus the sensor uses
// for two purposes:
//
//  1. Deception: low-interaction auth handlers (ftp_files, telnet,
//     http basic-auth) can be configured to ACCEPT a small set of
//     well-known default credentials so an attacker who tries
//     admin/admin actually "gets in" and reveals more TTPs.
//
//  2. Detection: every handler that captures a credential pair runs
//     it through Match. A hit on a known vendor-default
//     (admin/admin, root/calvin, cisco/cisco, ...) is high signal —
//     it means the attacker is running a default-credential sweep,
//     which we surface as the `default-credential-attempt` anomaly
//     and tag with ATT&CK T1078.001 (Valid Accounts: Default
//     Accounts).
//
// The corpus is intentionally small + curated from the credentials
// real IoT / network / ICS gear ships with (the Mirai list, router
// defaults, BMC defaults, database defaults). It is NOT a brute-force
// wordlist.
package creds

import "strings"

// Cred is a single username/password default pair plus the rough
// device class it belongs to (for the event meta).
type Cred struct {
	User     string
	Pass     string
	Category string // "router", "ics", "bmc", "database", "generic", "camera"
}

// defaults is the curated vendor-default corpus.
var defaults = []Cred{
	// Generic / OS.
	{"root", "root", "generic"},
	{"root", "", "generic"},
	{"root", "toor", "generic"},
	{"root", "admin", "generic"},
	{"admin", "admin", "generic"},
	{"admin", "", "generic"},
	{"admin", "password", "generic"},
	{"admin", "1234", "generic"},
	{"admin", "12345", "generic"},
	{"admin", "123456", "generic"},
	{"user", "user", "generic"},
	{"guest", "guest", "generic"},
	{"test", "test", "generic"},
	{"administrator", "administrator", "generic"},

	// Routers / network gear (Mirai-class + vendor defaults).
	{"admin", "admin1234", "router"},
	{"admin", "smcadmin", "router"},
	{"cisco", "cisco", "router"},
	{"ubnt", "ubnt", "router"},
	{"admin", "Zte521", "router"},
	{"root", "vizxv", "camera"},
	{"root", "xc3511", "camera"},
	{"root", "888888", "camera"},
	{"root", "54321", "camera"},
	{"supervisor", "supervisor", "camera"},

	// BMC / IPMI (Dell iDRAC, HP iLO, Supermicro).
	// admin/admin lives in the generic set; not duplicated here.
	{"root", "calvin", "bmc"},
	{"ADMIN", "ADMIN", "bmc"},
	{"Administrator", "password", "bmc"},

	// Databases. root/"" and root/root live in the generic set.
	{"sa", "", "database"},
	{"sa", "sa", "database"},
	{"postgres", "postgres", "database"},
	{"oracle", "oracle", "database"},
	{"mysql", "mysql", "database"},

	// ICS / OT (PLC + HMI + SCADA web defaults). admin/admin is
	// already covered by the generic set above; don't duplicate it
	// (the map index would otherwise just overwrite the category).
	{"Administrator", "0", "ics"},
	{"plcadmin", "plcadmin", "ics"},
	{"operator", "operator", "ics"},
	{"engineer", "engineer", "ics"},
}

// index for O(1) Match. Keyed by lower(user)+"\x00"+pass (pass is
// case-sensitive; user typically isn't on the gear we model).
var index = func() map[string]Cred {
	m := make(map[string]Cred, len(defaults))
	for _, c := range defaults {
		m[key(c.User, c.Pass)] = c
	}
	return m
}()

func key(user, pass string) string {
	return strings.ToLower(user) + "\x00" + pass
}

// Match reports whether (user, pass) is a known vendor-default
// credential, returning the matched Cred (with its Category) and
// true. Username match is case-insensitive; password is exact.
func Match(user, pass string) (Cred, bool) {
	c, ok := index[key(user, pass)]
	return c, ok
}

// Accepts reports whether the handler should treat (user, pass) as a
// successful login given the configured accept-policy. The policy is
// one of:
//
//	""        / "none"   -> never accept (pure capture; default)
//	"defaults"           -> accept any credential in the default corpus
//	"any"                -> accept anything (maximum engagement)
//
// A nil / unknown policy is treated as "none".
func Accepts(policy, user, pass string) bool {
	switch policy {
	case "any":
		return true
	case "defaults":
		_, ok := Match(user, pass)
		return ok
	}
	return false
}

// AcceptsCustom reports whether (user, pass) matches an entry in an
// operator-supplied accept-list. Each entry is "user:pass"; a "*" in either
// field matches anything, and an entry with no ":" matches any password for
// that user. Username matching is case-insensitive; password is exact (unless
// "*"). This lets a deployment pin exactly which weak credentials "work" (e.g.
// make the decoy behave like a real box whose password is root:hunter2), beyond
// the built-in default corpus.
func AcceptsCustom(list []string, user, pass string) bool {
	for _, e := range list {
		u, p, hasColon := strings.Cut(strings.TrimSpace(e), ":")
		if !hasColon {
			p = "*"
		}
		if (u == "*" || strings.EqualFold(u, user)) && (p == "*" || p == pass) {
			return true
		}
	}
	return false
}

// AcceptsWith combines the built-in policy with an operator accept-list: a login
// succeeds if either the policy (none|defaults|any) or the custom list accepts
// it. Handlers call this so `credential_list` works regardless of `accept_creds`.
func AcceptsWith(policy string, list []string, user, pass string) bool {
	return Accepts(policy, user, pass) || AcceptsCustom(list, user, pass)
}

// All returns the full default corpus (used by docs / tests).
func All() []Cred { return defaults }
