package enrich

import (
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// credUserKeys / credPassKeys are the meta keys handlers use for a captured
// login username / password, across the protocol surface.
var credUserKeys = []string{"auth_user", "http_login_user", "user_attempt", "username", "user", "user_name"}
var credPassKeys = []string{"auth_pass", "password", "http_login_pass", "pass_attempt", "user_pass", "pass"}

// builtinDefaultPasswords is a tiny, always-on set of the most common default /
// trivial credentials, so cred_class works with no data file at all. The
// breached-password file (optional) extends the "breach" tier.
var builtinDefaultPasswords = map[string]struct{}{
	"": {}, "admin": {}, "password": {}, "root": {}, "toor": {}, "1234": {},
	"12345": {}, "123456": {}, "1234567": {}, "12345678": {}, "123456789": {},
	"guest": {}, "changeme": {}, "default": {}, "letmein": {}, "qwerty": {},
	"pass": {}, "test": {}, "user": {}, "admin123": {}, "root123": {},
	"password1": {}, "welcome": {}, "login": {}, "abc123": {}, "111111": {},
	"000000": {}, "support": {}, "oracle": {}, "postgres": {}, "ubnt": {},
}

// decorateCreds classifies any captured login credential on the event into
// cred_class: "default" (trivial / user==pass / known default), "breach" (on
// the operator's breached-password list), "weak" (short / all-digits), or
// "unique". Enrichment only — it never stores or echoes the secret.
func (e *Enricher) decorateCreds(ev *event.Event) {
	pass, ok := firstMeta(ev.Meta, credPassKeys)
	if !ok {
		return
	}
	user, _ := firstMeta(ev.Meta, credUserKeys)
	if c := classifyCred(user, pass, e.breachedPw); c != "" {
		ev.Meta["cred_class"] = c
	}
}

// firstMeta returns the first present, string-typed meta value among keys.
func firstMeta(m map[string]any, keys []string) (string, bool) {
	for _, k := range keys {
		if v, ok := m[k].(string); ok {
			return v, true
		}
	}
	return "", false
}

func classifyCred(user, pass string, breached map[string]struct{}) string {
	lp := strings.ToLower(pass)
	if user != "" && strings.EqualFold(user, pass) {
		return "default"
	}
	if _, ok := builtinDefaultPasswords[lp]; ok {
		return "default"
	}
	if breached != nil {
		if _, ok := breached[lp]; ok {
			return "breach"
		}
	}
	if isWeakPassword(pass) {
		return "weak"
	}
	return "unique"
}

// isWeakPassword flags short or trivially-structured passwords (all digits /
// all one character class) that aren't in the default/breach sets.
func isWeakPassword(p string) bool {
	if len(p) < 8 {
		return true
	}
	allDigit := true
	for _, r := range p {
		if r < '0' || r > '9' {
			allDigit = false
			break
		}
	}
	return allDigit
}
