// Package secretscan harvests the ATTACKER'S OWN secrets from anything they
// send the honeypot — HTTP headers and bodies, shell input, uploaded files,
// request payloads. Tools, agents and proxied victims routinely leak their API
// keys, bearer tokens, session cookies, private keys and DB connection strings
// into requests; capturing those is high-value intelligence (it attributes the
// operator and can even be actioned). This is the inbound counterpart to the
// planted honeytokens in internal/lure: those bait the attacker, this reaps what
// the attacker brings. Detection only — nothing is ever used.
package secretscan

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// Secret is one harvested credential/secret.
type Secret struct {
	Kind  string `json:"kind"`           // e.g. aws-access-key, github-token, jwt, bearer-token, private-key
	Value string `json:"value"`          // the captured secret (full — this is the intel)
	Hint  string `json:"hint,omitempty"` // decoded detail (e.g. user:pass for basic-auth)
}

// Redacted renders a secret safe for a glance (keeps the shape, hides the
// middle) — used for UI/logs where the full value would be noise or risk.
func (s Secret) Redacted() string {
	v := s.Value
	if len(v) <= 10 {
		return strings.Repeat("•", len(v))
	}
	return v[:4] + "…" + v[len(v)-4:] + " (" + itoa(len(v)) + " chars)"
}

const (
	maxSecrets   = 48
	maxValueLen  = 4096 // cap a single captured value (PEM keys can be large)
	maxScanBytes = 1 << 20
)

type detector struct {
	kind  string
	re    *regexp.Regexp
	group int // capture group holding the secret (0 = whole match)
}

// detectors are ordered most-specific first so a value a specific rule claims
// isn't also caught by the generic assignment rule.
var detectors = []detector{
	// --- cloud / vendor API keys & tokens (distinctive prefixes) ----------
	{"aws-access-key", regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|AIPA|A3T[A-Z0-9])[A-Z0-9]{16}\b`), 0},
	{"aws-secret-key", regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9/+]{40})`), 1},
	{"github-token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b`), 0},
	{"github-pat", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{60,}\b`), 0},
	{"gitlab-pat", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`), 0},
	{"slack-token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), 0},
	{"google-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), 0},
	{"google-oauth", regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{20,}\b`), 0},
	{"stripe-key", regexp.MustCompile(`\b[sr]k_live_[0-9A-Za-z]{20,}\b`), 0},
	{"anthropic-key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`), 0},
	{"openai-key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b`), 0},
	{"npm-token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), 0},
	{"pypi-token", regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{16,}\b`), 0},
	{"huggingface-token", regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}\b`), 0},
	{"sendgrid-key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`), 0},
	{"twilio-key", regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`), 0},
	{"telegram-bot-token", regexp.MustCompile(`\b\d{8,10}:AA[A-Za-z0-9_-]{32,}\b`), 0},
	// Capture the whole PEM block when the END marker is present (the key
	// material itself is the intel), falling back to the header alone when the
	// capture is truncated. maxValueLen bounds the stored value.
	{"private-key", regexp.MustCompile(`-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----(?:[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----)?`), 0},
	{"certificate", regexp.MustCompile(`-----BEGIN CERTIFICATE-----(?:[\s\S]*?-----END CERTIFICATE-----)?`), 0},
	// --- transport-carried credentials ------------------------------------
	{"basic-auth", regexp.MustCompile(`(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{8,})`), 1},
	{"bearer-token", regexp.MustCompile(`(?i)authorization:\s*bearer\s+([A-Za-z0-9._~+/=-]{8,})`), 1},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b`), 0},
	{"api-key-header", regexp.MustCompile(`(?i)(?:x-api-key|api[_-]?key|apikey)["']?\s*[=:]\s*["']?([A-Za-z0-9._-]{12,})`), 1},
	{"session-cookie", regexp.MustCompile(`(?i)\b(?:sessionid|session|phpsessid|jsessionid|connect\.sid|csrftoken|auth[_-]?token|access[_-]?token)=([A-Za-z0-9%._-]{8,})`), 1},
	{"db-uri", regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|ftp|sftp)://[^\s:@/]+:[^\s:@/]+@[^\s/"']+`), 0},
	// --- generic assignment (least specific; runs last) -------------------
	{"secret-assignment", regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|api[_-]?secret)["']?\s*[=:]\s*["']?([^\s"';,&]{6,})`), 1},
}

// Scan harvests secrets from text, de-duplicated by kind+value and bounded.
func Scan(text string) []Secret {
	if len(text) > maxScanBytes {
		text = text[:maxScanBytes]
	}
	var out []Secret
	seen := map[string]bool{}
	for _, d := range detectors {
		for _, m := range d.re.FindAllStringSubmatch(text, -1) {
			val := m[0]
			if d.group > 0 && d.group < len(m) {
				val = m[d.group]
			}
			val = strings.TrimSpace(val)
			if val == "" {
				continue
			}
			if len(val) > maxValueLen {
				val = val[:maxValueLen]
			}
			key := d.kind + "\x00" + val
			if seen[key] {
				continue
			}
			seen[key] = true
			s := Secret{Kind: d.kind, Value: val}
			if d.kind == "basic-auth" {
				if dec, err := base64.StdEncoding.DecodeString(val); err == nil && strings.Contains(string(dec), ":") {
					s.Hint = string(dec) // user:pass
				}
			}
			out = append(out, s)
			if len(out) >= maxSecrets {
				return out
			}
		}
	}
	return out
}

// ScanBytes is Scan over raw bytes.
func ScanBytes(b []byte) []Secret { return Scan(string(b)) }

// Kinds returns the distinct secret kinds found — a compact signal for anomaly
// markers / severity without exposing the values.
func Kinds(secrets []Secret) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range secrets {
		if !seen[s.Kind] {
			seen[s.Kind] = true
			out = append(out, s.Kind)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
