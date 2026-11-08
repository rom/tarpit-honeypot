package ui

import (
	"strings"
	"testing"
)

// TestRedactConfigSecrets: the /config renderer must mask an inline
// abuse_ch_auth_key value, but leave the env-var-name variant and empty values
// untouched.
func TestRedactConfigSecrets(t *testing.T) {
	in := "sensor:\n" +
		"  enrichment:\n" +
		"    abuse_ch_auth_key: my-real-secret-key\n" +
		"    abuse_ch_auth_key_env: ABUSE_CH_AUTH_KEY\n" +
		"  other:\n" +
		"    abuse_ch_auth_key: \"\"\n"
	out := redactConfigSecrets(in)
	if strings.Contains(out, "my-real-secret-key") {
		t.Error("inline abuse_ch_auth_key value was not redacted")
	}
	if !strings.Contains(out, "***REDACTED***") {
		t.Error("redaction marker missing")
	}
	// The env-var-name indirection must be preserved (it is not a secret).
	if !strings.Contains(out, "abuse_ch_auth_key_env: ABUSE_CH_AUTH_KEY") {
		t.Error("abuse_ch_auth_key_env was wrongly altered")
	}
	// An empty inline value needs no redaction marker on its line.
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, `abuse_ch_auth_key: ""`) && strings.Contains(ln, "REDACTED") {
			t.Error("empty value should not be redacted")
		}
	}
}
