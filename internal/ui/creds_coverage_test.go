package ui

import (
	"encoding/base64"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// The generalized extractCreds must surface credentials previously invisible on
// the captures page: protocol hashes, LDAP binds, vendor *_auth blobs, JWTs,
// session tokens, and generic <prefix>_user/_pass pairs from Lua personas.
func credsOf(meta map[string]any) []credPair {
	return extractCreds(&event.Event{Meta: meta})
}

func hasKind(cs []credPair, kind string) *credPair {
	for i := range cs {
		if cs[i].Kind == kind {
			return &cs[i]
		}
	}
	return nil
}

func TestExtractCredsGeneralized(t *testing.T) {
	cases := []struct {
		name string
		meta map[string]any
		kind string
		pass string // expected Pass substring ("" = don't check)
	}{
		{"ntlm hash", map[string]any{"ntlm_response_hex": "aabbcc"}, "hash", "aabbcc"},
		{"mysql hash", map[string]any{"auth_response_hex": "deadbeef"}, "hash", "deadbeef"},
		{"vnc challenge", map[string]any{"challenge_hex": "0011"}, "hash", "0011"},
		{"ldap bind pw", map[string]any{"bind_pw": "s3cret"}, "password", "s3cret"},
		{"jwt", map[string]any{"jwt_token": "eyJ.a.b"}, "jwt", "eyJ.a.b"},
		{"session token", map[string]any{"metabase_session": "abc123"}, "token", "abc123"},
		{"vendor auth", map[string]any{"zabbix_auth": "blob"}, "authorization", "blob"},
		{"gitlab token", map[string]any{"gitlab_token": "glpat-xxx"}, "token", "glpat-xxx"},
		{"consul token", map[string]any{"consul_token": "uuid-tok"}, "token", "uuid-tok"},
		{"k8s bearer", map[string]any{"k8s_bearer": "kube-tok"}, "token", "kube-tok"},
	}
	for _, c := range cases {
		cs := credsOf(c.meta)
		got := hasKind(cs, c.kind)
		if got == nil {
			t.Errorf("%s: no %q credential in %v", c.name, c.kind, cs)
			continue
		}
		if c.pass != "" && got.Pass != c.pass {
			t.Errorf("%s: Pass = %q want %q", c.name, got.Pass, c.pass)
		}
	}
}

func TestExtractCredsPrefixPairing(t *testing.T) {
	// adminer_username + adminer_password should pair into one password row.
	cs := credsOf(map[string]any{"adminer_username": "admin", "adminer_password": "hunter2"})
	p := hasKind(cs, "password")
	if p == nil || p.User != "admin" || p.Pass != "hunter2" {
		t.Errorf("prefix pairing failed: %v", cs)
	}
}

func TestExtractCredsBasicAuthDecode(t *testing.T) {
	// A Lua *_auth blob carrying "Basic base64(user:pass)" is decoded.
	blob := "Basic " + base64.StdEncoding.EncodeToString([]byte("root:toor"))
	cs := credsOf(map[string]any{"tomcat_auth": blob})
	p := hasKind(cs, "password")
	if p == nil || p.User != "root" || p.Pass != "toor" {
		t.Errorf("basic-auth decode failed: %v", cs)
	}
}

func TestClassifyCredKeyExclusions(t *testing.T) {
	for _, k := range []string{"user_agent", "auth_type", "ntlm_domain", "request_line", "host", "tools"} {
		if _, ok := classifyCredKey(k); ok {
			t.Errorf("%q must NOT be classified as a credential", k)
		}
	}
}
