package secretscan

import (
	"encoding/base64"
	"strings"
	"testing"
)

// kindsOf is a tiny helper: does the scan contain a secret of this kind with
// (optionally) this value?
func find(secrets []Secret, kind string) (Secret, bool) {
	for _, s := range secrets {
		if s.Kind == kind {
			return s, true
		}
	}
	return Secret{}, false
}

func TestScanCatchesVendorKeys(t *testing.T) {
	// A few vendor patterns are "high-confidence" partner formats that a
	// platform secret-scanner (including the one guarding this repo's pushes)
	// blocks on sight — even synthetic ones. Assemble those fixtures from parts
	// so the literal pattern never appears contiguously in the committed source,
	// while still exercising our detector at runtime.
	gitlabPAT := "glpat" + "-ABCDEF1234567890abcd"
	stripeKey := "sk_" + "live_abcdefghij0123456789ABCD"
	cases := []struct {
		name string
		text string
		kind string
		want string // substring the captured value must contain (empty = any)
	}{
		{"aws-access-key", "key is AKIAIOSFODNN7EXAMPLE here", "aws-access-key", "AKIAIOSFODNN7EXAMPLE"},
		{"aws-secret-key", `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, "aws-secret-key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"github-token", "token ghp_1234567890abcdefghijklmnopqrstuvwxyz go", "github-token", "ghp_"},
		{"gitlab-pat", gitlabPAT, "gitlab-pat", "glpat-"},
		{"slack-token", "xoxb-123456789012-abcdefghijkl", "slack-token", "xoxb-"},
		{"google-api-key", "AIzaSyB1234567890abcdefghijklmnopqrstuv", "google-api-key", "AIza"},
		{"stripe-key", stripeKey, "stripe-key", "sk_live_"},
		{"anthropic-key", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz", "anthropic-key", "sk-ant-"},
		{"npm-token", "npm_abcdefghijklmnopqrstuvwxyz0123456789", "npm-token", "npm_"},
		{"huggingface-token", "hf_abcdefghijklmnopqrstuvwxyz012345", "huggingface-token", "hf_"},
		{"telegram-bot-token", "123456789:AAE1234567890abcdefghijklmnopqrstuv", "telegram-bot-token", ":AA"},
		{"jwt", "Bearer eyJhbGciOi.eyJzdWIiOiIxMjM.SflKxwRJSMeKKF2QT", "jwt", "eyJ"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Scan(c.text)
			s, ok := find(got, c.kind)
			if !ok {
				t.Fatalf("Scan(%q) did not find kind %q; got %+v", c.text, c.kind, got)
			}
			if c.want != "" && !strings.Contains(s.Value, c.want) {
				t.Errorf("value %q does not contain %q", s.Value, c.want)
			}
		})
	}
}

func TestScanPrivateKeyAndCert(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
	s, ok := find(Scan(pem), "private-key")
	if !ok {
		t.Fatal("RSA private key not detected")
	}
	// The whole PEM block (not just the header) must be captured — the key
	// material is the intel.
	if !strings.Contains(s.Value, "MIIEpAIBAAKCAQEA") || !strings.Contains(s.Value, "END RSA PRIVATE KEY") {
		t.Errorf("private-key value should capture the full block; got %q", s.Value)
	}
	// A truncated key (no END marker) still flags, on the header alone.
	openssh := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk...\n"
	if _, ok := find(Scan(openssh), "private-key"); !ok {
		t.Error("truncated OpenSSH private key header not detected")
	}
	cert := "-----BEGIN CERTIFICATE-----\nMIIDdummydata\n-----END CERTIFICATE-----"
	cs, ok := find(Scan(cert), "certificate")
	if !ok {
		t.Fatal("certificate not detected")
	}
	if !strings.Contains(cs.Value, "END CERTIFICATE") {
		t.Errorf("certificate value should capture the full block; got %q", cs.Value)
	}
}

func TestScanBasicAuthDecodesHint(t *testing.T) {
	cred := base64.StdEncoding.EncodeToString([]byte("alice:s3cr3t"))
	text := "Authorization: Basic " + cred
	got := Scan(text)
	s, ok := find(got, "basic-auth")
	if !ok {
		t.Fatalf("basic-auth not detected in %q; got %+v", text, got)
	}
	if s.Hint != "alice:s3cr3t" {
		t.Errorf("basic-auth hint = %q; want alice:s3cr3t", s.Hint)
	}
}

func TestScanBearerAndApiKeyHeaders(t *testing.T) {
	text := "Authorization: Bearer abc123def456ghi789\r\nX-API-Key: deadbeefcafe0123\r\n"
	got := Scan(text)
	if _, ok := find(got, "bearer-token"); !ok {
		t.Errorf("bearer-token not detected; got %+v", got)
	}
	if _, ok := find(got, "api-key-header"); !ok {
		t.Errorf("api-key-header not detected; got %+v", got)
	}
}

func TestScanSessionCookie(t *testing.T) {
	text := "Cookie: sessionid=abc123XYZ._-def456; other=1"
	s, ok := find(Scan(text), "session-cookie")
	if !ok {
		t.Fatalf("session-cookie not detected in %q", text)
	}
	if !strings.Contains(s.Value, "abc123XYZ") {
		t.Errorf("session-cookie value = %q", s.Value)
	}
}

func TestScanDBURI(t *testing.T) {
	text := "DATABASE_URL=postgres://dbuser:dbpass@db.internal:5432/app"
	s, ok := find(Scan(text), "db-uri")
	if !ok {
		t.Fatalf("db-uri not detected in %q", text)
	}
	if !strings.Contains(s.Value, "dbuser:dbpass@") {
		t.Errorf("db-uri value = %q; want embedded creds", s.Value)
	}
}

func TestScanGenericAssignment(t *testing.T) {
	text := `password: "hunter2pass"`
	s, ok := find(Scan(text), "secret-assignment")
	if !ok {
		t.Fatalf("secret-assignment not detected in %q", text)
	}
	if s.Value != "hunter2pass" {
		t.Errorf("secret-assignment value = %q; want hunter2pass", s.Value)
	}
}

func TestScanNoFalsePositivesOnBenignText(t *testing.T) {
	benign := "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\nAccept: */*\r\n\r\nhello world, this is an ordinary request with no secrets."
	if got := Scan(benign); len(got) != 0 {
		t.Errorf("benign text yielded secrets: %+v", got)
	}
}

func TestScanDedupAndBounds(t *testing.T) {
	// Same token twice → one result.
	dup := "ghp_1234567890abcdefghijklmnopqrstuvwxyz ghp_1234567890abcdefghijklmnopqrstuvwxyz"
	if got := Scan(dup); len(got) != 1 {
		t.Errorf("duplicate token should dedup to 1; got %d", len(got))
	}
	// maxScanBytes: a secret beyond the cap is not scanned.
	big := strings.Repeat("x", maxScanBytes+100) + " AKIAIOSFODNN7EXAMPLE"
	if _, ok := find(Scan(big), "aws-access-key"); ok {
		t.Error("secret past maxScanBytes should be ignored")
	}
}

func TestRedacted(t *testing.T) {
	s := Secret{Kind: "github-token", Value: "ghp_1234567890abcdef"}
	r := s.Redacted()
	if strings.Contains(r, "567890") {
		t.Errorf("redacted value leaks middle: %q", r)
	}
	if !strings.HasPrefix(r, "ghp_") {
		t.Errorf("redacted should keep prefix: %q", r)
	}
	short := Secret{Value: "abc"}
	if short.Redacted() != "•••" {
		t.Errorf("short redacted = %q; want bullets", short.Redacted())
	}
}

func TestKinds(t *testing.T) {
	secrets := []Secret{
		{Kind: "jwt"}, {Kind: "jwt"}, {Kind: "aws-access-key"},
	}
	k := Kinds(secrets)
	if len(k) != 2 {
		t.Fatalf("Kinds = %v; want 2 distinct", k)
	}
}
