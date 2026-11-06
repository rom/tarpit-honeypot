package lure

import (
	"encoding/json"
	"strings"
	"testing"
)

const testSeed = "deploy-A"

func TestAllLuresGenerate(t *testing.T) {
	ls := All(testSeed)
	if len(ls) < 10 {
		t.Fatalf("want >=10 lures, got %d", len(ls))
	}
	seenKind, seenCanary := map[string]bool{}, map[string]bool{}
	for _, l := range ls {
		if l.Kind == "" || l.Filename == "" || len(l.Content) == 0 || l.Canary == "" {
			t.Errorf("%s: incomplete lure %+v", l.Kind, l)
		}
		if seenKind[l.Kind] {
			t.Errorf("duplicate kind %q", l.Kind)
		}
		seenKind[l.Kind] = true
		if seenCanary[l.Canary] {
			t.Errorf("%s: canary collides with another lure", l.Kind)
		}
		seenCanary[l.Canary] = true
	}
}

func TestDeterministic(t *testing.T) {
	a, b := All(testSeed), All(testSeed)
	for i := range a {
		if string(a[i].Content) != string(b[i].Content) || a[i].Canary != b[i].Canary {
			t.Errorf("%s not deterministic", a[i].Kind)
		}
	}
	if string(All("deploy-B")[0].Content) == string(a[0].Content) {
		t.Error("different seeds produced identical content")
	}
}

func TestFormatsValid(t *testing.T) {
	aws, _ := Generate("aws-credentials", testSeed)
	if !strings.Contains(string(aws.Content), "aws_access_key_id") || !strings.HasPrefix(aws.Canary, "AKIA") {
		t.Errorf("aws creds wrong: %s", aws.Content)
	}
	ssh, _ := Generate("ssh-private-key", testSeed)
	if !strings.HasPrefix(string(ssh.Content), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Error("ssh key missing PEM header")
	}
	// GCP service-account + dockerconfig must be valid JSON.
	for _, k := range []string{"gcp-service-account", "dockerconfig", "terraform-state"} {
		l, _ := Generate(k, testSeed)
		var v any
		if err := json.Unmarshal(l.Content, &v); err != nil {
			t.Errorf("%s not valid JSON: %v", k, err)
		}
	}
	jwt, _ := Generate("jwt-token", testSeed)
	if parts := strings.Count(string(jwt.Content), "."); parts < 2 {
		t.Errorf("JWT should have 3 dot-separated parts: %s", jwt.Content)
	}
}
