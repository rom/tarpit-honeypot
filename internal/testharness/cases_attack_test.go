package testharness

import (
	"strings"
	"testing"
)

// TestAttackGeneratorBuildsCases confirms the attack-replay generator emits a
// case per matching endpoint handler, with the right id + exploit-shaped probe.
func TestAttackGeneratorBuildsCases(t *testing.T) {
	cfg := &Config{
		Mode: "network",
		Endpoints: []Endpoint{
			{Label: "web", Proto: "tcp", Port: 8080, Handler: "http"},
			{Label: "ai", Proto: "tcp", Port: 11434, Handler: "ollama"},
			{Label: "agent", Proto: "tcp", Port: 3000, Handler: "mcp"},
			{Label: "s3", Proto: "tcp", Port: 9000, Handler: "minio"},
			{Label: "fridge", Proto: "tcp", Port: 80, Handler: "danfoss_aksm"},
		},
	}
	cases := Build(cfg)
	got := map[string]Case{}
	for _, c := range cases {
		if c.Category == CatAttack {
			got[c.ID] = c
		}
	}
	for _, want := range []string{
		"attack/http-log4shell", "attack/ollama-prompt-injection",
		"attack/mcp-tool-exec", "attack/minio-bootstrap", "attack/danfoss-auth-bypass",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing attack case %q (have %d attack cases)", want, len(got))
		}
	}
	// A handler with no configured endpoint produces no case.
	if _, ok := got["attack/clickhouse-file-read"]; ok {
		t.Error("clickhouse case built without a clickhouse endpoint")
	}
	// Endpoints must be bound (not all pointing at the last one — a classic
	// loop-variable-capture bug).
	if c := got["attack/ollama-prompt-injection"]; c.Endpoint != "ai" {
		t.Errorf("ollama case endpoint = %q; want ai", c.Endpoint)
	}
	if c := got["attack/http-log4shell"]; c.Endpoint != "web" {
		t.Errorf("log4shell case endpoint = %q; want web", c.Endpoint)
	}
}

func TestAttackProbeBuilders(t *testing.T) {
	p := postJSON("/api/generate", `{"prompt":"x"}`)
	if !strings.HasPrefix(p, "POST /api/generate HTTP/1.1\r\n") || !strings.Contains(p, "Content-Type: application/json") {
		t.Errorf("postJSON malformed: %q", p)
	}
	if !strings.HasSuffix(p, `{"prompt":"x"}`) {
		t.Errorf("postJSON body missing: %q", p)
	}
	if join([]string{"a", "b"}, ", ") != "a, b" {
		t.Error("join wrong")
	}
}
