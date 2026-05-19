package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUILoopbackOK(t *testing.T) {
	dir := t.TempDir()
	cfg := write(t, dir, "cfg.yaml", `
sensor:
  data_dir: `+dir+`
ui:
  enabled: true
  bind: 127.0.0.1:8088
channels:
  - id: stdout
    type: stdout
routes:
  - match: { severity: ">=low" }
    channels: [stdout]
`)
	if _, err := Load(cfg); err != nil {
		t.Fatalf("loopback UI should validate: %v", err)
	}
}

func TestUINonLoopbackRejected(t *testing.T) {
	dir := t.TempDir()
	cfg := write(t, dir, "cfg.yaml", `
sensor:
  data_dir: `+dir+`
ui:
  enabled: true
  bind: 0.0.0.0:8088
channels:
  - id: stdout
    type: stdout
routes:
  - match: { severity: ">=low" }
    channels: [stdout]
`)
	_, err := Load(cfg)
	if err == nil {
		t.Fatal("non-loopback UI without TLS/auth should be rejected")
	}
	if !strings.Contains(err.Error(), "non-loopback") {
		t.Errorf("error should mention non-loopback; got: %v", err)
	}
}

func TestUINonLoopbackWithTLSAndAuth(t *testing.T) {
	dir := t.TempDir()
	certPath := write(t, dir, "ui.crt", "x")
	keyPath := write(t, dir, "ui.key", "x")
	cfg := write(t, dir, "cfg.yaml", `
sensor:
  data_dir: `+dir+`
ui:
  enabled: true
  bind: 0.0.0.0:8088
  tls_cert: `+certPath+`
  tls_key: `+keyPath+`
  auth_token_env: SOME_VAR
channels:
  - id: stdout
    type: stdout
routes:
  - match: { severity: ">=low" }
    channels: [stdout]
`)
	if _, err := Load(cfg); err != nil {
		t.Fatalf("non-loopback with TLS+auth should validate: %v", err)
	}
}
