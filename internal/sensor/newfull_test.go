package sensor

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestSensorNewFromFullExample(t *testing.T) {
	raw, err := os.ReadFile("../../configs/tarpit-honeypot.example-FULL.yaml")
	if err != nil {
		t.Skipf("example config not found: %v", err)
	}
	dir := t.TempDir()
	// Repoint data_dir at a tempdir so New's store/payload/session dirs land there.
	body := regexp.MustCompile(`(?m)^(\s*data_dir:).*$`).ReplaceAllString(string(raw), "${1} "+dir)
	p := filepath.Join(dir, "full.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load full example: %v", err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New(full example): %v", err)
	}
	if s == nil {
		t.Fatal("nil sensor")
	}
}
