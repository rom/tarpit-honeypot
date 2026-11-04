package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanaryToken(t *testing.T) {
	a := New("deployment-A").CanaryToken()
	b := New("deployment-B").CanaryToken()
	// Deterministic per seed.
	if a != New("deployment-A").CanaryToken() {
		t.Error("CanaryToken not deterministic for the same seed")
	}
	// Unique per deployment.
	if a == b {
		t.Errorf("CanaryToken collision across seeds: %q", a)
	}
	// 16 lowercase hex chars (8 bytes) — unique, but not secret-shaped.
	if len(a) != 16 {
		t.Errorf("CanaryToken len = %d; want 16 (%q)", len(a), a)
	}
	for _, c := range a {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("CanaryToken has non-hex char %q in %q", c, a)
		}
	}
}

func TestLoadPersistsAndReuses(t *testing.T) {
	dir := t.TempDir()
	a, err := Load(dir, "")
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if a.Seed() == "" {
		t.Fatal("empty seed")
	}
	// A second load reads the persisted id rather than minting a new one.
	b, err := Load(dir, "")
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if a.Seed() != b.Seed() {
		t.Errorf("deployment id not stable across loads: %q vs %q", a.Seed(), b.Seed())
	}
	if _, err := os.Stat(filepath.Join(dir, ".deployment-id")); err != nil {
		t.Errorf(".deployment-id not persisted: %v", err)
	}
}

func TestLoadOverrideNotPersisted(t *testing.T) {
	dir := t.TempDir()
	id, err := Load(dir, "fixed-seed")
	if err != nil || id.Seed() != "fixed-seed" {
		t.Fatalf("override load: seed=%q err=%v", id.Seed(), err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".deployment-id")); !os.IsNotExist(err) {
		t.Errorf("override must not be persisted (stat err=%v)", err)
	}
}

func TestIDPathHint(t *testing.T) {
	dir := t.TempDir()
	// No file yet -> the dir-write hint.
	missing := idPathHint(dir, filepath.Join(dir, ".deployment-id"))
	if !strings.Contains(missing, "chown -R") || !strings.Contains(missing, dir) {
		t.Errorf("dir hint not actionable: %q", missing)
	}
	// File exists -> the per-file chown hint.
	p := filepath.Join(dir, ".deployment-id")
	if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	exists := idPathHint(dir, p)
	if !strings.Contains(exists, "created by another user") || !strings.Contains(exists, p) {
		t.Errorf("file hint not actionable: %q", exists)
	}
	if !strings.Contains(exists, "restorecon") {
		t.Errorf("hint should mention SELinux relabel: %q", exists)
	}
}
