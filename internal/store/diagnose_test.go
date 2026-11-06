package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFingerprintKindOrder checks the exported kind order is non-empty and that
// callers get an independent copy (mutating the result can't corrupt the
// package-level source of truth).
func TestFingerprintKindOrder(t *testing.T) {
	got := FingerprintKindOrder()
	if len(got) == 0 {
		t.Fatal("FingerprintKindOrder returned empty")
	}
	got[0] = "MUTATED"
	if again := FingerprintKindOrder(); again[0] == "MUTATED" {
		t.Error("FingerprintKindOrder must return a defensive copy")
	}
}

// TestOpenError covers both branches: with a diagnosable path (hint appended)
// and with a healthy path (bare wrapped error).
func TestOpenError(t *testing.T) {
	base := errors.New("boom")
	dir := t.TempDir()

	withHint := openError("open", filepath.Join(dir, "missing", "db.sqlite"), base)
	if !strings.Contains(withHint.Error(), "does not exist") || !errors.Is(withHint, base) {
		t.Errorf("openError with bad path = %q; want hint + wrapped base", withHint)
	}
	noHint := openError("open", filepath.Join(dir, "ok.sqlite"), base)
	if strings.Contains(noHint.Error(), "(") || !errors.Is(noHint, base) {
		t.Errorf("openError with healthy path = %q; want no parenthesised hint", noHint)
	}
}

// TestDirAndFileWritable covers the writable probes' success and failure paths.
func TestDirAndFileWritable(t *testing.T) {
	dir := t.TempDir()
	if !dirWritable(dir) {
		t.Error("dirWritable(tempdir) = false; want true")
	}
	if dirWritable(filepath.Join(dir, "nonexistent-subdir")) {
		t.Error("dirWritable(missing dir) = true; want false")
	}

	f := filepath.Join(dir, "w.txt")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !fileWritable(f) {
		t.Error("fileWritable(existing writable file) = false; want true")
	}
	if fileWritable(filepath.Join(dir, "does-not-exist")) {
		t.Error("fileWritable(missing path) = true; want false")
	}
}
