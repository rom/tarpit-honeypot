//go:build linux

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestLandlockConfinesWrites applies the real Landlock policy in a
// subprocess (writable only under data_dir) and confirms a write inside
// data_dir succeeds while a write outside is denied.
func TestLandlockConfinesWrites(t *testing.T) {
	if os.Getenv("SANDBOX_LANDLOCK_CHILD") == "1" {
		dataDir := os.Getenv("SANDBOX_DATA_DIR")
		outside := os.Getenv("SANDBOX_OUTSIDE_DIR")
		if landlockABI() < 1 {
			os.Exit(childSkip)
		}
		if err := applyLandlock(Config{DataDir: dataDir, ReadPaths: []string{"/"}}); err != nil {
			os.Exit(childSkip)
		}
		// Inside data_dir: must succeed.
		if err := os.WriteFile(filepath.Join(dataDir, "ok"), []byte("x"), 0o600); err != nil {
			os.Exit(5)
		}
		// Outside data_dir: must be denied.
		if err := os.WriteFile(filepath.Join(outside, "evil"), []byte("x"), 0o600); err == nil {
			os.Exit(6) // write unexpectedly succeeded
		}
		// Reads outside must still work (read-all policy).
		if _, err := os.ReadDir("/"); err != nil {
			os.Exit(7)
		}
		os.Exit(0)
	}

	dataDir := t.TempDir()
	outside := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestLandlockConfinesWrites")
	cmd.Env = append(os.Environ(),
		"SANDBOX_LANDLOCK_CHILD=1",
		"SANDBOX_DATA_DIR="+dataDir,
		"SANDBOX_OUTSIDE_DIR="+outside,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		switch ee.ExitCode() {
		case childSkip:
			t.Skip("landlock not supported in this environment")
		case 6:
			t.Fatal("landlock did not block a write outside data_dir")
		}
	}
	t.Fatalf("landlock child failed: %v\n%s", err, out)
}
