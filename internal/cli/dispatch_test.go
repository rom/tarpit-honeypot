package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindSubcommand(t *testing.T) {
	cmdSet := map[string]command{"run": {}, "validate-config": {}, "reset-db": {}}
	cases := []struct {
		args []string
		want int // index of the subcommand, or -1
	}{
		{[]string{"run"}, 0},
		{[]string{"run", "-c", "x.yaml"}, 0}, // flag after
		{[]string{"-c", "x.yaml", "run"}, 2}, // flag (value) before
		{[]string{"--log-level", "debug", "validate-config"}, 2},
		{[]string{"-c", "x.yaml", "--set", "a=b", "run", "-c", "y"}, 4}, // flags both sides
		{[]string{"-c=x.yaml", "run"}, 1},                               // =-form value flag
		{[]string{"-c", "reset-db", "run"}, 2},                          // "reset-db" is -c's value, not the subcommand
		{[]string{"--help"}, -1},                                        // no subcommand
		{[]string{}, -1},
		{[]string{"bogus"}, -1},
	}
	for _, c := range cases {
		if got := findSubcommand(c.args, cmdSet); got != c.want {
			t.Errorf("findSubcommand(%v) = %d; want %d", c.args, got, c.want)
		}
	}
}

func TestResetDB(t *testing.T) {
	dir := t.TempDir()
	// Seed a data_dir.
	mustWrite(t, filepath.Join(dir, "events.db"), "db")
	mustWrite(t, filepath.Join(dir, "events.db-wal"), "wal")
	mustWrite(t, filepath.Join(dir, ".deployment-id"), "id") // must be preserved
	if err := os.MkdirAll(filepath.Join(dir, "events"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "events", "e-1.jsonl"), "{}")
	mustWrite(t, filepath.Join(dir, "devices.json"), "[]")
	if err := os.MkdirAll(filepath.Join(dir, "tls"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "tls", "host.key"), "key") // must be preserved

	// Dry-run must not delete anything.
	if err := cmdResetDB([]string{"--data-dir", dir}); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !exists(filepath.Join(dir, "events.db")) {
		t.Error("dry-run deleted events.db")
	}

	// Default --yes clears the event store, keeps devices.json + identity + tls.
	if err := cmdResetDB([]string{"--data-dir", dir, "--yes"}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if exists(filepath.Join(dir, "events.db")) {
		t.Error("events.db not removed")
	}
	if exists(filepath.Join(dir, "events", "e-1.jsonl")) {
		t.Error("events/ contents not cleared")
	}
	if !exists(filepath.Join(dir, "events")) {
		t.Error("events/ dir itself should be kept")
	}
	if !exists(filepath.Join(dir, "devices.json")) {
		t.Error("devices.json should be kept without --devices/--all")
	}
	if !exists(filepath.Join(dir, ".deployment-id")) || !exists(filepath.Join(dir, "tls", "host.key")) {
		t.Error("identity / tls must always be preserved")
	}

	// --all also clears devices.json.
	if err := cmdResetDB([]string{"--data-dir", dir, "--all", "--yes"}); err != nil {
		t.Fatalf("--all: %v", err)
	}
	if exists(filepath.Join(dir, "devices.json")) {
		t.Error("--all should remove devices.json")
	}
	if !exists(filepath.Join(dir, ".deployment-id")) {
		t.Error("--all must still preserve identity")
	}
}

func TestResetDBRefusesRootDataDir(t *testing.T) {
	if err := cmdResetDB([]string{"--data-dir", "/", "--yes"}); err == nil {
		t.Error("reset-db must refuse data_dir=/")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
