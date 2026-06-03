package cli

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// seedStore inserts n events spread one hour apart (newest first) into a fresh
// store under dir, then closes it.
func seedStore(t *testing.T, dir string, n int) {
	t.Helper()
	st, err := store.Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < n; i++ {
		ev := &event.Event{
			ID: event.NewID(), Time: now.Add(-time.Duration(i) * time.Hour),
			Sensor: "s", RuleID: "r", Severity: event.SeverityLow,
			Source: event.Endpoint{IP: "1.2.3.4"},
		}
		if err := st.Insert(context.Background(), ev); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

func countEvents(t *testing.T, dir string) int64 {
	t.Helper()
	st, err := store.Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var c int64
	if err := st.DB().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM events`).Scan(&c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRotateDBArchivesAndResets(t *testing.T) {
	dir := t.TempDir()
	seedStore(t, dir, 40)
	archive := filepath.Join(dir, "snap.db.gz")

	// Archive without reset: archive created, live store untouched.
	if err := cmdRotateDB([]string{"--data-dir", dir, "--out", archive}); err != nil {
		t.Fatalf("rotate-db: %v", err)
	}
	fi, err := os.Stat(archive)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("archive not written: %v", err)
	}
	// The archive must be a valid gzip stream.
	f, _ := os.Open(archive)
	if _, err := gzip.NewReader(f); err != nil {
		t.Errorf("archive is not valid gzip: %v", err)
	}
	f.Close()
	if got := countEvents(t, dir); got != 40 {
		t.Errorf("live store changed without --reset: %d", got)
	}

	// --reset without --yes is a dry-run.
	if err := cmdRotateDB([]string{"--data-dir", dir, "--out", filepath.Join(dir, "snap2.db.gz"), "--reset"}); err != nil {
		t.Fatalf("rotate-db dry-run: %v", err)
	}
	if got := countEvents(t, dir); got != 40 {
		t.Errorf("dry-run --reset emptied the store: %d", got)
	}

	// --reset --yes empties the live store.
	if err := cmdRotateDB([]string{"--data-dir", dir, "--out", filepath.Join(dir, "snap3.db.gz"), "--reset", "--yes"}); err != nil {
		t.Fatalf("rotate-db reset: %v", err)
	}
	if got := countEvents(t, dir); got != 0 {
		t.Errorf("store not emptied after --reset --yes: %d", got)
	}
}

func TestPruneDBKeepRowsAndDays(t *testing.T) {
	// keep-rows: dry-run keeps everything; --yes trims to the newest N.
	dir := t.TempDir()
	seedStore(t, dir, 50)
	if err := cmdPruneDB([]string{"--data-dir", dir, "--keep-rows", "10"}); err != nil {
		t.Fatalf("prune dry-run: %v", err)
	}
	if got := countEvents(t, dir); got != 50 {
		t.Errorf("dry-run deleted rows: %d", got)
	}
	if err := cmdPruneDB([]string{"--data-dir", dir, "--keep-rows", "10", "--yes"}); err != nil {
		t.Fatalf("prune keep-rows: %v", err)
	}
	if got := countEvents(t, dir); got != 10 {
		t.Errorf("keep-rows=10 left %d rows", got)
	}

	// keep-days: events are one hour apart, so keep-days=1 keeps ~24 of 50.
	dir2 := t.TempDir()
	seedStore(t, dir2, 50)
	if err := cmdPruneDB([]string{"--data-dir", dir2, "--keep-days", "1", "--yes"}); err != nil {
		t.Fatalf("prune keep-days: %v", err)
	}
	got := countEvents(t, dir2)
	if got < 20 || got > 26 {
		t.Errorf("keep-days=1 left %d rows; want ~24", got)
	}
}

func TestPruneDBRejectsBadModes(t *testing.T) {
	dir := t.TempDir()
	seedStore(t, dir, 5)
	if err := cmdPruneDB([]string{"--data-dir", dir}); err == nil {
		t.Error("prune-db with no mode should error")
	}
	if err := cmdPruneDB([]string{"--data-dir", dir, "--keep-rows", "1", "--keep-days", "1"}); err == nil {
		t.Error("prune-db with two modes should error")
	}
}
