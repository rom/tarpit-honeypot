package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// bigEvent builds an event whose meta is large enough that a few thousand of
// them bloat the on-disk file well past a 1 MiB cap.
func bigEvent(id string, t time.Time) *event.Event {
	return &event.Event{
		ID:       id,
		Time:     t,
		Sensor:   "test",
		RuleID:   "listener:ssh",
		Severity: event.SeverityLow,
		Source:   event.Endpoint{IP: "1.2.3.4", Port: 1234},
		Dest:     event.Endpoint{IP: "10.0.0.1", Port: 22},
		Proto:    "tcp",
		Handler:  "ssh",
		Meta:     map[string]any{"blob": strings.Repeat("A", 4096)},
	}
}

func countEvents(t *testing.T, s *Store) int64 {
	t.Helper()
	var n int64
	if err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM events`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestMaybePruneKeysOffLogicalNotFileSize is the regression for the runaway
// size-cap prune: once the events.db file ratcheted past sensor.disk.sqlite_mb
// (the default is 500 MB even with no sensor.disk block), the old prune — which
// compared os.Stat().Size() to the cap — fired on every prunePeriod tick forever
// because a DELETE never shrinks the file. That pinned the table to a sliver of
// the newest events regardless of retention (the "14d shows no more data than
// 24h" symptom). The fix compares the *logical* used bytes, which fall after a
// DELETE, so once the live data is under the cap the prune must stop.
func TestMaybePruneKeysOffLogicalNotFileSize(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Build the pathological state with NO cap (capMB=0 => prune disabled): a
	// physically bloated file holding only a tiny live set.
	s, err := OpenTuned(dir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 2000; i++ {
		if err := s.Insert(ctx, bigEvent(strings.Repeat("o", 1)+itoa(i), old)); err != nil {
			t.Fatal(err)
		}
	}
	// 40 recent keepers — well under 1 MiB logically.
	const keepers = 40
	recent := time.Now()
	for i := 0; i < keepers; i++ {
		if err := s.Insert(ctx, mkEvent("k"+itoa(i), "9.9.9.9", "listener:http", event.SeverityLow, recent)); err != nil {
			t.Fatal(err)
		}
	}
	// Delete the 2000 old rows -> frees pages into the freelist; the file stays
	// large but the logical size collapses to the 40 keepers.
	if _, _, err := s.PruneBefore(ctx, time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}

	// Sanity: the file is bloated (> 2 MiB) but the logical size is tiny.
	info, err := os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() < 2*1024*1024 {
		t.Fatalf("test did not bloat the file: %d bytes", info.Size())
	}
	used, ok := s.logicalUsedBytes(ctx)
	if !ok || used >= 1024*1024 {
		t.Fatalf("logical size not small after prune: used=%d ok=%v", used, ok)
	}

	// Now impose a 1 MiB cap and drive many prune ticks. With the old file-size
	// check this would delete 10% of the keepers on every tick; with the logical
	// check it must be a no-op because used < cap.
	s.capMB = 1
	for i := 0; i < 10; i++ {
		s.pruneTick.Store(prunePeriod - 1) // next call lands on the boundary
		s.maybePrune(ctx)
	}
	if got := countEvents(t, s); got != keepers {
		t.Errorf("prune ran away: %d events remain, want %d (all keepers)", got, keepers)
	}
	_ = s.Close()
}

// TestReclaimBloatVacuumsAtOpen: a database left bloated by the old prune is
// shrunk by a one-time VACUUM when reopened with a cap, without losing data.
func TestReclaimBloatVacuumsAtOpen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	s, err := OpenTuned(dir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 2000; i++ {
		if err := s.Insert(ctx, bigEvent("o"+itoa(i), old)); err != nil {
			t.Fatal(err)
		}
	}
	const keepers = 25
	recent := time.Now()
	for i := 0; i < keepers; i++ {
		if err := s.Insert(ctx, mkEvent("k"+itoa(i), "9.9.9.9", "listener:http", event.SeverityLow, recent)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.PruneBefore(ctx, time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	before := beforeInfo.Size()
	if before < 2*1024*1024 {
		t.Fatalf("test did not bloat the file: %d bytes", before)
	}
	_ = s.Close()

	// Reopen with a 1 MiB cap: reclaimBloat should VACUUM the bloated file.
	s2, err := OpenTuned(dir, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	afterInfo, err := os.Stat(s2.path)
	if err != nil {
		t.Fatal(err)
	}
	if afterInfo.Size() >= before/2 {
		t.Errorf("reclaimBloat did not shrink the DB: before=%d after=%d", before, afterInfo.Size())
	}
	if got := countEvents(t, s2); got != keepers {
		t.Errorf("VACUUM lost data: %d events, want %d", got, keepers)
	}
}

// itoa avoids strconv just to keep the test's imports minimal.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
