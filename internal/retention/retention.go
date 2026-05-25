// Package retention prunes durable state older than a configured age.
// Runs as a single background goroutine spawned by the sensor, ticking
// every hour. Touches the JSONL events directory, the SQLite events
// table, and the captures directory.
package retention

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Runner holds the configured age cap + pointers to the on-disk locations
// we manage. Any nil/empty field is skipped.
type Runner struct {
	Days        int
	JSONLogDir  string
	CapturesDir string
	DB          *sql.DB
}

// Run starts the periodic prune. Returns when ctx is cancelled.
func (r *Runner) Run(ctx context.Context) {
	if r == nil || r.Days <= 0 {
		return
	}
	// Run once at startup so a freshly-started sensor with an old data
	// dir doesn't sit on stale events for an hour.
	r.tick(ctx)
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.tick(ctx)
		}
	}
}

func (r *Runner) tick(ctx context.Context) {
	cutoff := time.Now().Add(-time.Duration(r.Days) * 24 * time.Hour)
	jsonlogPruned := pruneDir(r.JSONLogDir, cutoff)
	capturePruned := pruneDir(r.CapturesDir, cutoff)
	dbPruned := pruneDB(ctx, r.DB, cutoff)
	iocPruned := pruneIOCs(ctx, r.DB, cutoff)
	if jsonlogPruned > 0 || capturePruned > 0 || dbPruned > 0 || iocPruned > 0 {
		slog.Info("retention prune",
			"jsonlog_files", jsonlogPruned,
			"capture_files", capturePruned,
			"db_rows", dbPruned,
			"ioc_rows", iocPruned,
			"cutoff", cutoff.Format(time.RFC3339),
		)
	}
}

// pruneDir deletes regular files under dir with mtime before cutoff. Returns
// the number of files removed. Errors are logged at warn level and don't
// abort the pass — partial progress is better than none.
func pruneDir(dir string, cutoff time.Time) int {
	if dir == "" {
		return 0
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("retention: readdir", "dir", dir, "err", err)
		}
		return 0
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
				removed++
			}
		}
	}
	return removed
}

// pruneDB deletes events older than cutoff. Returns the number of rows
// removed. SQLite is the only schema we know about today; callers pass
// the raw *sql.DB so we don't have to import store and create a cycle.
func pruneDB(ctx context.Context, db *sql.DB, cutoff time.Time) int64 {
	if db == nil {
		return 0
	}
	res, err := db.ExecContext(ctx, `DELETE FROM events WHERE time < ?`, cutoff.UTC().UnixNano())
	if err != nil {
		slog.Warn("retention: db delete", "err", err)
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

// pruneIOCs drops indicators not seen since the cutoff (an IOC kept fresh by
// continued sightings survives; one stale for the whole retention window is
// dropped). Keyed on last_seen, the same age basis as the event prune.
func pruneIOCs(ctx context.Context, db *sql.DB, cutoff time.Time) int64 {
	if db == nil {
		return 0
	}
	res, err := db.ExecContext(ctx, `DELETE FROM iocs WHERE last_seen < ?`, cutoff.UTC().UnixNano())
	if err != nil {
		slog.Warn("retention: ioc delete", "err", err)
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}
