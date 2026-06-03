package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// cmdPruneDB deletes the oldest events from the sqlite store to reclaim space —
// by age (--keep-days), by row count (--keep-rows), or until the file is under a
// size budget (--max-mb). It dry-runs unless --yes is given, and VACUUMs so the
// freed pages are actually returned to the filesystem. Run it while the sensor
// is stopped (VACUUM needs exclusive access).
func cmdPruneDB(args []string) error {
	fs := flag.NewFlagSet("prune-db", flag.ContinueOnError)
	var f commonFlags
	f.register(fs, "/etc/tarpit-honeypot/config.yaml")
	dataDir := fs.String("data-dir", "", "data directory (overrides config; skips config loading)")
	keepDays := fs.Int("keep-days", 0, "delete events older than this many days")
	keepRows := fs.Int("keep-rows", 0, "keep only this many newest events, delete the rest")
	maxMB := fs.Int("max-mb", 0, "delete oldest events until the DB file is under this many MB")
	vacuum := fs.Bool("vacuum", true, "VACUUM after deleting to return freed space to the filesystem")
	yes := fs.Bool("yes", false, "actually delete (without this it is a dry-run)")
	fs.BoolVar(yes, "y", false, "alias for --yes")
	if err := parseOrUsage(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}

	modes := 0
	for _, on := range []bool{*keepDays > 0, *keepRows > 0, *maxMB > 0} {
		if on {
			modes++
		}
	}
	switch {
	case modes == 0:
		return fmt.Errorf("prune-db: choose one of --keep-days, --keep-rows, or --max-mb")
	case modes > 1:
		return fmt.Errorf("prune-db: --keep-days / --keep-rows / --max-mb are mutually exclusive")
	}

	dir, err := resolveDataDir(&f, *dataDir, "prune-db")
	if err != nil {
		return err
	}
	st, err := store.Open(dir, 0)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	db := st.DB()

	var total int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&total); err != nil {
		return fmt.Errorf("prune-db: count: %w", err)
	}
	sizeBefore := dbFootprint(st.Path())
	fmt.Printf("prune-db: %d event(s), DB %s\n", total, humanMB(sizeBefore))

	if *maxMB > 0 {
		return pruneToSize(ctx, st, int64(*maxMB)*1024*1024, *yes, total, sizeBefore)
	}

	// Resolve the delete predicate once, then count (dry-run) or delete with it.
	var where string
	var qargs []any
	if *keepDays > 0 {
		cutoff := time.Now().Add(-time.Duration(*keepDays) * 24 * time.Hour).UTC().UnixNano()
		where, qargs = "time < ?", []any{cutoff}
	} else { // keepRows
		where = "id IN (SELECT id FROM events ORDER BY time DESC LIMIT -1 OFFSET ?)"
		qargs = []any{*keepRows}
	}

	var willDelete int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE `+where, qargs...).Scan(&willDelete); err != nil {
		return fmt.Errorf("prune-db: count target: %w", err)
	}
	if !*yes {
		fmt.Printf("DRY RUN — would delete %d oldest event(s) (re-run with --yes to apply).\n", willDelete)
		return nil
	}
	res, err := db.ExecContext(ctx, `DELETE FROM events WHERE `+where, qargs...)
	if err != nil {
		return fmt.Errorf("prune-db: delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if *vacuum {
		if _, err := db.ExecContext(ctx, `VACUUM`); err != nil {
			return fmt.Errorf("prune-db: vacuum: %w", err)
		}
	}
	fmt.Printf("prune-db: deleted %d event(s); DB now %s (was %s)\n", n, humanMB(dbFootprint(st.Path())), humanMB(sizeBefore))
	return nil
}

// pruneToSize repeatedly drops the oldest ~10% of events and VACUUMs until the
// DB footprint is under target (or the store is empty).
func pruneToSize(ctx context.Context, st *store.Store, target int64, yes bool, total, sizeBefore int64) error {
	db := st.DB()
	if sizeBefore <= target {
		fmt.Printf("prune-db: DB %s already under %s; nothing to do.\n", humanMB(sizeBefore), humanMB(target))
		return nil
	}
	if !yes {
		est := total - int64(float64(total)*float64(target)/float64(sizeBefore))
		fmt.Printf("DRY RUN — DB %s exceeds %s; would delete ~%d oldest event(s) and VACUUM (re-run with --yes).\n",
			humanMB(sizeBefore), humanMB(target), est)
		return nil
	}
	var deleted int64
	for dbFootprint(st.Path()) > target {
		var cnt int64
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&cnt); err != nil {
			return fmt.Errorf("prune-db: count: %w", err)
		}
		if cnt == 0 {
			break
		}
		batch := cnt / 10
		if batch < 1000 {
			batch = 1000
		}
		res, err := db.ExecContext(ctx, `DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY time ASC LIMIT ?)`, batch)
		if err != nil {
			return fmt.Errorf("prune-db: delete batch: %w", err)
		}
		n, _ := res.RowsAffected()
		deleted += n
		// VACUUM each round so the on-disk size reflects the deletions for the
		// loop condition.
		if _, err := db.ExecContext(ctx, `VACUUM`); err != nil {
			return fmt.Errorf("prune-db: vacuum: %w", err)
		}
		if n == 0 {
			break
		}
	}
	fmt.Printf("prune-db: deleted %d event(s); DB now %s (target %s)\n", deleted, humanMB(dbFootprint(st.Path())), humanMB(target))
	return nil
}

// resolveDataDir returns the data directory from --data-dir, or from the loaded
// config, refusing obviously-unsafe roots.
func resolveDataDir(f *commonFlags, override, cmd string) (string, error) {
	dir := override
	if dir == "" {
		cfg, err := config.LoadManyWithOverrides(f.paths(), f.overrideSets())
		if err != nil {
			return "", fmt.Errorf("%s: %w (or pass --data-dir to skip config loading)", cmd, err)
		}
		dir = cfg.Sensor.DataDir
	}
	if dir == "" || dir == "/" {
		return "", fmt.Errorf("%s: refusing to operate on data_dir %q", cmd, dir)
	}
	return dir, nil
}

// dbFootprint is the on-disk size of the sqlite database including its WAL/SHM
// sidecars.
func dbFootprint(path string) int64 {
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Stat(path + suffix); err == nil {
			total += fi.Size()
		}
	}
	return total
}

func humanMB(b int64) string { return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024)) }
