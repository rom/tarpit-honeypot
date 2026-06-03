package cli

import (
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/store"
)

// cmdRotateDB writes a compressed, point-in-time copy of the event database to
// an archive (a consistent `VACUUM INTO` snapshot, gzip-compressed) so the
// current logs can be kept off-box before reclaiming space. With --reset --yes
// it then empties the live event table and VACUUMs, so the sensor continues
// with a fresh, small database — classic log rotation. Stop the sensor before
// using --reset.
func cmdRotateDB(args []string) error {
	fs := flag.NewFlagSet("rotate-db", flag.ContinueOnError)
	var f commonFlags
	f.register(fs, "/etc/tarpit-honeypot/config.yaml")
	dataDir := fs.String("data-dir", "", "data directory (overrides config; skips config loading)")
	out := fs.String("out", "", "archive path (default: <data_dir>/events-<UTC timestamp>.db.gz)")
	reset := fs.Bool("reset", false, "after archiving, empty the live event store and VACUUM (start fresh)")
	yes := fs.Bool("yes", false, "required with --reset to actually empty the live store")
	fs.BoolVar(yes, "y", false, "alias for --yes")
	if err := parseOrUsage(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}

	dir, err := resolveDataDir(&f, *dataDir, "rotate-db")
	if err != nil {
		return err
	}
	st, err := store.Open(dir, 0)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	db := st.DB()

	var count int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&count); err != nil {
		return fmt.Errorf("rotate-db: count: %w", err)
	}

	archive := *out
	if archive == "" {
		archive = filepath.Join(dir, "events-"+time.Now().UTC().Format("20060102T150405Z")+".db.gz")
	}
	if _, err := os.Stat(archive); err == nil {
		return fmt.Errorf("rotate-db: archive %s already exists", archive)
	}

	// VACUUM INTO writes a consistent, compacted single-file copy even under WAL,
	// so we needn't copy the -wal/-shm sidecars or stop writers to snapshot.
	tmp := archive + ".tmp.db"
	_ = os.Remove(tmp)
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, tmp); err != nil {
		return fmt.Errorf("rotate-db: snapshot: %w", err)
	}
	defer os.Remove(tmp)
	if err := gzipFile(tmp, archive); err != nil {
		return fmt.Errorf("rotate-db: compress: %w", err)
	}
	fmt.Printf("rotate-db: archived %d event(s) → %s (%s)\n", count, archive, humanMB(dbFootprint(archive)))

	if !*reset {
		fmt.Println("rotate-db: live store left intact (pass --reset --yes to start fresh).")
		return nil
	}
	if !*yes {
		fmt.Println("rotate-db: --reset requires --yes; live store NOT emptied (dry-run).")
		return nil
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM events`); err != nil {
		return fmt.Errorf("rotate-db: reset: %w", err)
	}
	if _, err := db.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("rotate-db: vacuum: %w", err)
	}
	fmt.Printf("rotate-db: live event store emptied and compacted (now %s). Archive kept at %s\n",
		humanMB(dbFootprint(st.Path())), archive)
	return nil
}

// gzipFile gzip-compresses src into dst (which must not already exist).
func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(out)
	zw.Name = filepath.Base(strings.TrimSuffix(dst, ".gz"))
	if _, err := io.Copy(zw, in); err != nil {
		zw.Close()
		out.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
