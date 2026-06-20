package pgstore

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// migrationFS holds the ordered SQL migrations, embedded so they ship inside the
// binary — there is no external migration step to forget. Each file is named
// <version>_<name>.sql (e.g. 0001_init.sql); the leading integer is the version.
//
//go:embed migrations/*.sql
var migrationFS embed.FS

// migrateLockKey is the advisory-lock key held while migrating, so two
// aggregators starting against the same database don't apply migrations
// concurrently. The value is arbitrary but fixed across the fleet.
const migrateLockKey int64 = 0x7461727069745f6d // "tarpit_m"

// migrate applies every embedded migration not yet recorded in
// schema_migrations, in version order, each in its own transaction. It is safe
// to run on every start: already-applied versions are skipped.
//
// It uses a dedicated connection in pgx simple-query mode because a single
// migration file may contain several statements (the extended protocol the
// runtime pool uses rejects multi-statement queries).
func migrate(ctx context.Context, dsn string) error {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("pgstore: parse dsn for migrate: %w", err)
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	// The simple protocol does client-side parameter encoding and so requires a
	// UTF-8 client encoding; set it explicitly in case the server/DSN default
	// differs.
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	cfg.RuntimeParams["client_encoding"] = "UTF8"
	mdb := stdlib.OpenDB(*cfg)
	defer mdb.Close()
	conn, err := mdb.Conn(ctx)
	if err != nil {
		return fmt.Errorf("pgstore: migrate conn: %w", err)
	}
	defer conn.Close()

	// Serialize migrators across the fleet. The session lock is released by the
	// deferred unlock (and unconditionally when the connection closes).
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrateLockKey); err != nil {
		return fmt.Errorf("pgstore: advisory lock: %w", err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, migrateLockKey) }()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
  version bigint PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
)`); err != nil {
		return fmt.Errorf("pgstore: create schema_migrations: %w", err)
	}

	applied := map[int64]bool{}
	rows, err := conn.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("pgstore: read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("pgstore: scan migration version: %w", err)
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	migs, err := loadMigrations()
	if err != nil {
		return err
	}
	for _, m := range migs {
		if applied[m.version] {
			continue
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("pgstore: begin migration %d: %w", m.version, err)
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("pgstore: apply migration %s: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, m.version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("pgstore: record migration %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("pgstore: commit migration %d: %w", m.version, err)
		}
		slog.Info("pgstore: applied migration", "version", m.version, "name", m.name)
	}
	return nil
}

type migration struct {
	version int64
	name    string
	sql     string
}

// loadMigrations reads and version-sorts the embedded migration files. The
// version is the integer prefix before the first underscore in the filename.
func loadMigrations() ([]migration, error) {
	ents, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("pgstore: read migrations dir: %w", err)
	}
	var out []migration
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		us := strings.IndexByte(name, '_')
		if us <= 0 {
			return nil, fmt.Errorf("pgstore: migration %q must be <version>_<name>.sql", name)
		}
		v, err := strconv.ParseInt(name[:us], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("pgstore: migration %q has a non-numeric version: %w", name, err)
		}
		b, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: name, sql: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}
