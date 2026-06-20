// Package store wraps a SQLite event index. Both the SQLite sink and the
// web UI / list-events CLI talk to events through this package so the SQL
// dialect and schema stay in one place.
//
// The database file lives at <data_dir>/events.db. We use modernc.org/sqlite,
// a pure-Go port, so the binary stays CGO-free and statically linked.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"github.com/rom/tarpit-honeypot/internal/event"
)

type Store struct {
	db    *sql.DB
	path  string
	capMB int

	// bannerCache memoizes banner sha256 -> banners.id so a repeated static
	// banner (the overwhelmingly common case) is interned without a DB hit.
	bannerMu    sync.Mutex
	bannerCache map[string]int64

	// pruneTick gates the cap check so we don't os.Stat the DB file on every
	// single insert — only every prunePeriod writes.
	pruneTick atomic.Uint64
}

// rowQueryer is satisfied by both *sql.DB and *sql.Tx, so banner interning can
// run on the batch transaction (a separate write would deadlock on SQLite's
// single-writer lock) or standalone for single inserts.
type rowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// bannerSelect resolves an event's banner in a query: the inline banner_sent for
// legacy rows, else the interned text referenced by banner_id for new rows.
const bannerSelect = `CASE WHEN banner_sent != '' THEN banner_sent ` +
	`ELSE COALESCE((SELECT text FROM banners WHERE banners.id = events.banner_id), '') END`

// internBanner returns the banners.id for text (inserting it once), or 0 for an
// empty banner. The in-memory cache makes repeated banners free.
func (s *Store) internBanner(ctx context.Context, q rowQueryer, text string) (int64, error) {
	if text == "" {
		return 0, nil
	}
	sum := sha256.Sum256([]byte(text))
	h := hex.EncodeToString(sum[:])
	s.bannerMu.Lock()
	if id, ok := s.bannerCache[h]; ok {
		s.bannerMu.Unlock()
		return id, nil
	}
	s.bannerMu.Unlock()
	var id int64
	err := q.QueryRowContext(ctx, `INSERT INTO banners (hash, text) VALUES (?, ?)
ON CONFLICT(hash) DO UPDATE SET hash = hash
RETURNING id`, h, text).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: intern banner: %w", err)
	}
	s.bannerMu.Lock()
	if s.bannerCache == nil {
		s.bannerCache = map[string]int64{}
	}
	if len(s.bannerCache) < 8192 { // bound the cache; static banners are few
		s.bannerCache[h] = id
	}
	s.bannerMu.Unlock()
	return id, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  time INTEGER NOT NULL,
  sensor TEXT NOT NULL,
  sensor_id TEXT,
  rule_id TEXT NOT NULL,
  severity INTEGER NOT NULL,
  src_ip TEXT,
  src_port INTEGER,
  dst_ip TEXT,
  dst_port INTEGER,
  proto TEXT,
  handler TEXT,
  banner_sent TEXT,
  payload_b64 TEXT,
  payload_len INTEGER,
  meta_json TEXT,
  anomalies TEXT,
  mitre_techniques TEXT,
  mitre_tactics TEXT,
  mitre_defenses TEXT,
  banner_id INTEGER,
  country TEXT
);
-- Interned banner strings: the same static service banner is sent on every
-- connection, so instead of storing a full copy per event we store it once here
-- and reference it by id (events.banner_id). Legacy rows keep their inline
-- banner_sent; new rows leave banner_sent empty and point at a banners row.
CREATE TABLE IF NOT EXISTS banners (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hash TEXT UNIQUE NOT NULL,
  text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS iocs (
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  count INTEGER NOT NULL,
  severity INTEGER,
  last_rule TEXT,
  last_sensor TEXT,
  last_source TEXT,
  PRIMARY KEY (type, value)
);
`

// indexStmts are created best-effort AFTER the tables + column migrations, each
// in its own statement (see ensureIndexes). They are deliberately NOT part of
// the schema const: creating an index on an already-large events table is a
// one-time write that needs scratch space, and on a full or nearly-full disk
// that write fails. Folding it into the mandatory schema exec at Open would
// turn a slow page into a crash loop — the daemon couldn't start, so it could
// never prune the table back under its cap to recover. Run separately and
// non-fatally, a failed index just means the dependent page does a full scan
// (still bounded by its query deadline) until a later restart can build it.
var indexStmts = []string{
	`CREATE INDEX IF NOT EXISTS idx_events_time ON events(time DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)`,
	// Composite index for the per-source profile query (WHERE src_ip = ? AND
	// time >= ? ORDER BY time DESC): lets SQLite both filter and order from one
	// index, avoiding a transient sort entirely.
	`CREATE INDEX IF NOT EXISTS idx_events_src_ip_time ON events(src_ip, time DESC)`,
	// Covering index for the /profiles list rollup (SourceAggregates):
	// "WHERE time >= ? GROUP BY src_ip" with COUNT / MIN+MAX(time), MAX(severity),
	// COUNT(DISTINCT rule_id) and SUM(severity*severity). With every referenced
	// column in the index, SQLite groups by the leading src_ip and reads severity
	// + rule_id straight from the index — no per-row main-table lookup — which is
	// what keeps the profiles list from timing out as the table grows.
	`CREATE INDEX IF NOT EXISTS idx_events_src_agg ON events(src_ip, time, severity, rule_id)`,
	`CREATE INDEX IF NOT EXISTS idx_events_rule_id ON events(rule_id)`,
	`CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)`,
	// Composite (column, time) covering indexes for the dashboard's
	// "WHERE time >= ? GROUP BY <column>" summary passes. With the grouped
	// column leading and time second, SQLite groups + range-filters straight
	// from the index (no full-row reads, no temp sort), which is what keeps the
	// summary fast as the events table grows into the tens/hundreds of
	// thousands. (src_ip is already covered by idx_events_src_ip_time above.)
	`CREATE INDEX IF NOT EXISTS idx_events_severity_time ON events(severity, time)`,
	`CREATE INDEX IF NOT EXISTS idx_events_rule_id_time ON events(rule_id, time)`,
	`CREATE INDEX IF NOT EXISTS idx_events_proto_time ON events(proto, time)`,
	// Composite (handler, time) index for the per-service pages (DNS / web /
	// database), which filter "WHERE handler IN (…) AND time >= ? ORDER BY time
	// DESC". With handler leading and time second SQLite range-filters + orders
	// straight from the index instead of scanning every recent row and
	// discarding the non-matching handlers Go-side.
	`CREATE INDEX IF NOT EXISTS idx_events_handler_time ON events(handler, time DESC)`,
	// (dst_ip, time) index for the multi-IP pivots — list-events --target and the
	// /stats "targeted server IPs" breakdown filter "WHERE dst_ip = ? AND
	// time >= ?". Without it those scan every recent row on a multi-address
	// sensor, which is what timed those pages out.
	`CREATE INDEX IF NOT EXISTS idx_events_dst_ip_time ON events(dst_ip, time DESC)`,
	// (country, time) index for the geo pivots — /events?country=XX and the
	// dashboard's country rollup. country is materialized from meta.geo_country
	// (migrate adds it; ensureIndexes runs after) so these hit the index instead
	// of json_extract over every recent row.
	`CREATE INDEX IF NOT EXISTS idx_events_country_time ON events(country, time DESC)`,
	// sensor_id is added by migrate(); ensureIndexes runs after migrate so the
	// column exists by the time this runs.
	`CREATE INDEX IF NOT EXISTS idx_events_sensor_id ON events(sensor_id)`,
	`CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type)`,
}

// ensureIndexes creates the secondary indexes best-effort. A failure (most
// likely a full disk while building an index over a large table) is logged but
// never fatal: the sensor must still start so it keeps capturing and can prune
// the table back under its cap. Returns the number that failed.
func ensureIndexes(db *sql.DB) int {
	failed := 0
	for _, stmt := range indexStmts {
		if _, err := db.Exec(stmt); err != nil {
			failed++
			slog.Warn("store: could not create index (continuing without it; dependent pages will full-scan)",
				"stmt", stmt, "err", err)
		}
	}
	return failed
}

// indexName extracts the "idx_…" name from a CREATE INDEX statement.
func indexName(stmt string) string {
	const marker = "EXISTS "
	i := strings.Index(stmt, marker)
	if i < 0 {
		return ""
	}
	rest := stmt[i+len(marker):]
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		return rest[:j]
	}
	return rest
}

// MissingIndexes returns the names of expected secondary indexes that are not
// present in the database — e.g. one whose creation failed earlier because the
// disk was full. Empty slice = healthy. Surfaced on /health and used by the
// periodic self-heal (EnsureIndexes).
func (s *Store) MissingIndexes() []string {
	have := map[string]bool{}
	rows, err := s.db.Query(`SELECT name FROM sqlite_master WHERE type='index'`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			have[n] = true
		}
	}
	var missing []string
	for _, stmt := range indexStmts {
		if n := indexName(stmt); n != "" && !have[n] {
			missing = append(missing, n)
		}
	}
	return missing
}

// EnsureIndexes (re)creates any missing secondary index, best-effort. It is safe
// to call repeatedly (CREATE INDEX IF NOT EXISTS) and is invoked both at Open
// and periodically by the sensor, so an index that couldn't be built during a
// full-disk window is healed automatically once space frees up. Returns how
// many statements failed this pass.
func (s *Store) EnsureIndexes() int { return ensureIndexes(s.db) }

// Open creates (if necessary) and opens the events database under dataDir.
// capMB is the soft cap on database size; when exceeded, the oldest events
// are pruned during the next Insert.
func Open(dataDir string, capMB int) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("store: mkdir %s: %w", dataDir, err)
	}
	path := filepath.Join(dataDir, "events.db")
	// _journal_mode=WAL gives us concurrent reads while the sink is writing.
	// temp_store=MEMORY keeps SQLite's transient sort/GROUP-BY/materialisation
	// B-trees in RAM instead of a temp file: queries that sort by a different
	// column than they filter on (e.g. the per-source profile page, which
	// filters by src_ip then ORDER BY time) otherwise spill to an on-disk temp
	// file, and a locked-down runtime (systemd PrivateTmp/ProtectSystem, a
	// non-writable or missing TMPDIR) makes that open fail with CANTOPEN(14) —
	// surfacing as "unable to open database file (14)" on those pages only.
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=temp_store(MEMORY)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, openError("open", path, err)
	}
	// WAL mode allows many concurrent readers, so size the pool for the
	// dashboard's fan-out: every page auto-refreshes and most fire several
	// queries, so a pool of 4 lets a couple of heavy aggregate scans starve the
	// rest — light pages then queue past their own deadline and show the "taking
	// longer than usual" page even though they'd be instant. 12 read slots keep
	// concurrent views from blocking each other; the single writer (the sink)
	// still serializes via WAL + busy_timeout. Idle conns are kept warm so a
	// refresh storm doesn't pay reconnect cost.
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(12)
	db.SetConnMaxIdleTime(5 * time.Minute)
	// sql.Open is lazy — this is the first statement that actually opens the
	// file, so a CANTOPEN (error 14) surfaces here. openError names the path
	// and probes for the usual cause.
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, openError("schema", path, err)
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Secondary indexes are created here, separately and non-fatally: a full
	// disk while building an index over a large table must not stop the sensor
	// from starting (and thus from pruning back under its cap). See indexStmts.
	ensureIndexes(db)
	// The DB holds captured payloads, source IPs, and harvested
	// credentials — restrict it (and its WAL/SHM siblings, created by the
	// schema write above) to owner-only. Best-effort: a chmod failure
	// shouldn't stop the sensor from running.
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		_ = os.Chmod(p, 0o600)
	}
	// Proactively warn when the filesystem is nearly full: SQLite can't grow the
	// WAL/-shm on a full disk (the writes fail with disk I/O error / SHMMAP), so
	// surface it loudly while the operator can still act — before inserts start
	// failing and the table freezes.
	if free, ok := freeDiskBytes(filepath.Dir(path)); ok && free < lowDiskBytes {
		slog.Warn("store: low free disk space on the data filesystem — SQLite cannot grow once full",
			"path", path, "free_mb", free/(1024*1024),
			"hint", "lower sensor.disk.sqlite_mb below the partition's free space, or grow the partition")
	}
	st := &Store{db: db, path: path, capMB: capMB}
	// Fill the materialized country column for rows ingested before it existed,
	// off the startup path (chunked, best-effort). New rows already get it at
	// insert; this converges the index + rollup over history without blocking
	// Open or holding a long write lock against the sink.
	go st.backfillCountry(context.Background())
	return st, nil
}

// backfillCountry populates events.country from meta.geo_country for rows that
// predate the column, in small chunks with a yield between them so it never
// starves the sink's writes. Best-effort: any error (DB closing, locked, disk
// full) just stops it — new rows are already correct and a later restart
// resumes. COALESCE(...,”) guarantees every touched row becomes non-NULL, so
// rows whose meta merely mentions "geo_country" elsewhere can't loop forever.
func (s *Store) backfillCountry(ctx context.Context) {
	for {
		res, err := s.db.ExecContext(ctx, `
UPDATE events SET country = COALESCE(json_extract(meta_json, '$.geo_country'), '')
WHERE rowid IN (
  SELECT rowid FROM events
  WHERE country IS NULL AND json_valid(meta_json) AND meta_json LIKE '%geo_country%'
  LIMIT 2000
)`)
		if err != nil {
			slog.Debug("store: country backfill stopped", "err", err)
			return
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(50 * time.Millisecond): // yield the write lock to the sink
		}
	}
}

// lowDiskBytes is the free-space floor below which Open warns: a honeypot under
// load can burn through this quickly, and once the filesystem is full SQLite
// can no longer grow the WAL/-shm (writes fail with disk I/O error / SHMMAP).
const lowDiskBytes = 128 * 1024 * 1024 // 128 MiB

// openError wraps a database open/initialise failure with the file path and,
// where it can tell, the most likely cause. modernc's SQLITE_CANTOPEN bubbles
// up as a bare "unable to open database file (14)" — no filename, no reason —
// which is useless when you're staring at a honeypot that won't start. We probe
// the path ourselves: a missing or read-only parent directory, a path that is a
// directory, or a DB file owned by another user (created by root, now reopened
// as the service account) are the usual culprits.
func openError(stage, path string, err error) error {
	if hint := diagnosePath(path); hint != "" {
		return fmt.Errorf("store: %s: %s: %w (%s)", stage, path, err, hint)
	}
	return fmt.Errorf("store: %s: %s: %w", stage, path, err)
}

// diagnosePath returns a human-readable likely cause for a failure to open the
// SQLite file at path, or "" if nothing obvious stands out. It runs only on the
// error path, so the probe writes (a temp file in the dir) are acceptable.
func diagnosePath(path string) string {
	uid := strconv.Itoa(os.Getuid())
	dir := filepath.Dir(path)
	switch fi, err := os.Stat(dir); {
	case os.IsNotExist(err):
		return "parent directory " + dir + " does not exist"
	case err != nil:
		return "cannot stat parent directory " + dir + ": " + err.Error()
	case !fi.IsDir():
		return dir + " is not a directory"
	case !dirWritable(dir):
		return "directory " + dir + " is not writable by uid " + uid +
			" — SQLite needs to create the -wal/-shm sidecar files"
	}
	// A full (or nearly-full) filesystem is the usual cause of a "disk I/O
	// error" / SHMMAP at open: SQLite can't extend the -wal/-shm. The empty
	// temp-file probe above can still succeed on a full disk (it writes no
	// bytes), so check free space explicitly.
	if free, ok := freeDiskBytes(dir); ok && free < 1024*1024 {
		return "filesystem holding " + dir + " is full (only " +
			strconv.FormatInt(free/1024, 10) + " KiB free) — SQLite cannot grow the " +
			"-wal/-shm; free space (or lower sensor.disk.sqlite_mb) and restart"
	}
	if fi, err := os.Stat(path); err == nil {
		if fi.IsDir() {
			return path + " is a directory, not a database file"
		}
		if !fileWritable(path) {
			return "database file is not writable by uid " + uid +
				" — was it created by another user (e.g. root)? chown it to the service account"
		}
	}
	return ""
}

// dirWritable reports whether the current process can create a file in dir.
func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".tarpit-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// fileWritable reports whether the current process can open path for writing.
func fileWritable(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// migrate applies additive schema changes to a database created by an earlier
// release. ADD COLUMN is cheap and leaves the new column NULL for old rows.
func migrate(db *sql.DB) error {
	has, err := hasColumn(db, "events", "anomalies")
	if err != nil {
		return fmt.Errorf("store: inspect schema: %w", err)
	}
	if !has {
		if _, err := db.Exec(`ALTER TABLE events ADD COLUMN anomalies TEXT`); err != nil {
			return fmt.Errorf("store: add anomalies column: %w", err)
		}
	}
	hasSID, err := hasColumn(db, "events", "sensor_id")
	if err != nil {
		return fmt.Errorf("store: inspect schema: %w", err)
	}
	if !hasSID {
		if _, err := db.Exec(`ALTER TABLE events ADD COLUMN sensor_id TEXT`); err != nil {
			return fmt.Errorf("store: add sensor_id column: %w", err)
		}
	}
	// The idx_events_sensor_id index is created (best-effort) by ensureIndexes,
	// which Open runs right after migrate — once this column is guaranteed to
	// exist on both fresh and migrated databases.
	// ATT&CK / D3FEND attribution, persisted so /api/events + the UI carry the
	// same techniques/tactics/defenses the streaming sinks already get.
	for _, col := range []string{"mitre_techniques", "mitre_tactics", "mitre_defenses"} {
		if err := addColumn(db, "events", col, "TEXT"); err != nil {
			return err
		}
	}
	// Banner interning: a banner_id reference on events plus the banners table
	// (created here too, for DBs that predate it).
	if err := addColumn(db, "events", "banner_id", "INTEGER"); err != nil {
		return err
	}
	// Materialized geo country (from meta.geo_country) so the country= filter +
	// the dashboard country rollup hit an index instead of json_extract over
	// every row. Set at insert for new rows; backfilled for old ones off the
	// startup path (see backfillCountry).
	if err := addColumn(db, "events", "country", "TEXT"); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS banners (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hash TEXT UNIQUE NOT NULL,
  text TEXT NOT NULL
)`); err != nil {
		return fmt.Errorf("store: create banners: %w", err)
	}
	return nil
}

// addColumn adds a column to a table if a database from an earlier release
// doesn't already have it (fresh DBs get it from the schema const).
func addColumn(db *sql.DB, table, col, typ string) error {
	has, err := hasColumn(db, table, col)
	if err != nil {
		return fmt.Errorf("store: inspect %s.%s: %w", table, col, err)
	}
	if !has {
		if _, err := db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + col + ` ` + typ); err != nil {
			return fmt.Errorf("store: add %s.%s: %w", table, col, err)
		}
	}
	return nil
}

func hasColumn(db *sql.DB, table, col string) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid, notnull, pk int
			name, ctype      string
			dflt             any
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == col {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Path() string { return s.path }

// DB returns the underlying *sql.DB so the retention runner can issue
// DELETE statements without importing this package's full API. The
// retention package treats this strictly as a write target.
func (s *Store) DB() *sql.DB { return s.db }

// Insert persists an event. Errors that look transient (busy / locked) are
// returned so the caller's retry logic (or worker drop) can handle them.
const insertSQL = `
INSERT OR REPLACE INTO events
(id, time, sensor, sensor_id, rule_id, severity, src_ip, src_port, dst_ip, dst_port,
 proto, handler, banner_sent, payload_b64, payload_len, meta_json, anomalies,
 mitre_techniques, mitre_tactics, mitre_defenses, banner_id, country)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// eventCols flattens an event into the insertSQL bind parameters. bannerID is
// the interned banners.id (0 when none); the inline banner_sent column is left
// empty for new rows so the banner is stored only once in the banners table.
func eventCols(ev *event.Event, bannerID int64) []any {
	country, _ := ev.Meta["geo_country"].(string)
	return []any{
		ev.ID, ev.Time.UTC().UnixNano(), ev.Sensor, ev.SensorID, ev.RuleID, int(ev.Severity),
		ev.Source.IP, ev.Source.Port, ev.Dest.IP, ev.Dest.Port,
		ev.Proto, ev.Handler, "", ev.PayloadBase64, ev.PayloadLen,
		jsonOrEmpty(ev.Meta), jsonOrEmpty(ev.Anomalies),
		jsonOrEmpty(ev.MitreTechniques), jsonOrEmpty(ev.MitreTactics), jsonOrEmpty(ev.MitreDefenses),
		bannerID, country,
	}
}

// jsonOrEmpty marshals a non-empty slice/map to JSON, or returns "".
func jsonOrEmpty(v any) string {
	switch t := v.(type) {
	case []string:
		if len(t) == 0 {
			return ""
		}
	case map[string]any:
		if len(t) == 0 {
			return ""
		}
	case nil:
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func (s *Store) Insert(ctx context.Context, ev *event.Event) error {
	bid, err := s.internBanner(ctx, s.db, ev.BannerSent)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, insertSQL, eventCols(ev, bid)...); err != nil {
		return fmt.Errorf("store insert: %w", err)
	}
	s.maybePrune(ctx)
	return nil
}

// InsertBatch persists many events in one transaction — the throughput path for
// an aggregator ingesting from many sensors (sqlite per-row commits are slow;
// one prepared statement in one txn is far cheaper). Errors are returned so the
// caller can fall back to per-event inserts.
func (s *Store) InsertBatch(ctx context.Context, evs []*event.Event) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store batch: begin: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, insertSQL)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("store batch: prepare: %w", err)
	}
	for _, ev := range evs {
		// Intern on the same tx — a separate write connection would deadlock on
		// SQLite's single-writer lock while this tx is open.
		bid, err := s.internBanner(ctx, tx, ev.BannerSent)
		if err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return err
		}
		if _, err := stmt.ExecContext(ctx, eventCols(ev, bid)...); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return fmt.Errorf("store batch: exec: %w", err)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store batch: commit: %w", err)
	}
	s.maybePrune(ctx)
	return nil
}

// prunePeriod gates the cap check: stat the DB file (and possibly prune) once
// per this many writes rather than on every insert.
const prunePeriod = 256

func (s *Store) maybePrune(ctx context.Context) {
	if s.capMB <= 0 {
		return
	}
	// Only check periodically — os.Stat per insert is wasted syscalls under load.
	if s.pruneTick.Add(1)%prunePeriod != 0 {
		return
	}
	info, err := os.Stat(s.path)
	if err != nil {
		return
	}
	overCap := info.Size() >= int64(s.capMB)*1024*1024
	// Safety net: prune even when under the configured cap if the filesystem is
	// running low. A sqlite_mb cap larger than the partition's free space would
	// otherwise let the DB grow until the disk fills and SQLite can no longer
	// write (disk I/O error / SHMMAP) — the exact failure this guards against.
	lowDisk := false
	if free, ok := freeDiskBytes(filepath.Dir(s.path)); ok && free < lowDiskBytes {
		lowDisk = true
	}
	if !overCap && !lowDisk {
		return
	}
	if lowDisk && !overCap {
		slog.Warn("store: low free disk — pruning oldest events below the configured cap to keep writing",
			"path", s.path, "cap_mb", s.capMB)
	}
	// Delete the oldest 10% of events. Surface failures (disk full, locked,
	// corrupt index) so a silently-failing prune can't let the DB grow forever.
	if _, err := s.db.ExecContext(ctx, `
DELETE FROM events WHERE id IN (
  SELECT id FROM events ORDER BY time ASC LIMIT (
    SELECT MAX(CAST(COUNT(*) * 0.1 AS INTEGER), 100) FROM events
  )
)`); err != nil {
		slog.Warn("store: retention prune failed; cap enforcement paused", "err", err, "path", s.path)
		return
	}
	// Return the freed WAL space to the filesystem: a TRUNCATE checkpoint shrinks
	// the -wal file back (best-effort). The main DB file itself doesn't shrink —
	// SQLite reuses the freed pages for new rows — but this keeps the WAL from
	// holding space on a tight disk.
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		slog.Debug("store: wal checkpoint after prune failed", "err", err)
	}
}

// PruneBefore deletes events older than cutoff (by event time) and IOCs not
// seen since cutoff (by last_seen — the same age basis), returning the rows
// removed from each. It is the engine-neutral retention primitive the retention
// runner calls; the size-cap prune in maybePrune is a separate SQLite-file
// concern.
func (s *Store) PruneBefore(ctx context.Context, cutoff time.Time) (events, iocs int64, err error) {
	cut := cutoff.UTC().UnixNano()
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE time < ?`, cut)
	if err != nil {
		return 0, 0, fmt.Errorf("store: prune events: %w", err)
	}
	events, _ = res.RowsAffected()
	res, err = s.db.ExecContext(ctx, `DELETE FROM iocs WHERE last_seen < ?`, cut)
	if err != nil {
		return events, 0, fmt.Errorf("store: prune iocs: %w", err)
	}
	iocs, _ = res.RowsAffected()
	return events, iocs, nil
}

// Filter narrows what Query returns. Zero values mean "no constraint".
type Filter struct {
	Since    time.Time
	Until    time.Time
	SourceIP string
	// DstIP restricts to events whose destination (the host's server IP that
	// was hit) matches — the "which of my IPs did this target" pivot on a
	// multi-IP deployment. Empty = any.
	DstIP       string
	RuleID      string
	MinSeverity event.Severity
	// Proto restricts to a transport (tcp / udp / icmp / l2 / …); empty = any.
	Proto string
	// Handler restricts to events produced by a given protocol handler (the
	// "all attacks against this service" pivot off the summary). Empty = any.
	Handler string
	// Handlers restricts to events whose handler is one of the given set (an
	// "OR" pushdown for service pages whose category spans several handlers —
	// web = http/https/http2, database = mysql/postgres/…). Empty = any. When
	// both Handler and Handlers are set, both constraints apply.
	Handlers []string
	// DstPort restricts to a destination (listener) port; 0 = any.
	DstPort int
	// Country restricts to events whose GeoIP meta.geo_country matches (the
	// "attacks from this place" pivot off the source map). Empty = any.
	Country string
	// ASN restricts to events whose GeoIP meta.asn matches (the "attacks from
	// this network" pivot off the summary). 0 = any.
	ASN int
	// Text is a free-text substring matched (case-insensitively) against
	// the rule_id, banner_sent, and meta JSON — a full-text search over
	// what the attacker sent / what we captured.
	Text string
	// FPKind / FPValue restrict to events carrying a given network
	// fingerprint (FPKind is one of the allowlisted kinds — ja3, ja4, …).
	// An unknown FPKind matches nothing.
	FPKind  string
	FPValue string
	// --- Negated / multi-value filters --------------------------------------
	// These power the events-page negation ("everything except rule X") and the
	// charts include/exclude patterns. Each *include* list is OR-within-itself
	// and AND-across-dimensions: an event must match at least one value in every
	// non-empty include list. Each *exclude* list drops an event matching ANY of
	// its values (exclusion wins over inclusion). They compose with — and apply
	// on top of — the single-valued fields above.
	SourceIPs        []string
	ExcludeSourceIPs []string
	RuleIDs          []string
	ExcludeRuleIDs   []string
	ExcludeHandlers  []string // Handlers (above) is the matching include list
	Protos           []string
	ExcludeProtos    []string
	Countries        []string
	ExcludeCountries []string
	DstPorts         []int
	ExcludeDstPorts  []int
	ASNs             []int
	ExcludeASNs      []int
	// Free-text GeoIP / network dimensions filtered via json_extract over
	// meta_json (these have no dedicated column): geo_city, geo_country_name,
	// asn_org. Exact-match IN / NOT IN, powering the events + charts + stats
	// pivots off the city / country-name / network-org tables. Substring
	// SEARCH over the same fields is the /search page's Go-side job.
	Cities              []string
	ExcludeCities       []string
	CountryNames        []string
	ExcludeCountryNames []string
	ASNOrgs             []string
	ExcludeASNOrgs      []string
	// Regex switches the text-dimension matching from exact (= / IN / NOT IN) to
	// case-insensitive RE2 patterns (col REGEXP ?), applied per value to the
	// include/exclude lists above — src_ip, dst_ip, rule_id, proto, handler,
	// country, the geo_city / geo_country_name / asn_org meta dimensions, and the
	// free-text search (Text). Numeric dimensions (ports, ASN) are unaffected.
	// Drives the /events filter bar's optional regex mode; off by default so the
	// exact-match pivots/links the UI generates keep their precise semantics.
	Regex  bool
	Limit  int
	Offset int
	// NoPayload skips the captured payload + banner columns (the per-row banner
	// subquery and the base64 payload blob). Aggregation scans that only need
	// the metadata columns (the dashboard enrichment) set this to read far less.
	NoPayload bool
}

func (s *Store) Query(ctx context.Context, f Filter) ([]*event.Event, error) {
	bannerCol, payloadCol := bannerSelect+" AS banner_sent", "payload_b64"
	if f.NoPayload {
		bannerCol, payloadCol = "'' AS banner_sent", "'' AS payload_b64"
	}
	q := `SELECT id, time, sensor, sensor_id, rule_id, severity, src_ip, src_port,
                dst_ip, dst_port, proto, handler, ` + bannerCol + `,
                ` + payloadCol + `, payload_len, meta_json, anomalies,
                mitre_techniques, mitre_tactics, mitre_defenses
          FROM events WHERE 1=1`
	var args []any
	if !f.Since.IsZero() {
		q += " AND time >= ?"
		args = append(args, f.Since.UTC().UnixNano())
	}
	if !f.Until.IsZero() {
		q += " AND time <= ?"
		args = append(args, f.Until.UTC().UnixNano())
	}
	if f.SourceIP != "" {
		q += " AND src_ip = ?"
		args = append(args, f.SourceIP)
	}
	if f.DstIP != "" {
		q += " AND dst_ip = ?"
		args = append(args, f.DstIP)
	}
	if f.RuleID != "" {
		q += " AND rule_id = ?"
		args = append(args, f.RuleID)
	}
	if f.Proto != "" {
		q += " AND proto = ?"
		args = append(args, f.Proto)
	}
	if f.Handler != "" {
		q += " AND handler = ?"
		args = append(args, f.Handler)
	}
	if f.DstPort > 0 {
		q += " AND dst_port = ?"
		args = append(args, f.DstPort)
	}
	if f.Country != "" {
		// Materialized, indexed column (idx_events_country_time) — set at insert
		// from meta.geo_country and backfilled for old rows — so this is an index
		// lookup, not a json_extract over every row in the window.
		q += " AND country = ?"
		args = append(args, f.Country)
	}
	if f.ASN > 0 {
		// asn is stored as a JSON number; CAST so the comparison is integer.
		q += " AND CASE WHEN json_valid(meta_json) THEN CAST(json_extract(meta_json, '$.asn') AS INTEGER) END = ?"
		args = append(args, f.ASN)
	}
	if f.MinSeverity > 0 {
		q += " AND severity >= ?"
		args = append(args, int(f.MinSeverity))
	}
	if f.Text != "" {
		// Case-insensitive substring across every text-bearing column an
		// operator can see: identifiers, addresses, handler/proto, the banner,
		// the captured meta JSON, and the ATT&CK columns. LOWER() on both sides
		// makes it explicit and independent of the SQLite case_sensitive_like
		// pragma. (Payload bytes are base64 in the DB, so payload-content search
		// is done Go-side by the search page over the decoded bytes.)
		//
		// In regex mode the same columns are matched against the RE2 pattern
		// instead, so the /events search box behaves like the advanced-search
		// full-text field.
		if f.Regex {
			textCols := []string{"rule_id", bannerSelect, "meta_json", "src_ip", "dst_ip",
				"handler", "proto", "sensor", "anomalies", "mitre_techniques", "mitre_tactics"}
			parts := make([]string, len(textCols))
			for i, c := range textCols {
				parts[i] = c + " REGEXP ?"
			}
			q += " AND (" + strings.Join(parts, " OR ") + ")"
			for range textCols {
				args = append(args, "(?i)"+f.Text)
			}
		} else {
			like := "%" + strings.ToLower(f.Text) + "%"
			q += " AND (LOWER(rule_id) LIKE ? OR LOWER(" + bannerSelect + ") LIKE ? OR LOWER(meta_json) LIKE ?" +
				" OR LOWER(src_ip) LIKE ? OR LOWER(dst_ip) LIKE ? OR LOWER(handler) LIKE ?" +
				" OR LOWER(proto) LIKE ? OR LOWER(sensor) LIKE ? OR LOWER(anomalies) LIKE ?" +
				" OR LOWER(mitre_techniques) LIKE ? OR LOWER(mitre_tactics) LIKE ?)"
			args = append(args, like, like, like, like, like, like, like, like, like, like, like)
		}
	}
	if f.FPValue != "" {
		// The path is taken from the fixed allowlist map (never user input);
		// the value is bound as a parameter. An unknown kind matches nothing.
		if path := fingerprintPath(f.FPKind); path != "" {
			// json_valid guard: events with empty meta store meta_json = ''
			// and json_extract('', …) raises "malformed JSON".
			q += " AND CASE WHEN json_valid(meta_json) THEN json_extract(meta_json, '" + path + "') END = ?"
			args = append(args, f.FPValue)
		} else {
			q += " AND 0=1"
		}
	}
	// Multi-value include / exclude (events negation, charts include/exclude).
	// The column names are fixed literals; the values are always bound as
	// parameters, so this stays injection-safe.
	// In regex mode the include/exclude lists match each value as a
	// case-insensitive RE2 pattern (col REGEXP ?) instead of exact IN / NOT IN;
	// the patterns are bound as params, so this stays injection-safe.
	inStr := func(col string, vals []string) {
		if len(vals) == 0 {
			return
		}
		if f.Regex {
			q += " AND (" + regexpOr(col, len(vals)) + ")"
			for _, v := range vals {
				args = append(args, "(?i)"+v)
			}
			return
		}
		q += " AND " + col + " IN (" + strings.Repeat("?,", len(vals)-1) + "?)"
		for _, v := range vals {
			args = append(args, v)
		}
	}
	notInStr := func(col string, vals []string) {
		if len(vals) == 0 {
			return
		}
		if f.Regex {
			q += " AND NOT (" + regexpOr(col, len(vals)) + ")"
			for _, v := range vals {
				args = append(args, "(?i)"+v)
			}
			return
		}
		q += " AND " + col + " NOT IN (" + strings.Repeat("?,", len(vals)-1) + "?)"
		for _, v := range vals {
			args = append(args, v)
		}
	}
	inInt := func(col string, vals []int) {
		if len(vals) == 0 {
			return
		}
		q += " AND " + col + " IN (" + strings.Repeat("?,", len(vals)-1) + "?)"
		for _, v := range vals {
			args = append(args, v)
		}
	}
	notInInt := func(col string, vals []int) {
		if len(vals) == 0 {
			return
		}
		q += " AND " + col + " NOT IN (" + strings.Repeat("?,", len(vals)-1) + "?)"
		for _, v := range vals {
			args = append(args, v)
		}
	}
	inStr("src_ip", f.SourceIPs)
	notInStr("src_ip", f.ExcludeSourceIPs)
	inStr("rule_id", f.RuleIDs)
	notInStr("rule_id", f.ExcludeRuleIDs)
	inStr("handler", f.Handlers)
	notInStr("handler", f.ExcludeHandlers)
	inStr("proto", f.Protos)
	notInStr("proto", f.ExcludeProtos)
	inStr("country", f.Countries)
	notInStr("country", f.ExcludeCountries)
	inInt("dst_port", f.DstPorts)
	notInInt("dst_port", f.ExcludeDstPorts)
	// ASN is stored as a JSON number; CAST so the comparison is integer. The
	// exclusion deliberately keeps rows that carry no ASN (json_extract → NULL),
	// which a bare NOT IN would otherwise drop.
	if len(f.ASNs) > 0 || len(f.ExcludeASNs) > 0 {
		asnExpr := "CASE WHEN json_valid(meta_json) THEN CAST(json_extract(meta_json, '$.asn') AS INTEGER) END"
		if len(f.ASNs) > 0 {
			q += " AND " + asnExpr + " IN (" + strings.Repeat("?,", len(f.ASNs)-1) + "?)"
			for _, v := range f.ASNs {
				args = append(args, v)
			}
		}
		if len(f.ExcludeASNs) > 0 {
			q += " AND (" + asnExpr + " IS NULL OR " + asnExpr + " NOT IN (" + strings.Repeat("?,", len(f.ExcludeASNs)-1) + "?))"
			for _, v := range f.ExcludeASNs {
				args = append(args, v)
			}
		}
	}
	// Allowlisted free-text meta dimensions (geo city / country name / ASN org)
	// filtered via json_extract. The paths are fixed literals (never operator
	// input); the values are always bound as parameters, so this is injection-
	// safe. Exclusion keeps rows that carry no value (json_extract → NULL),
	// matching the ASN behaviour above.
	for _, mf := range []struct {
		path  string
		in    []string
		notIn []string
	}{
		{"$.geo_city", f.Cities, f.ExcludeCities},
		{"$.geo_country_name", f.CountryNames, f.ExcludeCountryNames},
		{"$.asn_org", f.ASNOrgs, f.ExcludeASNOrgs},
	} {
		if len(mf.in) == 0 && len(mf.notIn) == 0 {
			continue
		}
		expr := "CASE WHEN json_valid(meta_json) THEN json_extract(meta_json, '" + mf.path + "') END"
		if len(mf.in) > 0 {
			if f.Regex {
				q += " AND (" + regexpOr(expr, len(mf.in)) + ")"
				for _, v := range mf.in {
					args = append(args, "(?i)"+v)
				}
			} else {
				q += " AND " + expr + " IN (" + strings.Repeat("?,", len(mf.in)-1) + "?)"
				for _, v := range mf.in {
					args = append(args, v)
				}
			}
		}
		if len(mf.notIn) > 0 {
			if f.Regex {
				q += " AND (" + expr + " IS NULL OR NOT (" + regexpOr(expr, len(mf.notIn)) + "))"
				for _, v := range mf.notIn {
					args = append(args, "(?i)"+v)
				}
			} else {
				q += " AND (" + expr + " IS NULL OR " + expr + " NOT IN (" + strings.Repeat("?,", len(mf.notIn)-1) + "?))"
				for _, v := range mf.notIn {
					args = append(args, v)
				}
			}
		}
	}
	q += " ORDER BY time DESC"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
		if f.Offset > 0 {
			q += " OFFSET ?"
			args = append(args, f.Offset)
		}
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*event.Event
	for rows.Next() {
		ev, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *Store) Get(ctx context.Context, id string) (*event.Event, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, time, sensor, sensor_id, rule_id, severity, src_ip, src_port,
       dst_ip, dst_port, proto, handler, `+bannerSelect+` AS banner_sent,
       payload_b64, payload_len, meta_json, anomalies,
       mitre_techniques, mitre_tactics, mitre_defenses
FROM events WHERE id = ?`, id)
	return scanRow(row)
}

// EventNeighbors locate the chronologically adjacent events in a conversation —
// everything exchanged between the same two peers (src_ip ↔ dst_ip) — for the
// event detail page's prev/next navigation.
type EventNeighbors struct {
	PrevID string // event just before the anchor in (time, id) order, "" if none
	NextID string // event just after, "" if none
	Total  int    // events in the conversation
	Pos    int    // 1-based position of the anchor within the conversation
}

// ConversationNav finds the previous/next events between ev's two peers
// (src_ip + dst_ip), ordered by (time, id), plus the conversation size and ev's
// position in it. A peer with an empty IP yields an empty (Total 0) result.
func (s *Store) ConversationNav(ctx context.Context, ev *event.Event) (EventNeighbors, error) {
	var nb EventNeighbors
	if ev == nil || ev.Source.IP == "" || ev.Dest.IP == "" {
		return nb, nil
	}
	src, dst, t := ev.Source.IP, ev.Dest.IP, ev.Time.UTC().UnixNano()

	// Previous: latest event strictly before the anchor in (time, id) order.
	err := s.db.QueryRowContext(ctx, `
SELECT id FROM events
WHERE src_ip = ? AND dst_ip = ? AND (time < ? OR (time = ? AND id < ?))
ORDER BY time DESC, id DESC LIMIT 1`, src, dst, t, t, ev.ID).Scan(&nb.PrevID)
	if err != nil && err != sql.ErrNoRows {
		return nb, err
	}
	// Next: earliest event strictly after the anchor.
	err = s.db.QueryRowContext(ctx, `
SELECT id FROM events
WHERE src_ip = ? AND dst_ip = ? AND (time > ? OR (time = ? AND id > ?))
ORDER BY time ASC, id ASC LIMIT 1`, src, dst, t, t, ev.ID).Scan(&nb.NextID)
	if err != nil && err != sql.ErrNoRows {
		return nb, err
	}
	// Total + the anchor's 1-based position (a friendly "n of m" context).
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events WHERE src_ip = ? AND dst_ip = ?`, src, dst).Scan(&nb.Total); err != nil {
		return nb, err
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events WHERE src_ip = ? AND dst_ip = ? AND (time < ? OR (time = ? AND id <= ?))`,
		src, dst, t, t, ev.ID).Scan(&nb.Pos); err != nil {
		return nb, err
	}
	return nb, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRow(r rowScanner) (*event.Event, error) {
	var (
		id, sensor, ruleID, srcIP, dstIP, proto, handler, banner, payloadB64, metaJSON string
		sensorID, anomaliesJSON                                                        sql.NullString
		techJSON, tacJSON, defJSON                                                     sql.NullString
		timeNS                                                                         int64
		sev, srcPort, dstPort, payloadLen                                              int
	)
	if err := r.Scan(&id, &timeNS, &sensor, &sensorID, &ruleID, &sev,
		&srcIP, &srcPort, &dstIP, &dstPort,
		&proto, &handler, &banner, &payloadB64, &payloadLen, &metaJSON, &anomaliesJSON,
		&techJSON, &tacJSON, &defJSON); err != nil {
		return nil, err
	}
	ev := &event.Event{
		ID:            id,
		Time:          time.Unix(0, timeNS).UTC(),
		Sensor:        sensor,
		SensorID:      sensorID.String,
		RuleID:        ruleID,
		Severity:      event.Severity(sev),
		Source:        event.Endpoint{IP: srcIP, Port: srcPort},
		Dest:          event.Endpoint{IP: dstIP, Port: dstPort},
		Proto:         proto,
		Handler:       handler,
		BannerSent:    banner,
		PayloadBase64: payloadB64,
		PayloadLen:    payloadLen,
	}
	if metaJSON != "" {
		_ = json.Unmarshal([]byte(metaJSON), &ev.Meta)
	}
	if anomaliesJSON.Valid && anomaliesJSON.String != "" {
		_ = json.Unmarshal([]byte(anomaliesJSON.String), &ev.Anomalies)
	}
	if techJSON.Valid && techJSON.String != "" {
		_ = json.Unmarshal([]byte(techJSON.String), &ev.MitreTechniques)
	}
	if tacJSON.Valid && tacJSON.String != "" {
		_ = json.Unmarshal([]byte(tacJSON.String), &ev.MitreTactics)
	}
	if defJSON.Valid && defJSON.String != "" {
		_ = json.Unmarshal([]byte(defJSON.String), &ev.MitreDefenses)
	}
	return ev, nil
}

// Summary is a small dashboard payload for the UI's index page.
type Summary struct {
	Since      time.Time      `json:"since"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByRule     map[string]int `json:"by_rule"`
	ByProto    map[string]int `json:"by_proto"` // tcp / udp / icmp / device / ...
	// ByHandler / ByTarget / ByCountry are index-backed top-N rollups (handler,
	// dst_ip, country) — single-valued, indexed dimensions the dashboard used to
	// count Go-side over a sampled event scan. Computed via GROUP BY so they're
	// full-window accurate and cost nothing per row beyond the covering-index walk.
	ByHandler  map[string]int `json:"by_handler"`
	ByTarget   map[string]int `json:"by_target"`
	ByCountry  map[string]int `json:"by_country"`
	TopSources []SourceCount  `json:"top_sources"`
}

type SourceCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// SourceAggregate is a cheap per-source rollup (one GROUP BY pass) that
// powers the attacker-profiles list. The rich per-actor dossier (tools,
// fingerprints, credentials, ATT&CK) is built separately by scanning that
// source's events.
type SourceAggregate struct {
	IP            string         `json:"ip"`
	Count         int            `json:"events"`
	FirstSeen     time.Time      `json:"first_seen"`
	LastSeen      time.Time      `json:"last_seen"`
	MaxSeverity   event.Severity `json:"max_severity"`
	DistinctRules int            `json:"distinct_rules"`
	Weight        int            `json:"threat_score"` // SUM(severity^2) — weights criticals
}

// SourceAggregates returns per-source rollups for events since the given
// time, ordered by severity-weighted threat score (most dangerous first).
func (s *Store) SourceAggregates(ctx context.Context, since time.Time, limit int) ([]SourceAggregate, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT src_ip, COUNT(*) c, MIN(time) mn, MAX(time) mx, MAX(severity) ms,
       COUNT(DISTINCT rule_id) dr, SUM(severity*severity) w
FROM events
WHERE time >= ? AND src_ip <> ''
GROUP BY src_ip
ORDER BY w DESC, c DESC
LIMIT ?`, since.UTC().UnixNano(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SourceAggregate
	for rows.Next() {
		var (
			a      SourceAggregate
			mn, mx int64
			ms     int
		)
		if err := rows.Scan(&a.IP, &a.Count, &mn, &mx, &ms, &a.DistinctRules, &a.Weight); err != nil {
			return nil, err
		}
		a.FirstSeen = time.Unix(0, mn).UTC()
		a.LastSeen = time.Unix(0, mx).UTC()
		a.MaxSeverity = event.Severity(ms)
		out = append(out, a)
	}
	return out, rows.Err()
}

// HourBucket is one hour of the events-over-time histogram.
type HourBucket struct {
	Hour  time.Time `json:"hour"`
	Count int       `json:"count"`
}

// EventsPerHour returns hourly event counts from since to now, with empty
// hours zero-filled, for the dashboard trend chart.
func (s *Store) EventsPerHour(ctx context.Context, since time.Time) ([]HourBucket, error) {
	return s.EventsPerBucket(ctx, since, time.Hour)
}

// EventsPerBucket is EventsPerHour generalized to an arbitrary bucket width, so
// the summary trend can show 24h (1h buckets) up to 31d (1d buckets) without a
// thousand bars. Empty buckets are zero-filled; Hour holds each bucket's start.
func (s *Store) EventsPerBucket(ctx context.Context, since time.Time, bucket time.Duration) ([]HourBucket, error) {
	hourNS := int64(bucket / time.Nanosecond)
	if hourNS <= 0 {
		hourNS = int64(time.Hour)
	}
	startBucket := since.UTC().UnixNano() / hourNS
	nowBucket := time.Now().UTC().UnixNano() / hourNS
	counts := map[int64]int{}
	rows, err := s.db.QueryContext(ctx,
		`SELECT time/?, COUNT(*) FROM events WHERE time >= ? GROUP BY time/?`,
		hourNS, since.UTC().UnixNano(), hourNS)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var b int64
		var c int
		if err := rows.Scan(&b, &c); err != nil {
			rows.Close()
			return nil, err
		}
		counts[b] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]HourBucket, 0, nowBucket-startBucket+1)
	for b := startBucket; b <= nowBucket; b++ {
		out = append(out, HourBucket{Hour: time.Unix(0, b*hourNS).UTC(), Count: counts[b]})
	}
	return out, nil
}

// Heartbeat returns a cheap freshness signal — the total event count and the
// latest event's timestamp — so the UI can decide whether a page actually
// needs re-rendering (skip the refresh when neither changed).
func (s *Store) Heartbeat(ctx context.Context) (count int64, latest time.Time, err error) {
	var ns sql.NullInt64
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*), MAX(time) FROM events`).Scan(&count, &ns); err != nil {
		return 0, time.Time{}, err
	}
	if ns.Valid {
		latest = time.Unix(0, ns.Int64).UTC()
	}
	return count, latest, nil
}

// OldestEventTime returns the timestamp of the earliest event still in the
// database (zero time when empty) — the retention horizon shown on the config
// page. Counts/Stats also expose totals; this is the "oldest entry" marker.
func (s *Store) OldestEventTime(ctx context.Context) (time.Time, error) {
	var ns sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MIN(time) FROM events`).Scan(&ns); err != nil {
		return time.Time{}, err
	}
	if !ns.Valid || ns.Int64 == 0 {
		return time.Time{}, nil
	}
	return time.Unix(0, ns.Int64).UTC(), nil
}

func (s *Store) Summary(ctx context.Context, since time.Time) (Summary, error) {
	sum := Summary{Since: since, BySeverity: map[string]int{}, ByRule: map[string]int{}, ByProto: map[string]int{}}
	sinceNS := since.UTC().UnixNano()

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE time >= ?`, sinceNS).Scan(&sum.Total); err != nil {
		return sum, err
	}

	rows, err := s.db.QueryContext(ctx, `SELECT severity, COUNT(*) FROM events WHERE time >= ? GROUP BY severity`, sinceNS)
	if err != nil {
		return sum, err
	}
	for rows.Next() {
		var sev, c int
		if err := rows.Scan(&sev, &c); err != nil {
			rows.Close()
			return sum, err
		}
		sum.BySeverity[event.Severity(sev).String()] = c
	}
	rows.Close()

	rows, err = s.db.QueryContext(ctx, `SELECT rule_id, COUNT(*) c FROM events WHERE time >= ? GROUP BY rule_id ORDER BY c DESC LIMIT 20`, sinceNS)
	if err != nil {
		return sum, err
	}
	for rows.Next() {
		var rid string
		var c int
		if err := rows.Scan(&rid, &c); err != nil {
			rows.Close()
			return sum, err
		}
		sum.ByRule[rid] = c
	}
	rows.Close()

	rows, err = s.db.QueryContext(ctx, `SELECT proto, COUNT(*) FROM events WHERE time >= ? AND proto != '' GROUP BY proto`, sinceNS)
	if err != nil {
		return sum, err
	}
	for rows.Next() {
		var proto string
		var c int
		if err := rows.Scan(&proto, &c); err != nil {
			rows.Close()
			return sum, err
		}
		sum.ByProto[proto] = c
	}
	rows.Close()

	rows, err = s.db.QueryContext(ctx, `SELECT src_ip, COUNT(*) c FROM events WHERE time >= ? AND src_ip != '' GROUP BY src_ip ORDER BY c DESC LIMIT 10`, sinceNS)
	if err != nil {
		return sum, err
	}
	for rows.Next() {
		var ip string
		var c int
		if err := rows.Scan(&ip, &c); err != nil {
			rows.Close()
			return sum, err
		}
		sum.TopSources = append(sum.TopSources, SourceCount{IP: ip, Count: c})
	}
	rows.Close()

	// Indexed single-valued dimensions via GROUP BY (covering indexes
	// idx_events_handler_time / idx_events_dst_ip_time) — full-window accurate and
	// cheap, replacing the dashboard's Go-side counting over a sampled scan.
	if sum.ByHandler, err = s.groupCount(ctx, "handler", sinceNS, 50); err != nil {
		return sum, err
	}
	if sum.ByTarget, err = s.groupCount(ctx, "dst_ip", sinceNS, 50); err != nil {
		return sum, err
	}
	if sum.ByCountry, err = s.groupCount(ctx, "country", sinceNS, 30); err != nil {
		return sum, err
	}

	return sum, nil
}

// groupCount runs a top-N rollup — SELECT <col>, COUNT(*) c FROM events WHERE
// time >= ? AND <col> != ” GROUP BY <col> ORDER BY c DESC LIMIT ? — into a
// label->count map. col MUST be a trusted column literal (never user input);
// callers pass fixed names ("handler", "dst_ip") whose (col, time) covering
// index lets SQLite group + count straight from the index.
func (s *Store) groupCount(ctx context.Context, col string, sinceNS int64, limit int) (map[string]int, error) {
	out := map[string]int{}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+col+`, COUNT(*) c FROM events WHERE time >= ? AND `+col+` != '' GROUP BY `+col+` ORDER BY c DESC LIMIT ?`,
		sinceNS, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var c int
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		out[k] = c
	}
	return out, rows.Err()
}
