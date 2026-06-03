// Package store wraps a SQLite event index. Both the SQLite sink and the
// web UI / list-events CLI talk to events through this package so the SQL
// dialect and schema stay in one place.
//
// The database file lives at <data_dir>/events.db. We use modernc.org/sqlite,
// a pure-Go port, so the binary stays CGO-free and statically linked.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/rom/tarpit-honeypot/internal/event"
)

type Store struct {
	db    *sql.DB
	path  string
	capMB int
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
  mitre_defenses TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(time DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_rule_id ON events(rule_id);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
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
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
`

// Open creates (if necessary) and opens the events database under dataDir.
// capMB is the soft cap on database size; when exceeded, the oldest events
// are pruned during the next Insert.
func Open(dataDir string, capMB int) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("store: mkdir %s: %w", dataDir, err)
	}
	path := filepath.Join(dataDir, "events.db")
	// _journal_mode=WAL gives us concurrent reads while the sink is writing.
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, openError("open", path, err)
	}
	db.SetMaxOpenConns(4)
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
	// The DB holds captured payloads, source IPs, and harvested
	// credentials — restrict it (and its WAL/SHM siblings, created by the
	// schema write above) to owner-only. Best-effort: a chmod failure
	// shouldn't stop the sensor from running.
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		_ = os.Chmod(p, 0o600)
	}
	return &Store{db: db, path: path, capMB: capMB}, nil
}

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
	// Index after the column exists (covers both fresh + migrated DBs).
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_sensor_id ON events(sensor_id)`); err != nil {
		return fmt.Errorf("store: index sensor_id: %w", err)
	}
	// ATT&CK / D3FEND attribution, persisted so /api/events + the UI carry the
	// same techniques/tactics/defenses the streaming sinks already get.
	for _, col := range []string{"mitre_techniques", "mitre_tactics", "mitre_defenses"} {
		if err := addColumn(db, "events", col, "TEXT"); err != nil {
			return err
		}
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
 mitre_techniques, mitre_tactics, mitre_defenses)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// eventCols flattens an event into the insertSQL bind parameters.
func eventCols(ev *event.Event) []any {
	return []any{
		ev.ID, ev.Time.UTC().UnixNano(), ev.Sensor, ev.SensorID, ev.RuleID, int(ev.Severity),
		ev.Source.IP, ev.Source.Port, ev.Dest.IP, ev.Dest.Port,
		ev.Proto, ev.Handler, ev.BannerSent, ev.PayloadBase64, ev.PayloadLen,
		jsonOrEmpty(ev.Meta), jsonOrEmpty(ev.Anomalies),
		jsonOrEmpty(ev.MitreTechniques), jsonOrEmpty(ev.MitreTactics), jsonOrEmpty(ev.MitreDefenses),
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
	if _, err := s.db.ExecContext(ctx, insertSQL, eventCols(ev)...); err != nil {
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
		if _, err := stmt.ExecContext(ctx, eventCols(ev)...); err != nil {
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

func (s *Store) maybePrune(ctx context.Context) {
	if s.capMB <= 0 {
		return
	}
	info, err := os.Stat(s.path)
	if err != nil {
		return
	}
	if info.Size() < int64(s.capMB)*1024*1024 {
		return
	}
	// Delete the oldest 10% of events.
	_, _ = s.db.ExecContext(ctx, `
DELETE FROM events WHERE id IN (
  SELECT id FROM events ORDER BY time ASC LIMIT (
    SELECT MAX(CAST(COUNT(*) * 0.1 AS INTEGER), 100) FROM events
  )
)`)
}

// Filter narrows what Query returns. Zero values mean "no constraint".
type Filter struct {
	Since       time.Time
	Until       time.Time
	SourceIP    string
	RuleID      string
	MinSeverity event.Severity
	// Proto restricts to a transport (tcp / udp / icmp / l2 / …); empty = any.
	Proto string
	// Handler restricts to events produced by a given protocol handler (the
	// "all attacks against this service" pivot off the summary). Empty = any.
	Handler string
	// DstPort restricts to a destination (listener) port; 0 = any.
	DstPort int
	// Country restricts to events whose GeoIP meta.geo_country matches (the
	// "attacks from this place" pivot off the source map). Empty = any.
	Country string
	// Text is a free-text substring matched (case-insensitively) against
	// the rule_id, banner_sent, and meta JSON — a full-text search over
	// what the attacker sent / what we captured.
	Text string
	// FPKind / FPValue restrict to events carrying a given network
	// fingerprint (FPKind is one of the allowlisted kinds — ja3, ja4, …).
	// An unknown FPKind matches nothing.
	FPKind  string
	FPValue string
	Limit   int
	Offset  int
}

func (s *Store) Query(ctx context.Context, f Filter) ([]*event.Event, error) {
	q := `SELECT id, time, sensor, sensor_id, rule_id, severity, src_ip, src_port,
                dst_ip, dst_port, proto, handler, banner_sent,
                payload_b64, payload_len, meta_json, anomalies,
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
		// json_valid guard: empty meta stores meta_json = '' which would make
		// json_extract raise "malformed JSON".
		q += " AND CASE WHEN json_valid(meta_json) THEN json_extract(meta_json, '$.geo_country') END = ?"
		args = append(args, f.Country)
	}
	if f.MinSeverity > 0 {
		q += " AND severity >= ?"
		args = append(args, int(f.MinSeverity))
	}
	if f.Text != "" {
		// Case-insensitive substring across rule_id / banner / meta JSON.
		// LOWER() on both sides makes it explicit and independent of the
		// SQLite case_sensitive_like pragma.
		like := "%" + strings.ToLower(f.Text) + "%"
		q += " AND (LOWER(rule_id) LIKE ? OR LOWER(banner_sent) LIKE ? OR LOWER(meta_json) LIKE ?)"
		args = append(args, like, like, like)
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
       dst_ip, dst_port, proto, handler, banner_sent,
       payload_b64, payload_len, meta_json, anomalies,
       mitre_techniques, mitre_tactics, mitre_defenses
FROM events WHERE id = ?`, id)
	return scanRow(row)
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

	return sum, nil
}
