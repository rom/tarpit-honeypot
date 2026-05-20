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
  meta_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(time DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_rule_id ON events(rule_id);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
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
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
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

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Path() string { return s.path }

// DB returns the underlying *sql.DB so the retention runner can issue
// DELETE statements without importing this package's full API. The
// retention package treats this strictly as a write target.
func (s *Store) DB() *sql.DB { return s.db }

// Insert persists an event. Errors that look transient (busy / locked) are
// returned so the caller's retry logic (or worker drop) can handle them.
func (s *Store) Insert(ctx context.Context, ev *event.Event) error {
	metaJSON := ""
	if len(ev.Meta) > 0 {
		b, err := json.Marshal(ev.Meta)
		if err == nil {
			metaJSON = string(b)
		}
	}
	_, err := s.db.ExecContext(ctx, `
INSERT OR REPLACE INTO events
(id, time, sensor, rule_id, severity, src_ip, src_port, dst_ip, dst_port,
 proto, handler, banner_sent, payload_b64, payload_len, meta_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.ID, ev.Time.UTC().UnixNano(), ev.Sensor, ev.RuleID, int(ev.Severity),
		ev.Source.IP, ev.Source.Port, ev.Dest.IP, ev.Dest.Port,
		ev.Proto, ev.Handler, ev.BannerSent, ev.PayloadBase64, ev.PayloadLen,
		metaJSON,
	)
	if err != nil {
		return fmt.Errorf("store insert: %w", err)
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
	Limit       int
	Offset      int
}

func (s *Store) Query(ctx context.Context, f Filter) ([]*event.Event, error) {
	q := `SELECT id, time, sensor, rule_id, severity, src_ip, src_port,
                dst_ip, dst_port, proto, handler, banner_sent,
                payload_b64, payload_len, meta_json
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
	if f.MinSeverity > 0 {
		q += " AND severity >= ?"
		args = append(args, int(f.MinSeverity))
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
SELECT id, time, sensor, rule_id, severity, src_ip, src_port,
       dst_ip, dst_port, proto, handler, banner_sent,
       payload_b64, payload_len, meta_json
FROM events WHERE id = ?`, id)
	return scanRow(row)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRow(r rowScanner) (*event.Event, error) {
	var (
		id, sensor, ruleID, srcIP, dstIP, proto, handler, banner, payloadB64, metaJSON string
		timeNS                                                                         int64
		sev, srcPort, dstPort, payloadLen                                              int
	)
	if err := r.Scan(&id, &timeNS, &sensor, &ruleID, &sev,
		&srcIP, &srcPort, &dstIP, &dstPort,
		&proto, &handler, &banner, &payloadB64, &payloadLen, &metaJSON); err != nil {
		return nil, err
	}
	ev := &event.Event{
		ID:            id,
		Time:          time.Unix(0, timeNS).UTC(),
		Sensor:        sensor,
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
	return ev, nil
}

// Summary is a small dashboard payload for the UI's index page.
type Summary struct {
	Since      time.Time      `json:"since"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByRule     map[string]int `json:"by_rule"`
	TopSources []SourceCount  `json:"top_sources"`
}

type SourceCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

func (s *Store) Summary(ctx context.Context, since time.Time) (Summary, error) {
	sum := Summary{Since: since, BySeverity: map[string]int{}, ByRule: map[string]int{}}
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
