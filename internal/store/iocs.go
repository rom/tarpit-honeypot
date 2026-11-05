package store

import (
	"context"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// IOCRow is one de-duplicated indicator the sensor has observed.
type IOCRow struct {
	Type       string         `json:"type"`
	Value      string         `json:"value"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	Count      int            `json:"count"`
	Severity   event.Severity `json:"severity"`
	LastRule   string         `json:"last_rule"`
	LastSensor string         `json:"last_sensor"`
	LastSource string         `json:"last_source"`
}

// IOCFilter narrows QueryIOCs. Zero values mean "no constraint".
type IOCFilter struct {
	Type  string    // exact indicator type
	Since time.Time // last_seen >= this
	Text  string    // case-insensitive substring on value
	Limit int
}

// IOCUpsert is one indicator sighting for the batched UpsertIOCs path.
type IOCUpsert struct {
	Type, Value, RuleID, Sensor, Source string
	Severity                            event.Severity
	Time                                time.Time
}

// UpsertIOC records one indicator sighting and reports whether it was the first
// time this (type, value) was seen. The source/rule/sensor/severity reflect the
// triggering event; count and last_seen advance on every sighting.
func (s *Store) UpsertIOC(ctx context.Context, typ, value, ruleID, sensor, source string, sev event.Severity, t time.Time) (bool, error) {
	ns := t.UTC().UnixNano()
	var count int
	err := s.db.QueryRowContext(ctx, `
INSERT INTO iocs (type, value, first_seen, last_seen, count, severity, last_rule, last_sensor, last_source)
VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)
ON CONFLICT(type, value) DO UPDATE SET
  last_seen   = excluded.last_seen,
  count       = count + 1,
  severity    = MAX(severity, excluded.severity),
  last_rule   = excluded.last_rule,
  last_sensor = excluded.last_sensor,
  last_source = excluded.last_source
RETURNING count`,
		typ, value, ns, ns, int(sev), ruleID, sensor, source).Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 1, nil
}

// UpsertIOCs records a batch of indicator sightings in ONE transaction and
// returns, per row in order, whether that sighting was the first. Batching
// collapses what were N single-row INSERT…ON CONFLICT writes — each otherwise
// competing with the async event sink for SQLite's single writer lock — into one
// lock acquisition + commit, so the sensor's IOC writer no longer contends per
// indicator. A duplicate (type,value) within the same batch resolves correctly:
// the first row reports first-seen, later ones don't. Empty batch is a no-op.
func (s *Store) UpsertIOCs(ctx context.Context, batch []IOCUpsert) ([]bool, error) {
	if len(batch) == 0 {
		return nil, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO iocs (type, value, first_seen, last_seen, count, severity, last_rule, last_sensor, last_source)
VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)
ON CONFLICT(type, value) DO UPDATE SET
  last_seen   = excluded.last_seen,
  count       = count + 1,
  severity    = MAX(severity, excluded.severity),
  last_rule   = excluded.last_rule,
  last_sensor = excluded.last_sensor,
  last_source = excluded.last_source
RETURNING count`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = stmt.Close() }()
	out := make([]bool, len(batch))
	for i, u := range batch {
		ns := u.Time.UTC().UnixNano()
		var count int
		if err := stmt.QueryRowContext(ctx, u.Type, u.Value, ns, ns, int(u.Severity), u.RuleID, u.Sensor, u.Source).Scan(&count); err != nil {
			return nil, err
		}
		out[i] = count == 1
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

// QueryIOCs returns indicators matching the filter, newest sighting first.
func (s *Store) QueryIOCs(ctx context.Context, f IOCFilter) ([]IOCRow, error) {
	q := `SELECT type, value, first_seen, last_seen, count, severity, last_rule, last_sensor, last_source
          FROM iocs WHERE 1=1`
	var args []any
	if f.Type != "" {
		q += " AND type = ?"
		args = append(args, f.Type)
	}
	if !f.Since.IsZero() {
		q += " AND last_seen >= ?"
		args = append(args, f.Since.UTC().UnixNano())
	}
	if f.Text != "" {
		q += " AND LOWER(value) LIKE ?"
		args = append(args, "%"+strings.ToLower(f.Text)+"%")
	}
	q += " ORDER BY last_seen DESC"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IOCRow
	for rows.Next() {
		var (
			r                                IOCRow
			first, last                      int64
			sev                              int
			lastRule, lastSensor, lastSource any
		)
		if err := rows.Scan(&r.Type, &r.Value, &first, &last, &r.Count, &sev, &lastRule, &lastSensor, &lastSource); err != nil {
			return nil, err
		}
		r.FirstSeen = time.Unix(0, first).UTC()
		r.LastSeen = time.Unix(0, last).UTC()
		r.Severity = event.Severity(sev)
		r.LastRule, _ = lastRule.(string)
		r.LastSensor, _ = lastSensor.(string)
		r.LastSource, _ = lastSource.(string)
		out = append(out, r)
	}
	return out, rows.Err()
}

// IOCSummary returns the indicator count per type (for the UI breakdown).
func (s *Store) IOCSummary(ctx context.Context, since time.Time) (map[string]int, error) {
	q := `SELECT type, COUNT(*) FROM iocs`
	var args []any
	if !since.IsZero() {
		q += " WHERE last_seen >= ?"
		args = append(args, since.UTC().UnixNano())
	}
	q += " GROUP BY type"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var typ string
		var n int
		if err := rows.Scan(&typ, &n); err != nil {
			return nil, err
		}
		out[typ] = n
	}
	return out, rows.Err()
}
