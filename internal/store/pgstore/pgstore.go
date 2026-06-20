// Package pgstore implements store.EventStore on PostgreSQL — the opt-in
// backend for a fleet aggregator/hub where many forwarders write concurrently
// and HA/replication/backups matter (see docs/database-backend.md). Leaf
// sensors keep the embedded SQLite store in internal/store; this is selected
// only when sensor.store.backend is "postgres".
//
// It talks to Postgres through database/sql + the pure-Go pgx stdlib driver, so
// the binary stays CGO-free. The query shapes mirror internal/store/store.go;
// the dialect differences are: $N placeholders (not ?), jsonb meta with ->>
// operators (not SQLite json_extract), ILIKE for case-insensitive search, and a
// native timestamptz time column (the SQLite store uses int64 UnixNano). IP
// columns stay text — not inet — so crafted/edge source identifiers (e.g. IPv6
// link-local with a zone like fe80::1%eth0) round-trip with full fidelity, which
// is the point of a honeypot. The engine-neutral Filter/Summary/event types are
// reused unchanged.
package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// Store is the PostgreSQL-backed event store.
type Store struct {
	db *sql.DB
	// partTick gates the lazy partition top-up on the write path (see
	// maybeEnsurePartitions).
	partTick atomic.Uint64
}

// Compile-time guarantee that this backend satisfies the same contract as the
// embedded SQLite store.
var _ store.EventStore = (*Store)(nil)

// Open connects to PostgreSQL at dsn (a libpq/pgx connection string or URL),
// verifies the connection, and ensures the schema exists.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("pgstore: open: %w", err)
	}
	// Size the pool for an aggregator's fan-out: concurrent forwarder writes
	// plus the dashboard's read fan-out. Unlike SQLite there is no single-writer
	// lock to serialize against.
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(8)
	db.SetConnMaxIdleTime(5 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pgstore: ping %s: %w", redactDSN(dsn), err)
	}
	// Apply embedded migrations (creates the partitioned schema on a fresh DB),
	// then provision the current + adjacent monthly partitions.
	if err := migrate(ctx, dsn); err != nil {
		_ = db.Close()
		return nil, err
	}
	st := &Store{db: db}
	st.ensurePartitions(ctx, time.Now())
	return st, nil
}

// redactDSN strips anything after the first credential-bearing token so a
// connection error never logs the password.
func redactDSN(dsn string) string {
	if i := strings.Index(dsn, "@"); i >= 0 {
		if j := strings.Index(dsn, "://"); j >= 0 && j+3 < i {
			return dsn[:j+3] + "***@" + dsn[i+1:]
		}
		return "***"
	}
	return "(host)"
}

func (s *Store) Close() error { return s.db.Close() }

// --- argList: $N placeholder builder ---------------------------------------

// argList accumulates bind values and emits the matching $N placeholder, so the
// dynamic Query filter can be assembled the same way store.go builds its ?-list.
type argList struct{ args []any }

func (a *argList) next(v any) string {
	a.args = append(a.args, v)
	return fmt.Sprintf("$%d", len(a.args))
}

// --- writes -----------------------------------------------------------------

const insertSQL = `
INSERT INTO events
(id, time, sensor, sensor_id, rule_id, severity, src_ip, src_port, dst_ip, dst_port,
 proto, handler, banner_sent, payload_b64, payload_len,
 meta, anomalies, mitre_techniques, mitre_tactics, mitre_defenses, country)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
        $16::jsonb,$17::jsonb,$18::jsonb,$19::jsonb,$20::jsonb,$21)
ON CONFLICT (id, time) DO UPDATE SET
  sensor=excluded.sensor, sensor_id=excluded.sensor_id,
  rule_id=excluded.rule_id, severity=excluded.severity,
  src_ip=excluded.src_ip, src_port=excluded.src_port,
  dst_ip=excluded.dst_ip, dst_port=excluded.dst_port,
  proto=excluded.proto, handler=excluded.handler, banner_sent=excluded.banner_sent,
  payload_b64=excluded.payload_b64, payload_len=excluded.payload_len,
  meta=excluded.meta, anomalies=excluded.anomalies,
  mitre_techniques=excluded.mitre_techniques, mitre_tactics=excluded.mitre_tactics,
  mitre_defenses=excluded.mitre_defenses, country=excluded.country`

// eventArgs flattens an event into the insert bind parameters. The jsonb columns
// take a JSON string or nil (NULL) — never "", which would not parse as jsonb.
func eventArgs(ev *event.Event) []any {
	country, _ := ev.Meta["geo_country"].(string)
	return []any{
		ev.ID, ev.Time.UTC(), ev.Sensor, ev.SensorID, ev.RuleID, int(ev.Severity),
		ev.Source.IP, ev.Source.Port, ev.Dest.IP, ev.Dest.Port,
		ev.Proto, ev.Handler, ev.BannerSent, ev.PayloadBase64, ev.PayloadLen,
		jsonOrNil(ev.Meta), jsonOrNil(ev.Anomalies),
		jsonOrNil(ev.MitreTechniques), jsonOrNil(ev.MitreTactics), jsonOrNil(ev.MitreDefenses),
		country,
	}
}

// jsonOrNil marshals a non-empty slice/map to a JSON string, or returns nil so
// the jsonb column is stored as SQL NULL.
func jsonOrNil(v any) any {
	switch t := v.(type) {
	case []string:
		if len(t) == 0 {
			return nil
		}
	case map[string]any:
		if len(t) == 0 {
			return nil
		}
	case nil:
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return string(b)
}

func (s *Store) Insert(ctx context.Context, ev *event.Event) error {
	if _, err := s.db.ExecContext(ctx, insertSQL, eventArgs(ev)...); err != nil {
		return fmt.Errorf("pgstore insert: %w", err)
	}
	s.maybeEnsurePartitions(ctx)
	return nil
}

func (s *Store) InsertBatch(ctx context.Context, evs []*event.Event) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("pgstore batch: begin: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, insertSQL)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("pgstore batch: prepare: %w", err)
	}
	for _, ev := range evs {
		if _, err := stmt.ExecContext(ctx, eventArgs(ev)...); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return fmt.Errorf("pgstore batch: exec: %w", err)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("pgstore batch: commit: %w", err)
	}
	s.maybeEnsurePartitions(ctx)
	return nil
}

// PruneBefore enforces retention by first dropping whole monthly partitions
// older than the cutoff (instant, no row scan), then DELETE-ing any stragglers
// in the partial boundary month and the DEFAULT partition so the cut is exact.
// The events count combines the dropped partitions' row estimate with the exact
// boundary-delete count (dropped rows can't be counted precisely without
// scanning a table that is about to vanish).
func (s *Store) PruneBefore(ctx context.Context, cutoff time.Time) (events, iocs int64, err error) {
	cut := cutoff.UTC()
	dropped, err := s.dropOldPartitions(ctx, cut)
	if err != nil {
		return 0, 0, err
	}
	events = dropped
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE time < $1`, cut)
	if err != nil {
		return events, 0, fmt.Errorf("pgstore: prune events: %w", err)
	}
	n, _ := res.RowsAffected()
	events += n
	res, err = s.db.ExecContext(ctx, `DELETE FROM iocs WHERE last_seen < $1`, cut)
	if err != nil {
		return events, 0, fmt.Errorf("pgstore: prune iocs: %w", err)
	}
	iocs, _ = res.RowsAffected()
	return events, iocs, nil
}

// --- event reads ------------------------------------------------------------

// selectCols is the column list scanRow expects. The jsonb columns are rendered
// to text (COALESCE to ”) so they scan into Go strings exactly like the SQLite
// store's TEXT columns.
const selectCols = `id, time, sensor, sensor_id, rule_id, severity, src_ip, src_port,
 dst_ip, dst_port, proto, handler, %s,
 %s, payload_len, COALESCE(meta::text,''), COALESCE(anomalies::text,''),
 COALESCE(mitre_techniques::text,''), COALESCE(mitre_tactics::text,''), COALESCE(mitre_defenses::text,'')`

func (s *Store) Query(ctx context.Context, f store.Filter) ([]*event.Event, error) {
	bannerCol, payloadCol := "banner_sent", "payload_b64"
	if f.NoPayload {
		bannerCol, payloadCol = "'' AS banner_sent", "'' AS payload_b64"
	}
	var a argList
	q := "SELECT " + fmt.Sprintf(selectCols, bannerCol, payloadCol) + " FROM events WHERE 1=1"

	if !f.Since.IsZero() {
		q += " AND time >= " + a.next(f.Since.UTC())
	}
	if !f.Until.IsZero() {
		q += " AND time <= " + a.next(f.Until.UTC())
	}
	if f.SourceIP != "" {
		q += " AND src_ip = " + a.next(f.SourceIP)
	}
	if f.DstIP != "" {
		q += " AND dst_ip = " + a.next(f.DstIP)
	}
	if f.RuleID != "" {
		q += " AND rule_id = " + a.next(f.RuleID)
	}
	if f.Proto != "" {
		q += " AND proto = " + a.next(f.Proto)
	}
	if f.Handler != "" {
		q += " AND handler = " + a.next(f.Handler)
	}
	if len(f.Handlers) > 0 {
		q += " AND handler IN (" + inListAny(&a, anyStr(f.Handlers)) + ")"
	}
	if f.DstPort > 0 {
		q += " AND dst_port = " + a.next(f.DstPort)
	}
	if f.Country != "" {
		q += " AND country = " + a.next(f.Country)
	}
	if f.ASN > 0 {
		q += " AND " + asnExpr + " = " + a.next(f.ASN)
	}
	if f.MinSeverity > 0 {
		q += " AND severity >= " + a.next(int(f.MinSeverity))
	}
	if f.Text != "" {
		// ILIKE is case-insensitive, so (unlike the SQLite LOWER() dance) one
		// pattern parameter is reused across every searchable column.
		p := a.next("%" + f.Text + "%")
		q += " AND (rule_id ILIKE " + p + " OR banner_sent ILIKE " + p +
			" OR COALESCE(meta::text,'') ILIKE " + p + " OR src_ip ILIKE " + p +
			" OR dst_ip ILIKE " + p + " OR handler ILIKE " + p + " OR proto ILIKE " + p +
			" OR sensor ILIKE " + p + " OR COALESCE(anomalies::text,'') ILIKE " + p +
			" OR COALESCE(mitre_techniques::text,'') ILIKE " + p +
			" OR COALESCE(mitre_tactics::text,'') ILIKE " + p + ")"
	}
	if f.FPValue != "" {
		// The kind is validated against the store allowlist, so the meta key is a
		// safe literal; only the value is bound.
		if store.FingerprintKindKnown(f.FPKind) {
			q += " AND meta->>'" + f.FPKind + "' = " + a.next(f.FPValue)
		} else {
			q += " AND 1=0"
		}
	}

	// Multi-value include / exclude (events negation, charts include/exclude).
	addIn := func(col string, vals []string) {
		if len(vals) > 0 {
			q += " AND " + col + " IN (" + inListAny(&a, anyStr(vals)) + ")"
		}
	}
	addNotIn := func(col string, vals []string) {
		if len(vals) > 0 {
			q += " AND " + col + " NOT IN (" + inListAny(&a, anyStr(vals)) + ")"
		}
	}
	addIn("src_ip", f.SourceIPs)
	addNotIn("src_ip", f.ExcludeSourceIPs)
	addIn("rule_id", f.RuleIDs)
	addNotIn("rule_id", f.ExcludeRuleIDs)
	addNotIn("handler", f.ExcludeHandlers)
	addIn("proto", f.Protos)
	addNotIn("proto", f.ExcludeProtos)
	addIn("country", f.Countries)
	addNotIn("country", f.ExcludeCountries)
	if len(f.DstPorts) > 0 {
		q += " AND dst_port IN (" + inListAny(&a, anyInt(f.DstPorts)) + ")"
	}
	if len(f.ExcludeDstPorts) > 0 {
		q += " AND dst_port NOT IN (" + inListAny(&a, anyInt(f.ExcludeDstPorts)) + ")"
	}
	// ASN is a JSON number; the exclusion keeps rows with no ASN (expr IS NULL),
	// matching the SQLite store.
	if len(f.ASNs) > 0 {
		q += " AND " + asnExpr + " IN (" + inListAny(&a, anyInt(f.ASNs)) + ")"
	}
	if len(f.ExcludeASNs) > 0 {
		q += " AND (" + asnExpr + " IS NULL OR " + asnExpr + " NOT IN (" + inListAny(&a, anyInt(f.ExcludeASNs)) + "))"
	}
	// Allowlisted free-text meta dimensions; exclusion keeps rows with no value.
	for _, mf := range []struct {
		key       string
		in, notIn []string
	}{
		{"geo_city", f.Cities, f.ExcludeCities},
		{"geo_country_name", f.CountryNames, f.ExcludeCountryNames},
		{"asn_org", f.ASNOrgs, f.ExcludeASNOrgs},
	} {
		expr := "meta->>'" + mf.key + "'"
		if len(mf.in) > 0 {
			q += " AND " + expr + " IN (" + inListAny(&a, anyStr(mf.in)) + ")"
		}
		if len(mf.notIn) > 0 {
			q += " AND (" + expr + " IS NULL OR " + expr + " NOT IN (" + inListAny(&a, anyStr(mf.notIn)) + "))"
		}
	}

	q += " ORDER BY time DESC"
	if f.Limit > 0 {
		q += " LIMIT " + a.next(f.Limit)
		if f.Offset > 0 {
			q += " OFFSET " + a.next(f.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, q, a.args...)
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

// asnExpr extracts meta.asn as an integer, guarding against a missing or
// non-numeric value (which becomes NULL rather than erroring the query).
const asnExpr = `CASE WHEN meta->>'asn' ~ '^[0-9]+$' THEN (meta->>'asn')::bigint END`

// inListAny binds each value and returns the comma-joined $N placeholders for an
// IN (...) clause.
func inListAny(a *argList, vals []any) string {
	ps := make([]string, len(vals))
	for i, v := range vals {
		ps[i] = a.next(v)
	}
	return strings.Join(ps, ",")
}

func anyStr(v []string) []any {
	out := make([]any, len(v))
	for i, x := range v {
		out[i] = x
	}
	return out
}

func anyInt(v []int) []any {
	out := make([]any, len(v))
	for i, x := range v {
		out[i] = x
	}
	return out
}

func (s *Store) Get(ctx context.Context, id string) (*event.Event, error) {
	q := "SELECT " + fmt.Sprintf(selectCols, "banner_sent", "payload_b64") + " FROM events WHERE id = $1"
	return scanRow(s.db.QueryRowContext(ctx, q, id))
}

func (s *Store) ConversationNav(ctx context.Context, ev *event.Event) (store.EventNeighbors, error) {
	var nb store.EventNeighbors
	if ev == nil || ev.Source.IP == "" || ev.Dest.IP == "" {
		return nb, nil
	}
	src, dst, t := ev.Source.IP, ev.Dest.IP, ev.Time.UTC()
	err := s.db.QueryRowContext(ctx, `
SELECT id FROM events
WHERE src_ip = $1 AND dst_ip = $2 AND (time < $3 OR (time = $3 AND id < $4))
ORDER BY time DESC, id DESC LIMIT 1`, src, dst, t, ev.ID).Scan(&nb.PrevID)
	if err != nil && err != sql.ErrNoRows {
		return nb, err
	}
	err = s.db.QueryRowContext(ctx, `
SELECT id FROM events
WHERE src_ip = $1 AND dst_ip = $2 AND (time > $3 OR (time = $3 AND id > $4))
ORDER BY time ASC, id ASC LIMIT 1`, src, dst, t, ev.ID).Scan(&nb.NextID)
	if err != nil && err != sql.ErrNoRows {
		return nb, err
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events WHERE src_ip = $1 AND dst_ip = $2`, src, dst).Scan(&nb.Total); err != nil {
		return nb, err
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events WHERE src_ip = $1 AND dst_ip = $2 AND (time < $3 OR (time = $3 AND id <= $4))`,
		src, dst, t, ev.ID).Scan(&nb.Pos); err != nil {
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
		ts                                                                             time.Time
		sev, srcPort, dstPort, payloadLen                                              int
	)
	if err := r.Scan(&id, &ts, &sensor, &sensorID, &ruleID, &sev,
		&srcIP, &srcPort, &dstIP, &dstPort,
		&proto, &handler, &banner, &payloadB64, &payloadLen, &metaJSON, &anomaliesJSON,
		&techJSON, &tacJSON, &defJSON); err != nil {
		return nil, err
	}
	ev := &event.Event{
		ID:            id,
		Time:          ts.UTC(),
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

// --- aggregates -------------------------------------------------------------

func (s *Store) Heartbeat(ctx context.Context) (count int64, latest time.Time, err error) {
	var nt sql.NullTime
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*), MAX(time) FROM events`).Scan(&count, &nt); err != nil {
		return 0, time.Time{}, err
	}
	if nt.Valid {
		latest = nt.Time.UTC()
	}
	return count, latest, nil
}

func (s *Store) OldestEventTime(ctx context.Context) (time.Time, error) {
	var nt sql.NullTime
	if err := s.db.QueryRowContext(ctx, `SELECT MIN(time) FROM events`).Scan(&nt); err != nil {
		return time.Time{}, err
	}
	if !nt.Valid {
		return time.Time{}, nil
	}
	return nt.Time.UTC(), nil
}

func (s *Store) SourceAggregates(ctx context.Context, since time.Time, limit int) ([]store.SourceAggregate, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT src_ip, COUNT(*) c, MIN(time) mn, MAX(time) mx, MAX(severity) ms,
       COUNT(DISTINCT rule_id) dr, SUM(severity*severity) w
FROM events
WHERE time >= $1 AND src_ip <> ''
GROUP BY src_ip
ORDER BY w DESC, c DESC
LIMIT $2`, since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.SourceAggregate
	for rows.Next() {
		var (
			a      store.SourceAggregate
			mn, mx time.Time
			ms     int
		)
		if err := rows.Scan(&a.IP, &a.Count, &mn, &mx, &ms, &a.DistinctRules, &a.Weight); err != nil {
			return nil, err
		}
		a.FirstSeen = mn.UTC()
		a.LastSeen = mx.UTC()
		a.MaxSeverity = event.Severity(ms)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) EventsPerHour(ctx context.Context, since time.Time) ([]store.HourBucket, error) {
	return s.EventsPerBucket(ctx, since, time.Hour)
}

func (s *Store) EventsPerBucket(ctx context.Context, since time.Time, bucket time.Duration) ([]store.HourBucket, error) {
	bucketSec := int64(bucket / time.Second)
	if bucketSec <= 0 {
		bucketSec = int64(time.Hour / time.Second)
	}
	startBucket := since.UTC().Unix() / bucketSec
	nowBucket := time.Now().UTC().Unix() / bucketSec
	counts := map[int64]int{}
	// Bucket on the timestamp's epoch seconds: floor(epoch/bucketSec) is the
	// bucket index, reconstructed to a time in Go (mirrors the SQLite store,
	// which divides UnixNano).
	rows, err := s.db.QueryContext(ctx,
		`SELECT floor(extract(epoch FROM time)/$1)::bigint AS b, COUNT(*) FROM events WHERE time >= $2 GROUP BY b`,
		bucketSec, since.UTC())
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
	out := make([]store.HourBucket, 0, nowBucket-startBucket+1)
	for b := startBucket; b <= nowBucket; b++ {
		out = append(out, store.HourBucket{Hour: time.Unix(b*bucketSec, 0).UTC(), Count: counts[b]})
	}
	return out, nil
}

func (s *Store) Summary(ctx context.Context, since time.Time) (store.Summary, error) {
	sum := store.Summary{Since: since, BySeverity: map[string]int{}, ByRule: map[string]int{}, ByProto: map[string]int{}}
	sinceTS := since.UTC()

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE time >= $1`, sinceTS).Scan(&sum.Total); err != nil {
		return sum, err
	}
	// severity is an integer column, so it is scanned as int (not via scanCounts,
	// which reads string keys) and mapped to its label.
	sevRows, err := s.db.QueryContext(ctx, `SELECT severity, COUNT(*) FROM events WHERE time >= $1 GROUP BY severity`, sinceTS)
	if err != nil {
		return sum, err
	}
	for sevRows.Next() {
		var sev, c int
		if err := sevRows.Scan(&sev, &c); err != nil {
			sevRows.Close()
			return sum, err
		}
		sum.BySeverity[event.Severity(sev).String()] = c
	}
	sevRows.Close()
	if err := sevRows.Err(); err != nil {
		return sum, err
	}
	if err := scanCounts(ctx, s.db, `SELECT rule_id, COUNT(*) c FROM events WHERE time >= $1 GROUP BY rule_id ORDER BY c DESC LIMIT 20`, sinceTS,
		func(k string, c int) { sum.ByRule[k] = c }); err != nil {
		return sum, err
	}
	if err := scanCounts(ctx, s.db, `SELECT proto, COUNT(*) FROM events WHERE time >= $1 AND proto <> '' GROUP BY proto`, sinceTS,
		func(k string, c int) { sum.ByProto[k] = c }); err != nil {
		return sum, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT src_ip, COUNT(*) c FROM events WHERE time >= $1 AND src_ip <> '' GROUP BY src_ip ORDER BY c DESC LIMIT 10`, sinceTS)
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
		sum.TopSources = append(sum.TopSources, store.SourceCount{IP: ip, Count: c})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return sum, err
	}

	if sum.ByHandler, err = s.groupCount(ctx, "handler", sinceTS, 50); err != nil {
		return sum, err
	}
	if sum.ByTarget, err = s.groupCount(ctx, "dst_ip", sinceTS, 50); err != nil {
		return sum, err
	}
	if sum.ByCountry, err = s.groupCount(ctx, "country", sinceTS, 30); err != nil {
		return sum, err
	}
	return sum, nil
}

func scanCounts(ctx context.Context, db *sql.DB, q string, since time.Time, fn func(k string, c int)) error {
	rows, err := db.QueryContext(ctx, q, since)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var c int
		if err := rows.Scan(&k, &c); err != nil {
			return err
		}
		fn(k, c)
	}
	return rows.Err()
}

func (s *Store) groupCount(ctx context.Context, col string, since time.Time, limit int) (map[string]int, error) {
	out := map[string]int{}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+col+`, COUNT(*) c FROM events WHERE time >= $1 AND `+col+` <> '' GROUP BY `+col+` ORDER BY c DESC LIMIT $2`,
		since, limit)
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

func (s *Store) Fingerprints(ctx context.Context, since time.Time, limit int) ([]store.FingerprintRow, error) {
	var selects []string
	for _, kind := range store.FingerprintKindOrder() {
		// kind is from the store allowlist, so it is a safe meta-key literal.
		val := "meta->>'" + kind + "'"
		selects = append(selects, `
SELECT '`+kind+`' AS kind, `+val+` AS val,
       COUNT(*) AS c, COUNT(DISTINCT src_ip) AS ips, COUNT(DISTINCT sensor) AS sensors,
       MIN(time) AS firstns, MAX(time) AS lastns
FROM events
WHERE time >= $1 AND `+val+` IS NOT NULL AND `+val+` <> ''
GROUP BY `+val)
	}
	q := "SELECT kind, val, c, ips, sensors, firstns, lastns FROM (" +
		strings.Join(selects, " UNION ALL ") + ") sub ORDER BY c DESC, lastns DESC"
	args := []any{since.UTC()}
	if limit > 0 {
		q += " LIMIT $2"
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.FingerprintRow
	for rows.Next() {
		var (
			r             store.FingerprintRow
			firstT, lastT time.Time
		)
		if err := rows.Scan(&r.Kind, &r.Value, &r.Count, &r.IPs, &r.Sensors, &firstT, &lastT); err != nil {
			return nil, err
		}
		r.FirstSeen = firstT.UTC()
		r.LastSeen = lastT.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- IOCs -------------------------------------------------------------------

func (s *Store) UpsertIOC(ctx context.Context, typ, value, ruleID, sensor, source string, sev event.Severity, t time.Time) (bool, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `
INSERT INTO iocs (type, value, first_seen, last_seen, count, severity, last_rule, last_sensor, last_source)
VALUES ($1, $2, $3, $3, 1, $4, $5, $6, $7)
ON CONFLICT (type, value) DO UPDATE SET
  last_seen   = excluded.last_seen,
  count       = iocs.count + 1,
  severity    = GREATEST(iocs.severity, excluded.severity),
  last_rule   = excluded.last_rule,
  last_sensor = excluded.last_sensor,
  last_source = excluded.last_source
RETURNING count`,
		typ, value, t.UTC(), int(sev), ruleID, sensor, source).Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 1, nil
}

func (s *Store) QueryIOCs(ctx context.Context, f store.IOCFilter) ([]store.IOCRow, error) {
	var a argList
	q := `SELECT type, value, first_seen, last_seen, count, severity, last_rule, last_sensor, last_source
          FROM iocs WHERE 1=1`
	if f.Type != "" {
		q += " AND type = " + a.next(f.Type)
	}
	if !f.Since.IsZero() {
		q += " AND last_seen >= " + a.next(f.Since.UTC())
	}
	if f.Text != "" {
		q += " AND value ILIKE " + a.next("%"+f.Text+"%")
	}
	q += " ORDER BY last_seen DESC"
	if f.Limit > 0 {
		q += " LIMIT " + a.next(f.Limit)
	}
	rows, err := s.db.QueryContext(ctx, q, a.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.IOCRow
	for rows.Next() {
		var (
			r                                store.IOCRow
			first, last                      time.Time
			count                            int64
			sev                              sql.NullInt64
			lastRule, lastSensor, lastSource sql.NullString
		)
		if err := rows.Scan(&r.Type, &r.Value, &first, &last, &count, &sev, &lastRule, &lastSensor, &lastSource); err != nil {
			return nil, err
		}
		r.FirstSeen = first.UTC()
		r.LastSeen = last.UTC()
		r.Count = int(count)
		r.Severity = event.Severity(sev.Int64)
		r.LastRule = lastRule.String
		r.LastSensor = lastSensor.String
		r.LastSource = lastSource.String
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) IOCSummary(ctx context.Context, since time.Time) (map[string]int, error) {
	q := `SELECT type, COUNT(*) FROM iocs`
	var args []any
	if !since.IsZero() {
		q += " WHERE last_seen >= $1"
		args = append(args, since.UTC())
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
