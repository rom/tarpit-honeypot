package pgstore

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"time"
)

// Monthly RANGE partitions on events.time. Retention drops whole partitions
// older than the cutoff (instant, no row-by-row delete or vacuum), and a
// boundary DELETE in PruneBefore trims the partial current month + the DEFAULT
// partition so retention stays exact rather than rounded to a whole month.

// partEnsurePeriod gates the lazy partition top-up on the write path: every this
// many batches a long-running aggregator re-ensures the current/adjacent months
// exist, so future inserts land in a dedicated partition rather than DEFAULT.
const partEnsurePeriod = 2048

// partNameRE matches a monthly partition name (events_YYYY_MM) so retention only
// ever drops partitions this package created — never the DEFAULT partition or
// anything else inheriting from events.
var partNameRE = regexp.MustCompile(`^events_(\d{4})_(\d{2})$`)

// monthBounds returns the [start, nextMonth) bounds (UnixNano) and the partition
// name for the month containing t.
func monthBounds(t time.Time) (loNano, hiNano int64, name string) {
	y, m, _ := t.UTC().Date()
	lo := time.Date(y, m, 1, 0, 0, 0, 0, time.UTC)
	hi := lo.AddDate(0, 1, 0)
	return lo.UnixNano(), hi.UnixNano(), fmt.Sprintf("events_%04d_%02d", y, int(m))
}

// ensurePartitions creates the monthly partitions around ref (previous, current,
// next) if they don't already exist. Best-effort: a create can fail if the
// DEFAULT partition already holds rows in that month's range (pre-existing
// data), in which case those rows stay in DEFAULT and retention's boundary
// DELETE handles them — so a failure is logged, not fatal.
func (s *Store) ensurePartitions(ctx context.Context, ref time.Time) {
	for _, off := range []int{-1, 0, 1} {
		lo, hi, name := monthBounds(ref.AddDate(0, off, 0))
		stmt := fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s PARTITION OF events FOR VALUES FROM (%d) TO (%d)`,
			name, lo, hi)
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			slog.Debug("pgstore: ensure partition (leaving rows in DEFAULT)", "name", name, "err", err)
		}
	}
}

// maybeEnsurePartitions runs ensurePartitions every partEnsurePeriod writes so a
// long-lived process keeps provisioning upcoming months without paying the DDL
// cost on every insert.
func (s *Store) maybeEnsurePartitions(ctx context.Context) {
	if s.partTick.Add(1)%partEnsurePeriod == 0 {
		s.ensurePartitions(ctx, time.Now())
	}
}

// dropOldPartitions drops every monthly partition whose entire range is older
// than cutoff, returning the estimated rows removed (from pg_class.reltuples —
// exact counts would mean scanning a table we're about to drop). The DEFAULT
// partition and any non-monthly child are left for the caller's boundary DELETE.
func (s *Store) dropOldPartitions(ctx context.Context, cutoffNano int64) (int64, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT c.relname
FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid
JOIN pg_class p ON p.oid = i.inhparent
WHERE p.relname = 'events'`)
	if err != nil {
		return 0, fmt.Errorf("pgstore: list partitions: %w", err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return 0, err
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	var removed int64
	for _, n := range names {
		m := partNameRE.FindStringSubmatch(n)
		if m == nil {
			continue // DEFAULT partition or a name we didn't create
		}
		year, _ := strconv.Atoi(m[1])
		month, _ := strconv.Atoi(m[2])
		// A partition is safe to drop only when its whole range is older than the
		// cutoff, i.e. the start of the following month is still <= cutoff.
		upper := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0).UnixNano()
		if upper > cutoffNano {
			continue
		}
		var est int64
		_ = s.db.QueryRowContext(ctx,
			`SELECT COALESCE(reltuples, 0)::bigint FROM pg_class WHERE relname = $1`, n).Scan(&est)
		// n comes from partNameRE, so it is a safe identifier literal.
		if _, err := s.db.ExecContext(ctx, `DROP TABLE IF EXISTS `+n); err != nil {
			return removed, fmt.Errorf("pgstore: drop partition %s: %w", n, err)
		}
		if est > 0 {
			removed += est
		}
		slog.Debug("pgstore: dropped expired partition", "name", n, "est_rows", est)
	}
	return removed, nil
}
