package testharness

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

// DB is the harness results database: it records, per run, which tool version
// was tested when, against what target, with the per-case outcomes — so QA can
// track reliability across builds over time.
type DB struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS runs (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  started      TEXT NOT NULL,
  finished     TEXT NOT NULL,
  tool_version TEXT NOT NULL,
  target       TEXT NOT NULL,
  seed         INTEGER NOT NULL,
  rounds       INTEGER NOT NULL,
  total        INTEGER NOT NULL,
  pass         INTEGER NOT NULL,
  fail         INTEGER NOT NULL,
  errors       INTEGER NOT NULL,
  skip         INTEGER NOT NULL,
  crash        INTEGER NOT NULL,
  time_bounded INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS results (
  run_id      INTEGER NOT NULL REFERENCES runs(id),
  case_id     TEXT NOT NULL,
  category    TEXT NOT NULL,
  endpoint    TEXT,
  round       INTEGER NOT NULL,
  attempts    INTEGER NOT NULL,
  status      TEXT NOT NULL,
  detail      TEXT,
  error       TEXT,
  duration_ns INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_results_run ON results(run_id);
CREATE INDEX IF NOT EXISTS idx_results_case ON results(case_id);
`

// OpenDB opens (creating + migrating) the results database at path.
func OpenDB(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &DB{db: db}, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.db.Close() }

// Record persists a run + its per-case results, returning the new run id.
func (d *DB) Record(rr *RunResult) (int64, error) {
	c := rr.Counts()
	tb := 0
	if rr.TimeBounded {
		tb = 1
	}
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	res, err := tx.Exec(
		`INSERT INTO runs (started, finished, tool_version, target, seed, rounds, total, pass, fail, errors, skip, crash, time_bounded)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rr.Started.Format(time.RFC3339Nano), rr.Finished.Format(time.RFC3339Nano), rr.ToolVersion, rr.Target, rr.Seed,
		rr.Rounds, len(rr.Results), c[StatusPass], c[StatusFail], c[StatusError], c[StatusSkip], c[StatusCrash], tb)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	runID, _ := res.LastInsertId()
	stmt, err := tx.Prepare(
		`INSERT INTO results (run_id, case_id, category, endpoint, round, attempts, status, detail, error, duration_ns)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	defer stmt.Close()
	for _, r := range rr.Results {
		if _, err := stmt.Exec(runID, r.CaseID, string(r.Category), r.Endpoint, r.Round, r.Attempt,
			string(r.Status), r.Detail, r.Err, int64(r.Duration)); err != nil {
			_ = tx.Rollback()
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return runID, nil
}

// History summarizes recent runs (for `report --history`).
type RunRow struct {
	ID          int64
	Started     string
	ToolVersion string
	Target      string
	Total       int
	Pass        int
	Fail        int
	Crash       int
}

// Recent returns the last n runs, newest first.
func (d *DB) Recent(n int) ([]RunRow, error) {
	rows, err := d.db.Query(`SELECT id, started, tool_version, target, total, pass, fail, crash FROM runs ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunRow
	for rows.Next() {
		var r RunRow
		if err := rows.Scan(&r.ID, &r.Started, &r.ToolVersion, &r.Target, &r.Total, &r.Pass, &r.Fail, &r.Crash); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
