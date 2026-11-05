package store

import (
	"context"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// EventStore is the engine-neutral persistence contract the rest of the sensor
// depends on: the write path (the SQLite sink), the read path (the web UI,
// /search, and the read-only CLI views), and the IOC tracker all talk to events
// through these methods, never through a concrete engine type.
//
// Today there is one implementation — *Store, the embedded SQLite index this
// package is built around — and Open returns it. The interface exists so a
// second, client-server backend (e.g. PostgreSQL at a fleet aggregator, where
// many forwarders write concurrently and HA/replication matter) can be dropped
// in behind the same contract without the UI/sink/CLI knowing which engine they
// hold. See docs/database-backend.md for the full two-tier design.
//
// Engine-specific operations deliberately stay OFF this interface, on the
// concrete *Store, because they leak the storage medium: DB() (*sql.DB for the
// retention runner), Path() (the on-disk file the prune-db/rotate-db/metrics
// CLIs stat), and EnsureIndexes/MissingIndexes (SQLite secondary-index health).
// The sensor is the composition root: it constructs the concrete store, wires
// those engine-specific paths, and hands collaborators this narrower interface.
type EventStore interface {
	// Write path — buffered single inserts and the batch throughput path used by
	// the aggregator ingesting forwarded events.
	Insert(ctx context.Context, ev *event.Event) error
	InsertBatch(ctx context.Context, evs []*event.Event) error

	// Event reads — the events list, the event-detail page, and its
	// previous/next conversation navigation.
	Query(ctx context.Context, f Filter) ([]*event.Event, error)
	Get(ctx context.Context, id string) (*event.Event, error)
	ConversationNav(ctx context.Context, ev *event.Event) (EventNeighbors, error)

	// Aggregates — the dashboard summary, attacker-profile rollups, the
	// events-over-time histogram, freshness/heartbeat, the retention horizon,
	// and the network-fingerprint rollup.
	Summary(ctx context.Context, since time.Time) (Summary, error)
	SourceAggregates(ctx context.Context, since time.Time, limit int) ([]SourceAggregate, error)
	EventsPerHour(ctx context.Context, since time.Time) ([]HourBucket, error)
	EventsPerBucket(ctx context.Context, since time.Time, bucket time.Duration) ([]HourBucket, error)
	Heartbeat(ctx context.Context) (count int64, latest time.Time, err error)
	OldestEventTime(ctx context.Context) (time.Time, error)
	Fingerprints(ctx context.Context, since time.Time, limit int) ([]FingerprintRow, error)

	// Indicators of compromise — the IOC tracker upserts sightings; the UI and
	// the export CLIs read them back.
	UpsertIOC(ctx context.Context, typ, value, ruleID, sensor, source string, sev event.Severity, t time.Time) (bool, error)
	// UpsertIOCs is the batched form (one transaction), used by the sensor's
	// off-bus-loop IOC writer so per-event indicator writes don't serialize
	// against the event sink on the single writer lock.
	UpsertIOCs(ctx context.Context, batch []IOCUpsert) ([]bool, error)
	QueryIOCs(ctx context.Context, f IOCFilter) ([]IOCRow, error)
	IOCSummary(ctx context.Context, since time.Time) (map[string]int, error)

	// PruneBefore drops events (by event time) and IOCs (by last_seen) older
	// than cutoff, returning the rows removed from each. This is the
	// engine-neutral retention primitive the retention runner calls regardless
	// of backend — unlike the SQLite-only DB()/Path() it does not leak the
	// engine, so it belongs on the contract.
	PruneBefore(ctx context.Context, cutoff time.Time) (events, iocs int64, err error)

	// Lifecycle.
	Close() error
}

// Compile-time guarantee that the embedded SQLite store satisfies the contract.
// A second backend adds its own assertion here.
var _ EventStore = (*Store)(nil)
