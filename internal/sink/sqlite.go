package sink

import (
	"context"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// sqliteSink wraps a store.Store as a Sink. It does not own the store —
// the sensor opens the store once and reuses it for both this sink and
// the read-only UI / list-events path so we don't hold two writers.
type sqliteSink struct {
	id string
	s  *store.Store
}

// NewSQLite is constructed by the sensor (which owns the store handle)
// rather than by Build, because the store needs to be shared.
func NewSQLite(id string, s *store.Store) Sink {
	return &sqliteSink{id: id, s: s}
}

func (q *sqliteSink) ID() string { return q.id }

func (q *sqliteSink) Send(ctx context.Context, ev *event.Event) error {
	return q.s.Insert(ctx, ev)
}

// Close is a no-op; the store is closed by its owner (the sensor).
func (q *sqliteSink) Close() error { return nil }
