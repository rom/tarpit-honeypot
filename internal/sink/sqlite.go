package sink

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// sqlite sink batching parameters: flush when the buffer reaches sqliteMaxBatch
// or sqliteMaxAge elapses, whichever comes first.
const (
	sqliteMaxBatch = 256
	sqliteMaxAge   = 500 * time.Millisecond
	sqliteHardCap  = 8192 // synchronous fallback above this, to bound memory
)

// sqliteSink wraps a store.EventStore as a Sink. It does not own the store —
// the sensor opens the store once and reuses it for both this sink and
// the read-only UI / list-events path so we don't hold two writers.
//
// It is typed on the store.EventStore interface rather than the concrete
// SQLite *store.Store so the same buffered write path serves a future
// client-server backend unchanged (see docs/database-backend.md); the embedded
// SQLite store is the only implementation today.
//
// Writes are batched: each Send buffers the event and a background flusher
// commits them in one transaction (the throughput path for a busy aggregator).
// Durability holds across shutdown because the sensor drains the router and
// then calls Close (which flushes) before closing the store.
type sqliteSink struct {
	id string
	s  store.EventStore

	mu  sync.Mutex
	buf []*event.Event

	flush     chan struct{}
	quit      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// NewSQLite is constructed by the sensor (which owns the store handle)
// rather than by Build, because the store needs to be shared.
func NewSQLite(id string, s store.EventStore) Sink {
	q := &sqliteSink{
		id: id, s: s,
		flush: make(chan struct{}, 1),
		quit:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go q.loop()
	return q
}

func (q *sqliteSink) ID() string { return q.id }

// Send buffers the event for the next batch flush. It returns nil immediately
// (the flusher owns durability); when the buffer is alarmingly large it commits
// synchronously to apply back-pressure rather than grow without bound.
func (q *sqliteSink) Send(ctx context.Context, ev *event.Event) error {
	q.mu.Lock()
	q.buf = append(q.buf, ev)
	n := len(q.buf)
	q.mu.Unlock()
	switch {
	case n >= sqliteHardCap:
		q.flushNow()
	case n >= sqliteMaxBatch:
		select {
		case q.flush <- struct{}{}:
		default:
		}
	}
	return nil
}

func (q *sqliteSink) loop() {
	defer close(q.done)
	t := time.NewTicker(sqliteMaxAge)
	defer t.Stop()
	for {
		select {
		case <-q.quit:
			q.flushNow() // final flush before exit
			return
		case <-t.C:
			q.flushNow()
		case <-q.flush:
			q.flushNow()
		}
	}
}

// flushNow commits the buffered events in one transaction, falling back to
// per-event inserts if the batch fails so one bad row can't drop the rest.
func (q *sqliteSink) flushNow() {
	q.mu.Lock()
	batch := q.buf
	q.buf = nil
	q.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := q.s.InsertBatch(ctx, batch); err == nil {
		return
	}
	for _, ev := range batch {
		ictx, ic := context.WithTimeout(context.Background(), 5*time.Second)
		if err := q.s.Insert(ictx, ev); err != nil {
			slog.Warn("sqlite sink: insert failed", "id", q.id, "err", err)
		}
		ic()
	}
}

// Close stops the flusher and flushes any buffered events. The store itself is
// closed by its owner (the sensor) after every sink is closed.
func (q *sqliteSink) Close() error {
	q.closeOnce.Do(func() {
		close(q.quit)
		<-q.done
	})
	return nil
}
