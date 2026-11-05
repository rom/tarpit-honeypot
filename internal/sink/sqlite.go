package sink

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// SQLiteTuning overrides the sink's write-batching parameters: flush when the
// buffer reaches Batch events or Flush elapses (whichever first), and go
// synchronous above HardCap to bound memory. A zero field uses its default
// (256 / 500ms / 8192) — so the sensor can pass config.Tuning straight through
// and an unset tuning block changes nothing.
type SQLiteTuning struct {
	Batch   int
	Flush   time.Duration
	HardCap int
}

func (t SQLiteTuning) withDefaults() SQLiteTuning {
	if t.Batch <= 0 {
		t.Batch = 256
	}
	if t.Flush <= 0 {
		t.Flush = 500 * time.Millisecond
	}
	if t.HardCap <= 0 {
		t.HardCap = 8192
	}
	return t
}

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

	maxBatch int
	maxAge   time.Duration
	hardCap  int

	mu  sync.Mutex
	buf []*event.Event

	flush     chan struct{}
	quit      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// NewSQLite is constructed by the sensor (which owns the store handle)
// rather than by Build, because the store needs to be shared. tune overrides
// the batch parameters (zero fields = defaults).
func NewSQLite(id string, s store.EventStore, tune SQLiteTuning) Sink {
	tune = tune.withDefaults()
	q := &sqliteSink{
		id: id, s: s,
		maxBatch: tune.Batch,
		maxAge:   tune.Flush,
		hardCap:  tune.HardCap,
		flush:    make(chan struct{}, 1),
		quit:     make(chan struct{}),
		done:     make(chan struct{}),
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
	case n >= q.hardCap:
		q.flushNow()
	case n >= q.maxBatch:
		select {
		case q.flush <- struct{}{}:
		default:
		}
	}
	return nil
}

func (q *sqliteSink) loop() {
	defer close(q.done)
	t := time.NewTicker(q.maxAge)
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
