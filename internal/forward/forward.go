// Package forward ships a sensor's events to one or more parent aggregator
// nodes for fleet-wide correlation. Each target is an independent forwarder
// (its own queue + retry), so listing several targets fans out (HA, or a site
// SOC plus a global hub). Events are batched as NDJSON over HTTPS, dialed
// through the egress allowlist (so a forward target is, by construction, an
// allowlisted destination), authenticated with a bearer token and optionally
// HMAC-signed. This node stamps itself into each event's Hops for loop/dup
// detection at the aggregator. At-least-once durability (disk spool) is a
// follow-on; for now a full queue sheds load with a counter, like the sinks.
package forward

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/tarpit-honeypot/internal/egress"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// Target is one parent aggregator endpoint.
type Target struct {
	ID          string         // channel id (for logs/metrics)
	URL         string         // parent ingest endpoint, e.g. https://agg/ingest
	NodeID      string         // this node's id, stamped into Hops + the node header
	Token       string         // bearer auth (resolved from env by the caller)
	HMACSecret  []byte         // optional body signature
	MinSeverity event.Severity // skip events below this (0 = forward all)
	MaxBatch    int            // flush after this many events (default 500)
	MaxAge      time.Duration  // flush at least this often (default 2s)
	QueueSize   int            // in-memory buffer depth (default 4096)
	Timeout     time.Duration  // per-POST timeout (default 10s)
	// Mode selects the upward wire shape: "full" (default) ships every event;
	// "rollup" ships one periodic fleet:rollup summary (per-source/ASN/
	// fingerprint/rule counters + severity histogram) instead, keeping upward
	// volume sane at higher tiers while preserving the correlation keys.
	Mode           string
	RollupInterval time.Duration // rollup flush period (default 60s)
	Client         *http.Client  // nil = egress.HTTPClient(Timeout)
}

func (t *Target) withDefaults() {
	if t.MaxBatch <= 0 {
		t.MaxBatch = 500
	}
	if t.MaxAge <= 0 {
		t.MaxAge = 2 * time.Second
	}
	if t.QueueSize <= 0 {
		t.QueueSize = 4096
	}
	if t.Timeout <= 0 {
		t.Timeout = 10 * time.Second
	}
	if t.RollupInterval <= 0 {
		t.RollupInterval = 60 * time.Second
	}
	if t.Client == nil {
		t.Client = egress.HTTPClient(t.Timeout)
	}
}

// Forwarder batches and ships events to a single Target.
type Forwarder struct {
	t       Target
	in      chan *event.Event
	dropped atomic.Int64
	sent    atomic.Int64
	failed  atomic.Int64
}

// NewForwarder builds a forwarder for a target (fills in defaults).
func NewForwarder(t Target) *Forwarder {
	t.withDefaults()
	return &Forwarder{t: t, in: make(chan *event.Event, t.QueueSize)}
}

// ID returns the target id.
func (f *Forwarder) ID() string { return f.t.ID }

// Enqueue offers an event for forwarding; if it's below MinSeverity it is
// skipped, and if the queue is full it is dropped (counted) — back-pressure
// must never block the event bus.
func (f *Forwarder) Enqueue(ev *event.Event) {
	if f.t.MinSeverity != 0 && ev.Severity < f.t.MinSeverity {
		return
	}
	select {
	case f.in <- ev:
	default:
		f.dropped.Add(1)
	}
}

// Stats reports counters for the health monitor.
func (f *Forwarder) Stats() (sent, dropped, failed int64) {
	return f.sent.Load(), f.dropped.Load(), f.failed.Load()
}

// Run drains the queue, batching by size/age, until ctx is done (then it makes
// a final flush attempt). Blocking; run it in a goroutine. In rollup mode it
// instead accumulates a periodic summary (see runRollup).
func (f *Forwarder) Run(ctx context.Context) {
	if f.t.Mode == "rollup" {
		f.runRollup(ctx)
		return
	}
	ticker := time.NewTicker(f.t.MaxAge)
	defer ticker.Stop()
	var batch []*event.Event
	flush := func() {
		if len(batch) == 0 {
			return
		}
		b := batch
		batch = nil
		if err := f.send(ctx, b); err != nil {
			f.failed.Add(1)
			f.dropped.Add(int64(len(b)))
			slog.Warn("forward: batch dropped after retries", "target", f.t.ID, "events", len(b), "err", err)
			return
		}
		f.sent.Add(int64(len(b)))
	}
	for {
		select {
		case <-ctx.Done():
			drainInto(&batch, f.in)
			flush()
			return
		case ev := <-f.in:
			batch = append(batch, ev)
			if len(batch) >= f.t.MaxBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// drainInto pulls any immediately-available events from in into batch (used for
// a best-effort final flush on shutdown).
func drainInto(batch *[]*event.Event, in <-chan *event.Event) {
	for {
		select {
		case ev := <-in:
			*batch = append(*batch, ev)
		default:
			return
		}
	}
}

// send posts a batch, retrying a bounded number of times with backoff. The
// batch is kept intact across retries (at-least-once toward the parent, which
// dedups by sensor_id:id).
func (f *Forwarder) send(ctx context.Context, batch []*event.Event) error {
	body, err := EncodeBatch(batch, f.t.NodeID)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}
		if err := f.post(ctx, body, len(batch)); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

func (f *Forwarder) post(ctx context.Context, body []byte, n int) error {
	cctx, cancel := context.WithTimeout(ctx, f.t.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, f.t.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("User-Agent", "tarpit-honeypot-forward")
	req.Header.Set("X-Tarpit-Node", f.t.NodeID)
	req.Header.Set("X-Tarpit-Batch-Count", fmt.Sprintf("%d", n))
	if f.t.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.t.Token)
	}
	if len(f.t.HMACSecret) > 0 {
		req.Header.Set("X-Tarpit-Signature", "sha256="+SignBody(f.t.HMACSecret, body))
	}
	resp, err := f.t.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("forward %s: status %d", f.t.ID, resp.StatusCode)
	}
	return nil
}

// Group fans an event out to several forwarders.
type Group struct {
	fwds []*Forwarder
}

// NewGroup builds a fan-out group.
func NewGroup(fwds ...*Forwarder) *Group { return &Group{fwds: fwds} }

// Empty reports whether there are no targets.
func (g *Group) Empty() bool { return g == nil || len(g.fwds) == 0 }

// Run starts every forwarder; returns when ctx is done and all have flushed.
func (g *Group) Run(ctx context.Context) {
	if g == nil {
		return
	}
	var wg sync.WaitGroup
	for _, f := range g.fwds {
		f := f
		wg.Add(1)
		go func() { defer wg.Done(); f.Run(ctx) }()
	}
	wg.Wait()
}

// Send offers an event to every target.
func (g *Group) Send(ev *event.Event) {
	if g == nil {
		return
	}
	for _, f := range g.fwds {
		f.Enqueue(ev)
	}
}

// --- wire codec (shared with the aggregator ingest endpoint) ----------------

// EncodeBatch renders events as NDJSON, stamping nodeID into each event's Hops
// (on a copy, so the shared event the sinks see is untouched).
func EncodeBatch(evs []*event.Event, nodeID string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range evs {
		e := *ev // shallow copy
		if nodeID != "" {
			e.Hops = append(append([]string(nil), ev.Hops...), nodeID)
		}
		if err := enc.Encode(&e); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// DecodeBatch parses an NDJSON batch (the aggregator ingest side).
func DecodeBatch(r io.Reader) ([]*event.Event, error) {
	var out []*event.Event
	sc := bufio.NewScanner(r)
	// Cap each NDJSON line at 256 KiB. A real event with a 32 KiB captured
	// payload (the sensor's safe.AllocBytes cap) plus metadata is well under
	// this; the previous 8 MiB ceiling let a malicious sender pack near-maximum
	// events into a batch and pressure the aggregator's memory.
	sc.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return out, err
		}
		out = append(out, &ev)
	}
	return out, sc.Err()
}

// SignBody returns the hex HMAC-SHA256 of body under secret.
func SignBody(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks an "sha256=<hex>" header value against body (the
// aggregator ingest side). Constant-time.
func VerifySignature(secret []byte, body []byte, header string) bool {
	const pfx = "sha256="
	if len(header) <= len(pfx) || header[:len(pfx)] != pfx {
		return false
	}
	want, err := hex.DecodeString(header[len(pfx):])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(want, mac.Sum(nil))
}
