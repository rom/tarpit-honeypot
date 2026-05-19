package listener

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// tarpitState tracks open tarpit connections per listener so we can enforce
// the per-source and per-total caps without leaking goroutines.
type tarpitState struct {
	total     atomic.Int64
	mu        sync.Mutex
	perSource map[string]int
}

func newTarpitState() *tarpitState {
	return &tarpitState{perSource: map[string]int{}}
}

func (s *tarpitState) tryAcquire(srcIP string, maxPerSource, maxTotal int) bool {
	if maxTotal > 0 && s.total.Load() >= int64(maxTotal) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if maxPerSource > 0 && s.perSource[srcIP] >= maxPerSource {
		return false
	}
	s.perSource[srcIP]++
	s.total.Add(1)
	return true
}

func (s *tarpitState) release(srcIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.perSource[srcIP]; ok {
		if n <= 1 {
			delete(s.perSource, srcIP)
		} else {
			s.perSource[srcIP] = n - 1
		}
	}
	s.total.Add(-1)
}

// runTarpit holds the connection per the configured strategy until ctx
// cancels or the remote disconnects.
// It emits a "tarpit_end" event with duration metadata on completion.
func (t *tcpListener) runTarpit(ctx context.Context, conn net.Conn, bus chan<- *event.Event, startTime time.Time, src, dst event.Endpoint) {
	defer conn.Close()
	defer t.tarpit.release(src.IP)

	tcfg := t.cfg.Tarpit

	// Optimistic: enable TCP keepalive so OS notices dead peers.
	if c, ok := conn.(*net.TCPConn); ok {
		_ = c.SetKeepAlive(true)
		_ = c.SetKeepAlivePeriod(30 * time.Second)
	}

	var err error
	switch tcfg.Strategy {
	case "sticky":
		err = tarpitSticky(ctx, conn)
	case "trickle":
		err = tarpitTrickle(ctx, conn, tcfg.Trickle.Text, tcfg.Trickle.ByteInterval)
	case "keepalive":
		err = tarpitKeepalive(ctx, conn, tcfg.Keepalive.Interval)
	default:
		err = errors.New("unknown tarpit strategy")
	}

	dur := time.Since(startTime)
	endSev := event.SeverityLow
	if t.sev > endSev {
		endSev = event.SeverityLow // intentionally low: the start event already alerted
	}
	endEv := &event.Event{
		ID:       event.NewID(),
		Time:     time.Now().UTC(),
		Sensor:   t.sensorName,
		RuleID:   "listener:" + t.cfg.ID + ":tarpit_end",
		Severity: endSev,
		Source:   src,
		Dest:     dst,
		Proto:    "tcp",
		Handler:  t.cfg.Handler,
		Meta: map[string]any{
			"tarpit_strategy": tcfg.Strategy,
			"duration_ms":     dur.Milliseconds(),
		},
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		endEv.Meta["end_reason"] = err.Error()
	}
	select {
	case bus <- endEv:
	case <-ctx.Done():
	}
}

// tarpitSticky accepts and holds the connection open without ever reading
// or writing application data. The kernel's TCP keepalive (enabled by the
// caller) will eventually detect a dead peer.
func tarpitSticky(ctx context.Context, conn net.Conn) error {
	// Poll a tiny read with a long deadline; if it errors with anything other
	// than a timeout, the peer is gone.
	buf := make([]byte, 1)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			continue // drain any client data, keep the connection open
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
	}
}

// tarpitTrickle writes one byte of text every interval, cycling forever.
func tarpitTrickle(ctx context.Context, conn net.Conn, text string, interval time.Duration) error {
	if text == "" {
		text = "Loading...\r\n"
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	idx := 0
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte{text[idx%len(text)]}); err != nil {
				return err
			}
			idx++
		}
	}
}

// tarpitKeepalive writes a NUL byte every interval to keep the socket warm.
// Cheap, no payload of interest, mostly soaks up scanner concurrency.
func tarpitKeepalive(ctx context.Context, conn net.Conn, interval time.Duration) error {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte{0}); err != nil {
				return err
			}
		}
	}
}

// dropTarpitOverflow records an event when the tarpit state refused a new
// connection so the operator can see the cap was hit.
func (t *tcpListener) emitTarpitDrop(ctx context.Context, bus chan<- *event.Event, src, dst event.Endpoint) {
	ev := &event.Event{
		ID:       event.NewID(),
		Time:     time.Now().UTC(),
		Sensor:   t.sensorName,
		RuleID:   "listener:" + t.cfg.ID + ":tarpit_drop",
		Severity: event.SeverityLow,
		Source:   src,
		Dest:     dst,
		Proto:    "tcp",
		Handler:  t.cfg.Handler,
		Meta: map[string]any{
			"tarpit_strategy": t.cfg.Tarpit.Strategy,
			"reason":          "cap_exceeded",
		},
	}
	select {
	case bus <- ev:
	case <-ctx.Done():
	}
	slog.Debug("tarpit cap hit", "listener", t.cfg.ID, "src", src.IP)
}

// configLimits used by tcp.go when constructing the listener.
func tarpitLimits(c config.Listener) (perSource, total int) {
	return c.Tarpit.MaxPerSource, c.Tarpit.MaxTotal
}
