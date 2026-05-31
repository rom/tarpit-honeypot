package listener

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/tarpit-honeypot/internal/capture"
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

// runTarpitWithCapture is the capture-aware entry point. The connection
// has already been wrapped in a capture.Conn by handle() when sess != nil.
func (t *tcpListener) runTarpitWithCapture(ctx context.Context, conn net.Conn, bus chan<- *event.Event, startTime time.Time, src, dst event.Endpoint, sess *capture.Session) {
	t.runTarpit(ctx, conn, bus, startTime, src, dst, sess)
}

// runTarpit holds the connection per the configured strategy until ctx
// cancels or the remote disconnects.
// It emits a "tarpit_end" event with duration metadata on completion.
func (t *tcpListener) runTarpit(ctx context.Context, conn net.Conn, bus chan<- *event.Event, startTime time.Time, src, dst event.Endpoint, sess *capture.Session) {
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
	case "jitter":
		err = tarpitJitter(ctx, conn, tcfg.Jitter.Text, tcfg.Jitter.MinInterval, tcfg.Jitter.MaxInterval)
	case "backoff":
		err = tarpitBackoff(ctx, conn, tcfg.Backoff.Text, tcfg.Backoff.Start, tcfg.Backoff.Max, tcfg.Backoff.Factor)
	case "ssh_banner":
		err = tarpitSSHBanner(ctx, conn, tcfg.SSHBanner.LineInterval, tcfg.SSHBanner.MaxLineBytes)
	case "http_headers":
		err = tarpitHTTPHeaders(ctx, conn, tcfg.HTTP.StatusLine, tcfg.HTTP.HeaderInterval)
	case "http_chunked":
		err = tarpitHTTPChunked(ctx, conn, tcfg.HTTP.StatusLine, tcfg.HTTP.ChunkText, tcfg.HTTP.ChunkInterval)
	case "echo":
		err = tarpitEcho(ctx, conn, tcfg.Echo.ByteInterval)
	case "babble":
		err = tarpitBabble(ctx, conn, tcfg.Babble.ByteInterval)
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
	if sess != nil {
		if path, truncated, serr := sess.End(); serr == nil && path != "" {
			endEv.Meta["capture_path"] = path
			if truncated {
				endEv.Meta["capture_truncated"] = true
			}
		}
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

// sleepCtx waits for d or until ctx is cancelled, returning ctx.Err() in the
// latter case. Strategies with a variable (non-fixed) cadence use this instead
// of a time.Ticker so the interval can change between writes.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// tarpitJitter is trickle with a randomized interval drawn from [min,max] on
// every byte. Defeats scanners that fingerprint (or time out on) the perfectly
// regular cadence of plain trickle.
func tarpitJitter(ctx context.Context, conn net.Conn, text string, min, max time.Duration) error {
	if text == "" {
		text = "Loading...\r\n"
	}
	if min <= 0 {
		min = 500 * time.Millisecond
	}
	if max <= min {
		max = min + 4*time.Second
	}
	idx := 0
	for {
		d := min + time.Duration(rand.Int63n(int64(max-min)+1))
		if err := sleepCtx(ctx, d); err != nil {
			return err
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte{text[idx%len(text)]}); err != nil {
			return err
		}
		idx++
	}
}

// tarpitBackoff is trickle whose interval starts at start and is multiplied by
// factor after each byte, capped at max. The connection feels responsive at
// first so the scanner commits, then degrades — punishing the patient ones.
func tarpitBackoff(ctx context.Context, conn net.Conn, text string, start, max time.Duration, factor float64) error {
	if text == "" {
		text = "Loading...\r\n"
	}
	if start <= 0 {
		start = 500 * time.Millisecond
	}
	if max <= 0 {
		max = 60 * time.Second
	}
	if factor < 1 {
		factor = 2
	}
	idx := 0
	d := start
	for {
		if err := sleepCtx(ctx, d); err != nil {
			return err
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte{text[idx%len(text)]}); err != nil {
			return err
		}
		idx++
		d = time.Duration(float64(d) * factor)
		if d > max {
			d = max
		}
	}
}

// tarpitSSHBanner emulates the endlessh technique: RFC 4253 §4.2 lets an SSH
// server send arbitrary lines (that do NOT begin with "SSH-") before its real
// identification string, and clients must keep reading them. We drip an endless
// stream of such lines, so a connecting SSH client hangs forever waiting for an
// identification string that never arrives. Pairs naturally with mode handlers
// or with tarpit.emulate for a service that looks alive before it stalls.
func tarpitSSHBanner(ctx context.Context, conn net.Conn, lineInterval time.Duration, maxLineBytes int) error {
	if lineInterval <= 0 {
		lineInterval = 2 * time.Second
	}
	if maxLineBytes <= 0 {
		maxLineBytes = 32
	}
	for {
		if err := sleepCtx(ctx, lineInterval); err != nil {
			return err
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(randomSSHLine(maxLineBytes)); err != nil {
			return err
		}
	}
}

// tarpitHTTPHeaders sends a status line then drips an endless run of valid
// response headers, never the terminating blank line. An HTTP client waits for
// the headers to finish (and the body that follows) forever — the inverse of a
// Slowloris: here the server is the slow one.
func tarpitHTTPHeaders(ctx context.Context, conn net.Conn, statusLine string, interval time.Duration) error {
	if statusLine == "" {
		statusLine = "HTTP/1.1 200 OK"
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(statusLine + "\r\n")); err != nil {
		return err
	}
	for {
		if err := sleepCtx(ctx, interval); err != nil {
			return err
		}
		hdr := fmt.Sprintf("X-%s: %s\r\n", randToken(8), randToken(16))
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(hdr)); err != nil {
			return err
		}
	}
}

// tarpitHTTPChunked completes the response head with Transfer-Encoding: chunked
// then emits one-byte chunks forever, never the terminating zero-length chunk.
// The client believes a large body is still streaming in.
func tarpitHTTPChunked(ctx context.Context, conn net.Conn, statusLine, chunkText string, interval time.Duration) error {
	if statusLine == "" {
		statusLine = "HTTP/1.1 200 OK"
	}
	if chunkText == "" {
		chunkText = "."
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	head := statusLine + "\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n"
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(head)); err != nil {
		return err
	}
	idx := 0
	for {
		if err := sleepCtx(ctx, interval); err != nil {
			return err
		}
		// One-byte chunk: "1\r\n<byte>\r\n".
		chunk := fmt.Sprintf("1\r\n%c\r\n", chunkText[idx%len(chunkText)])
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(chunk)); err != nil {
			return err
		}
		idx++
	}
}

// tarpitEcho reads whatever the attacker sends and dribbles it back one byte at
// a time after a per-byte delay. An interactive client (someone poking at a
// fake shell) keeps engaging, which yields more captured input than a silent
// hold while still wasting their time.
func tarpitEcho(ctx context.Context, conn net.Conn, interval time.Duration) error {
	if interval <= 0 {
		interval = 1 * time.Second
	}
	buf := make([]byte, 256)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		for i := 0; i < n; i++ {
			if err := sleepCtx(ctx, interval); err != nil {
				return err
			}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, werr := conn.Write(buf[i : i+1]); werr != nil {
				return werr
			}
		}
	}
}

// tarpitBabble trickles an endless stream of generated, plausible-looking
// printable text (rather than cycling a fixed string like trickle). It keeps
// content-grabbers reading and pollutes whatever they capture with junk.
func tarpitBabble(ctx context.Context, conn net.Conn, interval time.Duration) error {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	for {
		if err := sleepCtx(ctx, interval); err != nil {
			return err
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte{babbleByte()}); err != nil {
			return err
		}
	}
}

const tokenAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// randToken returns n random alphanumeric characters.
func randToken(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = tokenAlphabet[rand.Intn(len(tokenAlphabet))]
	}
	return string(b)
}

// babbleByte returns a random printable ASCII byte (space..~), biased toward a
// trailing newline occasionally so the output reads like wrapped log lines.
func babbleByte() byte {
	if rand.Intn(48) == 0 {
		return '\n'
	}
	return byte(32 + rand.Intn(95)) // printable ASCII range
}

// randomSSHLine builds one endlessh-style preamble line: a random run of
// printable bytes (never beginning with the literal "SSH-", which would be
// parsed as the real identification string) terminated with CRLF.
func randomSSHLine(maxLineBytes int) []byte {
	n := 1 + rand.Intn(maxLineBytes)
	line := make([]byte, 0, n+2)
	for i := 0; i < n; i++ {
		line = append(line, byte(32+rand.Intn(95)))
	}
	// Guard against accidentally emitting the identification prefix.
	if len(line) >= 4 && string(line[:4]) == "SSH-" {
		line[0] = 'x'
	}
	return append(line, '\r', '\n')
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
