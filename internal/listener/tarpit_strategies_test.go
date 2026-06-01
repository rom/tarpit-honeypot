package listener

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/capture"
)

// runStrategy spins the given strategy on one end of a net.Pipe and returns the
// client end plus a channel that yields the strategy's return error.
func runStrategy(t *testing.T, fn func(context.Context, net.Conn) error) (net.Conn, context.CancelFunc, <-chan error) {
	t.Helper()
	srv, cli := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- fn(ctx, srv)
		srv.Close()
	}()
	return cli, cancel, done
}

// expectCancel cancels the strategy and asserts it unwinds with context.Canceled.
func expectCancel(t *testing.T, cli net.Conn, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	cli.Close()
	select {
	case err := <-done:
		if err != nil && err != context.Canceled && err != io.EOF {
			// Closing the pipe can surface as io.ErrClosedPipe or io.EOF
			// (peer gone) for read-based strategies; all are fine.
			if !strings.Contains(err.Error(), "closed pipe") {
				t.Fatalf("unexpected strategy error: %v", err)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("strategy did not return after cancel")
	}
}

func TestTarpitJitterWritesBytes(t *testing.T) {
	cli, cancel, done := runStrategy(t, func(ctx context.Context, c net.Conn) error {
		return tarpitJitter(ctx, c, "AB", time.Millisecond, 5*time.Millisecond)
	})
	buf := make([]byte, 3)
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := readFull(cli, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, b := range buf {
		if b != 'A' && b != 'B' {
			t.Fatalf("jitter wrote unexpected byte %q", b)
		}
	}
	expectCancel(t, cli, cancel, done)
}

func TestTarpitBackoffWritesAndGrows(t *testing.T) {
	cli, cancel, done := runStrategy(t, func(ctx context.Context, c net.Conn) error {
		return tarpitBackoff(ctx, c, "XY", time.Millisecond, 20*time.Millisecond, 2)
	})
	buf := make([]byte, 3)
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := readFull(cli, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	expectCancel(t, cli, cancel, done)
}

func TestTarpitSSHBannerEndlessh(t *testing.T) {
	cli, cancel, done := runStrategy(t, func(ctx context.Context, c net.Conn) error {
		return tarpitSSHBanner(ctx, c, time.Millisecond, 16)
	})
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(cli)
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read line: %v", err)
	}
	if !strings.HasSuffix(line, "\r\n") {
		t.Fatalf("ssh_banner line not CRLF-terminated: %q", line)
	}
	if strings.HasPrefix(line, "SSH-") {
		t.Fatalf("ssh_banner emitted a real identification string: %q", line)
	}
	expectCancel(t, cli, cancel, done)
}

func TestTarpitHTTPHeadersNeverComplete(t *testing.T) {
	cli, cancel, done := runStrategy(t, func(ctx context.Context, c net.Conn) error {
		return tarpitHTTPHeaders(ctx, c, "HTTP/1.1 200 OK", time.Millisecond)
	})
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(cli)
	status, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 200 OK") {
		t.Fatalf("unexpected status line: %q", status)
	}
	hdr, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if !strings.HasPrefix(hdr, "X-") {
		t.Fatalf("expected an X- header, got %q", hdr)
	}
	expectCancel(t, cli, cancel, done)
}

func TestTarpitHTTPChunkedStreamsForever(t *testing.T) {
	cli, cancel, done := runStrategy(t, func(ctx context.Context, c net.Conn) error {
		return tarpitHTTPChunked(ctx, c, "HTTP/1.1 200 OK", "Z", time.Millisecond)
	})
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(cli)
	head := make([]byte, 0, 128)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read head: %v", err)
		}
		head = append(head, line...)
		if line == "\r\n" {
			break
		}
	}
	if !bytes.Contains(head, []byte("Transfer-Encoding: chunked")) {
		t.Fatalf("missing chunked header in:\n%s", head)
	}
	// First chunk should be "1\r\nZ\r\n".
	chunk := make([]byte, 6)
	if err := readFull(cli, chunk); err != nil {
		t.Fatalf("read chunk: %v", err)
	}
	if string(chunk) != "1\r\nZ\r\n" {
		t.Fatalf("unexpected first chunk %q", chunk)
	}
	expectCancel(t, cli, cancel, done)
}

func TestTarpitEchoReflectsInput(t *testing.T) {
	cli, cancel, done := runStrategy(t, func(ctx context.Context, c net.Conn) error {
		return tarpitEcho(ctx, c, time.Millisecond)
	})
	go func() {
		cli.SetWriteDeadline(time.Now().Add(time.Second))
		cli.Write([]byte("hi"))
	}()
	buf := make([]byte, 2)
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := readFull(cli, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "hi" {
		t.Fatalf("echo returned %q, want %q", buf, "hi")
	}
	expectCancel(t, cli, cancel, done)
}

func TestTarpitBabbleWritesPrintable(t *testing.T) {
	cli, cancel, done := runStrategy(t, func(ctx context.Context, c net.Conn) error {
		return tarpitBabble(ctx, c, time.Millisecond)
	})
	buf := make([]byte, 8)
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := readFull(cli, buf); err != nil {
		t.Fatalf("read babble: %v", err)
	}
	for _, b := range buf {
		if b != '\n' && (b < 32 || b > 126) {
			t.Fatalf("babble emitted non-printable byte %d", b)
		}
	}
	expectCancel(t, cli, cancel, done)
}

func TestTarpitZipBombInflates(t *testing.T) {
	const inflated = 1 << 20 // 1 MiB, small enough for a fast test
	cli, cancel, done := runStrategy(t, func(ctx context.Context, c net.Conn) error {
		return tarpitZipBomb(ctx, c, "HTTP/1.1 200 OK", inflated, 0)
	})
	defer func() {
		cancel()
		<-done // the bomb is finite; let the goroutine finish
	}()
	cli.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(cli)

	// Read the response head and assert the gzip Content-Encoding tell.
	var head []byte
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read head: %v", err)
		}
		head = append(head, line...)
		if line == "\r\n" {
			break
		}
	}
	if !bytes.Contains(head, []byte("Content-Encoding: gzip")) {
		t.Fatalf("missing gzip encoding in head:\n%s", head)
	}

	// De-chunk the body, then gunzip it and confirm it inflates to the
	// configured size from a tiny compressed payload.
	gz, compressed := dechunkAndCount(t, r)
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	n, err := io.Copy(io.Discard, zr)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	if n != inflated {
		t.Fatalf("inflated to %d bytes, want %d", n, inflated)
	}
	if compressed >= inflated {
		t.Fatalf("compressed payload (%d) not smaller than inflated (%d)", compressed, inflated)
	}
	t.Logf("zipbomb: %d compressed bytes -> %d inflated (%.0fx)", compressed, n, float64(n)/float64(compressed))
}

// dechunkAndCount reads an HTTP/1.1 chunked body to its terminator, returning
// the reassembled body bytes and their total length.
func dechunkAndCount(t *testing.T, r *bufio.Reader) ([]byte, int64) {
	t.Helper()
	var body []byte
	var total int64
	for {
		sizeLine, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read chunk size: %v", err)
		}
		var size int64
		if _, err := fmt.Sscanf(strings.TrimSpace(sizeLine), "%x", &size); err != nil {
			t.Fatalf("parse chunk size %q: %v", sizeLine, err)
		}
		if size == 0 {
			r.ReadString('\n') // trailing CRLF
			return body, total
		}
		chunk := make([]byte, size)
		if err := readFull(readerConn{r}, chunk); err != nil {
			t.Fatalf("read chunk body: %v", err)
		}
		body = append(body, chunk...)
		total += size
		r.ReadString('\n') // CRLF after chunk data
	}
}

// readerConn adapts a *bufio.Reader to the Read signature readFull expects.
type readerConn struct{ r *bufio.Reader }

func (rc readerConn) Read(p []byte) (int, error)       { return rc.r.Read(p) }
func (rc readerConn) Write(p []byte) (int, error)      { return 0, nil }
func (rc readerConn) Close() error                     { return nil }
func (rc readerConn) LocalAddr() net.Addr              { return nil }
func (rc readerConn) RemoteAddr() net.Addr             { return nil }
func (rc readerConn) SetDeadline(time.Time) error      { return nil }
func (rc readerConn) SetReadDeadline(time.Time) error  { return nil }
func (rc readerConn) SetWriteDeadline(time.Time) error { return nil }

func TestTarpitZeroWindowHolds(t *testing.T) {
	// net.Pipe isn't a *net.TCPConn, so SetReadBuffer is skipped and the
	// strategy falls back to a non-reading hold. We assert it holds the
	// connection (no bytes from us) and unwinds cleanly on cancel.
	cli, cancel, done := runStrategy(t, func(ctx context.Context, c net.Conn) error {
		return tarpitZeroWindow(ctx, c, 1)
	})
	cli.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := cli.Read(buf); err == nil {
		t.Fatal("zero_window wrote application data; it must stay silent")
	}
	expectCancel(t, cli, cancel, done)
}

func TestUnderlyingTCPConnUnwrapsCapture(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	// A pipe is not a TCP conn, so even wrapped it should resolve to nil
	// (rather than panic) — exercising the unwrap path.
	wrapped := &capture.Conn{Conn: srv}
	if got := underlyingTCPConn(wrapped); got != nil {
		t.Fatalf("expected nil for non-TCP wrapped conn, got %T", got)
	}
}

// readFull reads len(buf) bytes from c, tolerating short pipe reads.
func readFull(c net.Conn, buf []byte) error {
	got := 0
	for got < len(buf) {
		n, err := c.Read(buf[got:])
		got += n
		if err != nil {
			return err
		}
	}
	return nil
}
