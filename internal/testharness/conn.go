package testharness

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const maxRead = 1 << 20 // cap a single exchange's captured bytes

// exchange writes send (if non-nil) and reads the reply, concurrently so that
// server-speaks-first protocols and synchronous in-memory pipes don't
// deadlock. A read deadline is expected (we read until the peer pauses), so a
// timeout with data is success. Returns the bytes read and any non-timeout,
// non-EOF I/O error.
func exchange(conn net.Conn, send []byte, timeout time.Duration) ([]byte, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var wg sync.WaitGroup
	if send != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = conn.Write(send)
		}()
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	var readErr error
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) >= maxRead {
				break
			}
		}
		if err != nil {
			readErr = err
			break
		}
	}
	wg.Wait()
	var ne net.Error
	if errors.As(readErr, &ne) && ne.Timeout() {
		readErr = nil // a read deadline is how we know the peer paused
	}
	if errors.Is(readErr, io.EOF) || errors.Is(readErr, net.ErrClosed) {
		readErr = nil // a clean close after the reply is normal end-of-stream
	}
	return buf, readErr
}

// probe dials an endpoint, performs one exchange, and closes the connection.
func probe(ctx context.Context, t *Target, e Endpoint, send []byte) ([]byte, error) {
	conn, err := t.Dial(ctx, e)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return exchange(conn, send, t.cfg.Timeout)
}

// tcpConnect reports whether a TCP port accepts a connection (a scan probe).
func tcpConnect(ctx context.Context, host string, port int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, itoa(port)))
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [11]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
