package listener

import (
	"net"
	"sync/atomic"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// countConn wraps a net.Conn to tally total bytes transferred and the number of
// read/write operations in each direction. Unlike the pcap capture wrapper —
// which is opt-in (capture: true) and byte-capped per session, so it is
// unsuitable for traffic accounting — countConn is applied to every accepted
// connection and counts the full, uncapped volume. Counting is lock-free via
// atomics so it adds negligible overhead to the connection hot path.
//
// Because the honeypot captures from inside the application goroutine rather
// than a raw socket (no CAP_NET_RAW), an "operation" is one application-layer
// Read/Write — a TCP segment as the app sees it. We use that as the packet-rate
// proxy: it tracks the on-wire packet count closely but is not guaranteed to
// equal it (the kernel may coalesce or split segments).
type countConn struct {
	net.Conn
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
	opsIn    atomic.Int64
	opsOut   atomic.Int64
}

func newCountConn(c net.Conn) *countConn { return &countConn{Conn: c} }

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.bytesIn.Add(int64(n))
		c.opsIn.Add(1)
	}
	return n, err
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.bytesOut.Add(int64(n))
		c.opsOut.Add(1)
	}
	return n, err
}

// NetConn exposes the wrapped connection so unwrappers (e.g. the zero-window
// tarpit reaching for the underlying *net.TCPConn) can see through the counter.
func (c *countConn) NetConn() net.Conn { return c.Conn }

// stamp records the tallied byte/packet counts onto the event meta so the UI
// can derive incoming/outgoing throughput and packet-rate over time. It is a
// no-op when nothing was transferred (e.g. a drop-mode connection) so we don't
// pad every such event with zero-valued keys.
func (c *countConn) stamp(ev *event.Event) {
	if c == nil || ev == nil {
		return
	}
	bi, bo := c.bytesIn.Load(), c.bytesOut.Load()
	pi, po := c.opsIn.Load(), c.opsOut.Load()
	if bi == 0 && bo == 0 && pi == 0 && po == 0 {
		return
	}
	if ev.Meta == nil {
		ev.Meta = map[string]any{}
	}
	ev.Meta["bytes_in"] = bi
	ev.Meta["bytes_out"] = bo
	ev.Meta["pkts_in"] = pi
	ev.Meta["pkts_out"] = po
}
