package listener

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/listener/handler"
)

// fakeSessionHandler reads two datagrams from the session, replies once, and
// reports what it saw via meta — exercising the connection-oriented UDP path.
type fakeSessionHandler struct{ got [][]byte }

func (f *fakeSessionHandler) Name() string { return "udp-session-test" }

func (f *fakeSessionHandler) Handle(ctx context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (handler.Result, error) {
	return handler.Result{Meta: map[string]any{"stateless": true}}, nil
}

func (f *fakeSessionHandler) HandleSession(ctx context.Context, s *handler.UDPSession, cfg config.Listener) (handler.Result, error) {
	for i := 0; i < 2; i++ {
		b, err := s.Read(ctx, 2*time.Second)
		if err != nil {
			break
		}
		f.got = append(f.got, append([]byte(nil), b...))
	}
	_, _ = s.Write([]byte("ack"))
	return handler.Result{BannerSent: "ack", Meta: map[string]any{"datagrams": len(f.got)}}, nil
}

func TestUDPSessionMultiDatagram(t *testing.T) {
	fh := &fakeSessionHandler{}
	u := &udpListener{cfg: config.Listener{ID: "t", Handler: "udp-session-test", Mode: "banner", UDPSession: true}}
	bus := make(chan *event.Event, 1)
	pc := &capPacketConn{}
	raddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 5000}
	base := &event.Event{ID: "e1", Source: event.Endpoint{IP: "203.0.113.9", Port: 5000}, Handler: "udp-session-test"}

	// First datagram creates the session; second is delivered to it.
	if !u.routeToSession(context.Background(), pc, raddr, []byte("hello"), base, bus, fh) {
		t.Fatal("first routeToSession returned false")
	}
	if !u.routeToSession(context.Background(), pc, raddr, []byte("world"), base, bus, fh) {
		t.Fatal("second routeToSession returned false")
	}

	select {
	case ev := <-bus:
		if ev.BannerSent != "ack" {
			t.Errorf("banner = %q; want ack", ev.BannerSent)
		}
		if n, _ := ev.Meta["datagrams"].(int); n != 2 {
			t.Errorf("session saw %v datagrams; want 2 (got=%v)", ev.Meta["datagrams"], fh.got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no event emitted by the session")
	}
	if got := pc.written(); got != "ack" {
		t.Errorf("reply written to source = %q; want ack", got)
	}
}

// capPacketConn is a minimal net.PacketConn that records WriteTo payloads.
type capPacketConn struct {
	mu  sync.Mutex
	buf []byte
}

func (c *capPacketConn) written() string { c.mu.Lock(); defer c.mu.Unlock(); return string(c.buf) }
func (c *capPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	c.buf = append(c.buf, b...)
	c.mu.Unlock()
	return len(b), nil
}
func (c *capPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *capPacketConn) Close() error                           { return nil }
func (c *capPacketConn) LocalAddr() net.Addr                    { return &net.UDPAddr{Port: 161} }
func (c *capPacketConn) SetDeadline(time.Time) error            { return nil }
func (c *capPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (c *capPacketConn) SetWriteDeadline(time.Time) error       { return nil }
