package handler

import (
	"context"
	"net"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// UDPSession is a per-source, multi-datagram UDP session handed to a
// UDPSessionHandler. Unlike the stateless UDPHandler path (one datagram → one
// Handle call), a session lets a handler that needs several round-trips — a
// QUIC/DTLS handshake, TFTP's RRQ→DATA→ACK exchange, a multi-packet discovery
// dialogue — read successive datagrams from the same source and reply to them.
//
// The listener owns the socket and demultiplexes inbound datagrams to the right
// session by source address; the handler only sees Read (next datagram) and
// Write (reply to this source). Everything is bounded: Read takes a per-call
// timeout and honours ctx, and the listener caps concurrent sessions.
type UDPSession struct {
	Src net.Addr       // the remote source this session belongs to
	pc  net.PacketConn // the (reply-gated) socket to answer on
	in  chan []byte    // inbound datagrams the listener delivers
}

// NewUDPSession is called by the listener to create a session for one source.
// buffer bounds how many undelivered inbound datagrams queue before drops.
func NewUDPSession(src net.Addr, pc net.PacketConn, buffer int) *UDPSession {
	if buffer <= 0 {
		buffer = 32
	}
	return &UDPSession{Src: src, pc: pc, in: make(chan []byte, buffer)}
}

// Deliver hands an inbound datagram to the session; reports false (dropped) if
// the session's queue is full, so a flooding source can't grow memory.
func (s *UDPSession) Deliver(b []byte) bool {
	select {
	case s.in <- b:
		return true
	default:
		return false
	}
}

// Close releases the session; a subsequent Read returns net.ErrClosed.
func (s *UDPSession) Close() { close(s.in) }

// Read returns the next datagram from this source, blocking up to timeout (and
// honouring ctx). It returns os.ErrDeadlineExceeded on timeout and
// net.ErrClosed when the session has been closed by the listener.
func (s *UDPSession) Read(ctx context.Context, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case b, ok := <-s.in:
		if !ok {
			return nil, net.ErrClosed
		}
		return b, nil
	case <-t.C:
		return nil, timeoutErr{}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Write sends a reply datagram back to the session's source. The pc is the
// listener's reply-gated socket, so muted reply-policies drop the write.
func (s *UDPSession) Write(b []byte) (int, error) {
	if pw, ok := s.pc.(interface {
		WriteTo([]byte, net.Addr) (int, error)
	}); ok {
		return pw.WriteTo(b, s.Src)
	}
	return len(b), nil
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "udp session read timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// UDPSessionHandler is the optional interface a UDP handler implements when it
// needs multi-datagram state. The listener routes to HandleSession (instead of
// the per-datagram Handle) only when the listener has udp_session enabled AND
// the handler implements this interface; otherwise the stateless Handle path is
// used unchanged. Implementers must still satisfy UDPHandler so the stateless
// path remains available as a fallback (e.g. when the session table is full).
type UDPSessionHandler interface {
	UDPHandler
	HandleSession(ctx context.Context, sess *UDPSession, cfg config.Listener) (Result, error)
}
