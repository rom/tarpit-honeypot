package listener

import (
	"io"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// countConn must tally the full, uncapped byte volume and the read/write op
// count in each direction, and stamp them onto the event meta.
func TestCountConnTalliesAndStamps(t *testing.T) {
	cli, srv := net.Pipe()
	cc := newCountConn(srv)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Client sends 11 bytes in two writes, then reads the 5-byte reply.
		_, _ = cli.Write([]byte("hello"))
		_, _ = cli.Write([]byte(" world"))
		buf := make([]byte, 5)
		_, _ = io.ReadFull(cli, buf)
		_ = cli.Close()
	}()

	// Server (the counted side) reads the 11 bytes, then writes a 5-byte reply.
	in := make([]byte, 11)
	if _, err := io.ReadFull(cc, in); err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := cc.Write([]byte("ahoy!")); err != nil {
		t.Fatalf("write: %v", err)
	}
	<-done

	if got := cc.bytesIn.Load(); got != 11 {
		t.Errorf("bytesIn = %d, want 11", got)
	}
	if got := cc.bytesOut.Load(); got != 5 {
		t.Errorf("bytesOut = %d, want 5", got)
	}
	if got := cc.opsOut.Load(); got != 1 {
		t.Errorf("opsOut = %d, want 1", got)
	}
	if got := cc.opsIn.Load(); got < 1 {
		t.Errorf("opsIn = %d, want >= 1", got)
	}

	ev := &event.Event{}
	cc.stamp(ev)
	if ev.Meta["bytes_in"] != int64(11) || ev.Meta["bytes_out"] != int64(5) {
		t.Errorf("stamp bytes wrong: %+v", ev.Meta)
	}
	if ev.Meta["pkts_out"] != int64(1) {
		t.Errorf("stamp pkts_out wrong: %+v", ev.Meta)
	}

	// NetConn unwraps to the wrapped conn so tarpit strategies can reach the
	// underlying socket through the counter.
	if cc.NetConn() != srv {
		t.Error("NetConn should expose the wrapped conn")
	}
}

// A connection that transfers nothing must not pad the event with zero keys.
func TestCountConnStampNoopWhenIdle(t *testing.T) {
	_, srv := net.Pipe()
	cc := newCountConn(srv)
	ev := &event.Event{}
	cc.stamp(ev)
	if _, ok := ev.Meta["bytes_in"]; ok {
		t.Errorf("idle connection should not stamp traffic meta: %+v", ev.Meta)
	}
}
