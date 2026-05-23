package tcpstack

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

// Responder supplies the decoy's application-layer bytes. Either field may
// be nil: a nil Banner means the port is client-speaks-first (no greeting),
// a nil Respond means the decoy accepts data but never answers it. A wholly
// zero Responder turns every open port into accept-then-silence.
type Responder struct {
	// Banner returns server-speaks-first greeting bytes for (host, port)
	// right after the handshake completes (SSH/FTP/SMTP), or nil.
	Banner func(dst [4]byte, port uint16) []byte
	// Respond returns the reply to a client request, or nil to stay
	// silent. The decoy answers one request then closes the flow.
	Respond func(dst [4]byte, port uint16, req []byte) []byte
}

// EventKind enumerates the notable things the stack surfaces to the host
// (mapped onto the sensor event bus by the tunnet adapter).
type EventKind string

const (
	// EventHandshake is a SYN to an open port that we answered — a
	// completed connection attempt against a virtual host.
	EventHandshake EventKind = "handshake"
	// EventRequest carries captured client payload bytes.
	EventRequest EventKind = "request"
	// EventMalformed is an illegal / corrupt packet (see Markers).
	EventMalformed EventKind = "malformed"
)

// Event is a stack-level notification, deliberately decoupled from
// internal/event so this package stays dependency-free and unit-testable.
type Event struct {
	Kind    EventKind
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	Markers []string // populated for EventMalformed
	Payload []byte   // captured request bytes for EventRequest
	Raw     []byte   // the raw inbound packet (EventMalformed forensics)
}

// Result is the outcome of feeding one packet to the stack: packets to
// write back to the TUN and events to publish. Either may be empty.
type Result struct {
	Out    [][]byte
	Events []Event
}

// Config parameterizes a Stack. The Profile/Open callbacks make a single
// Stack serve every virtual host on a TUN; the test-only Now/ISN hooks
// make handshakes deterministic.
type Config struct {
	// Profile returns the OS fingerprint for a destination host IP
	// (nil -> always the Linux profile).
	Profile func(dst [4]byte) OSProfile
	// Open reports whether (host, port) accepts connections
	// (nil -> no open ports, i.e. RST-only like the legacy responder).
	Open func(dst [4]byte, port uint16) bool
	// Responder supplies banner/response bytes (zero value -> silent).
	Responder Responder
	// Now and ISN are injectable for deterministic tests.
	Now func() time.Time
	ISN func() uint32
	// IdleTimeout reaps flows with no activity (0 -> 30s).
	IdleTimeout time.Duration
}

type connState int

const (
	stSynRcvd connState = iota
	stEstablished
	stFinWait // we sent our FIN, awaiting the client's final ACK / FIN
)

type conn struct {
	state    connState
	irs      uint32 // client's initial sequence number
	iss      uint32 // our initial sequence number (constant; SYN-ACK seq)
	rcvNext  uint32 // next sequence we expect from the client
	sndNext  uint32 // next sequence we will send
	req      []byte // accumulated client payload (the single request)
	answered bool   // we have already sent our one response
	seen     time.Time
}

type flowKey struct {
	src    [4]byte
	dst    [4]byte
	sp, dp uint16
}

// Stats are cumulative counters for logging / the UI.
type Stats struct {
	Handshakes uint64
	Requests   uint64
	Malformed  uint64
	Resets     uint64
	Flows      int // live flow-table size
}

// Stack is a per-honeynet userspace TCP engine. One Stack serves every
// virtual host on a TUN; it is safe for the Run loop and the GC ticker to
// touch concurrently. The decoy is intentionally minimal: in-order data
// only, no retransmission, congestion control, or out-of-order reassembly.
type Stack struct {
	profile func(dst [4]byte) OSProfile
	open    func(dst [4]byte, port uint16) bool
	resp    Responder
	now     func() time.Time
	isn     func() uint32
	idle    time.Duration

	mu    sync.Mutex
	flows map[flowKey]*conn

	cHandshakes uint64
	cRequests   uint64
	cMalformed  uint64
	cResets     uint64
}

// NewStack builds a Stack from cfg, filling in defaults for nil hooks.
func NewStack(cfg Config) *Stack {
	s := &Stack{
		profile: cfg.Profile,
		open:    cfg.Open,
		resp:    cfg.Responder,
		now:     cfg.Now,
		isn:     cfg.ISN,
		idle:    cfg.IdleTimeout,
		flows:   map[flowKey]*conn{},
	}
	if s.profile == nil {
		s.profile = func([4]byte) OSProfile { return profiles["linux"] }
	}
	if s.open == nil {
		s.open = func([4]byte, uint16) bool { return false }
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.isn == nil {
		s.isn = randISN
	}
	if s.idle == 0 {
		s.idle = 30 * time.Second
	}
	return s
}

// OnPacket feeds one raw IPv4 packet (as read off the TUN) to the stack and
// returns the packets to send plus events to publish. Non-IPv4 / non-TCP
// input yields an empty Result (tunnet handles ICMP separately).
func (s *Stack) OnPacket(pkt []byte) Result {
	seg, ok := ParseV4(pkt)
	if !ok || !seg.IsTCP {
		return Result{}
	}
	var r Result
	open := s.open(seg.DstIP, seg.DstPort)

	if markers := Classify(seg); len(markers) > 0 {
		atomic.AddUint64(&s.cMalformed, 1)
		r.Events = append(r.Events, Event{
			Kind: EventMalformed, Markers: markers,
			SrcIP: seg.SrcIP, DstIP: seg.DstIP,
			SrcPort: seg.SrcPort, DstPort: seg.DstPort,
			Raw: append([]byte(nil), pkt...),
		})
		// Corrupt packets are dropped silently, just like a real stack.
		// A pure stealth-scan flag combo (valid checksums) still gets the
		// believable response: closed ports RST it, open ports ignore it.
		if !corrupt(seg) && !open && seg.Flags&RST == 0 {
			r.Out = append(r.Out, s.rst(seg))
			atomic.AddUint64(&s.cResets, 1)
		}
		return r
	}

	if !open {
		if seg.Flags&RST == 0 {
			r.Out = append(r.Out, s.rst(seg))
			atomic.AddUint64(&s.cResets, 1)
		}
		return r
	}
	s.handleOpen(seg, pkt, &r)
	return r
}

// handleOpen runs the connection state machine for a well-formed segment
// to an open port.
func (s *Stack) handleOpen(seg *Segment, pkt []byte, r *Result) {
	key := flowKey{seg.SrcIP, seg.DstIP, seg.SrcPort, seg.DstPort}
	f := seg.Flags

	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.flows[key]

	if c == nil {
		switch {
		case f&SYN != 0 && f&ACK == 0:
			c = s.newConn(seg)
			s.flows[key] = c
			r.Out = append(r.Out, s.synAck(seg, c))
			atomic.AddUint64(&s.cHandshakes, 1)
			r.Events = append(r.Events, Event{
				Kind:  EventHandshake,
				SrcIP: seg.SrcIP, DstIP: seg.DstIP,
				SrcPort: seg.SrcPort, DstPort: seg.DstPort,
			})
		case f&RST == 0:
			// Stray segment to an open port with no flow: a real host RSTs.
			r.Out = append(r.Out, s.rst(seg))
			atomic.AddUint64(&s.cResets, 1)
		}
		return
	}

	if f&RST != 0 {
		delete(s.flows, key)
		return
	}
	c.seen = s.now()

	switch c.state {
	case stSynRcvd:
		if f&SYN != 0 && f&ACK == 0 {
			// SYN retransmit before our SYN-ACK landed: resend it.
			r.Out = append(r.Out, s.synAck(seg, c))
			return
		}
		if f&ACK != 0 {
			c.state = stEstablished
			if b := s.banner(seg.DstIP, seg.DstPort); len(b) > 0 {
				r.Out = append(r.Out, s.seg(c, seg, PSH|ACK, b))
				c.sndNext += uint32(len(b))
			}
			if len(seg.Payload) > 0 && seg.Seq == c.rcvNext {
				s.consumeData(seg, c, r)
			}
		}
	case stEstablished:
		if len(seg.Payload) > 0 {
			if seg.Seq == c.rcvNext {
				s.consumeData(seg, c, r)
			} else {
				r.Out = append(r.Out, s.seg(c, seg, ACK, nil)) // dup-ack
			}
		}
		// Client-initiated close. The guard skips this when consumeData
		// just answered-and-closed (state is now stFinWait), so we never
		// emit two FINs for a single request+FIN segment.
		if c.state == stEstablished && f&FIN != 0 && seg.Seq+uint32(len(seg.Payload)) == c.rcvNext {
			c.rcvNext++ // FIN occupies the sequence after the data
			r.Out = append(r.Out, s.seg(c, seg, FIN|ACK, nil))
			c.sndNext++
			c.state = stFinWait
		}
	case stFinWait:
		if f&FIN != 0 {
			if fin := seg.Seq + uint32(len(seg.Payload)); fin == c.rcvNext {
				c.rcvNext++ // acknowledge the client's FIN
			}
			r.Out = append(r.Out, s.seg(c, seg, ACK, nil))
		}
		if f&ACK != 0 {
			delete(s.flows, key) // final ACK of our FIN; flow done
		}
	}
}

// consumeData advances the receive sequence, captures the request bytes,
// emits a request event and — once per flow — sends the configured reply
// followed by a FIN so the decoy answers a single request then closes.
func (s *Stack) consumeData(seg *Segment, c *conn, r *Result) {
	c.rcvNext = seg.Seq + uint32(len(seg.Payload))
	c.req = append(c.req, seg.Payload...)
	atomic.AddUint64(&s.cRequests, 1)
	r.Events = append(r.Events, Event{
		Kind:  EventRequest,
		SrcIP: seg.SrcIP, DstIP: seg.DstIP,
		SrcPort: seg.SrcPort, DstPort: seg.DstPort,
		Payload: append([]byte(nil), seg.Payload...),
	})
	if !c.answered && s.resp.Respond != nil {
		if reply := s.resp.Respond(seg.DstIP, seg.DstPort, c.req); len(reply) > 0 {
			r.Out = append(r.Out, s.seg(c, seg, PSH|ACK, reply))
			c.sndNext += uint32(len(reply))
			r.Out = append(r.Out, s.seg(c, seg, FIN|ACK, nil))
			c.sndNext++
			c.state = stFinWait
			c.answered = true
			return
		}
	}
	r.Out = append(r.Out, s.seg(c, seg, ACK, nil)) // acknowledge the data
}

func (s *Stack) newConn(seg *Segment) *conn {
	iss := s.isn()
	return &conn{
		state:   stSynRcvd,
		irs:     seg.Seq,
		iss:     iss,
		rcvNext: seg.Seq + 1, // client's SYN consumes one sequence
		sndNext: iss + 1,     // our SYN-ACK's SYN consumes one
		seen:    s.now(),
	}
}

func (s *Stack) banner(dst [4]byte, port uint16) []byte {
	if s.resp.Banner == nil {
		return nil
	}
	return s.resp.Banner(dst, port)
}

// synAck builds the fingerprint-shaped SYN-ACK: the profile drives TTL,
// window, DF and the option layout, and the client's timestamp is echoed.
func (s *Stack) synAck(seg *Segment, c *conn) []byte {
	p := s.profile(seg.DstIP)
	tsEcr := uint32(0)
	if seg.HasTS {
		tsEcr = seg.TSVal
	}
	return buildV4(out{
		src: seg.DstIP, dst: seg.SrcIP,
		srcPort: seg.DstPort, dstPort: seg.SrcPort,
		seq: c.iss, ack: c.rcvNext,
		flags: SYN | ACK, window: p.Window, ttl: p.TTL, df: p.DF,
		options: p.buildOptions(s.tsVal(), tsEcr),
	})
}

// seg builds an in-flow segment (ACK / data / FIN) using the connection's
// current sequence + ack and the host's profile for TTL/window/DF. Non-SYN
// segments carry no TCP options (a deliberate decoy simplification).
func (s *Stack) seg(c *conn, in *Segment, flags byte, payload []byte) []byte {
	p := s.profile(in.DstIP)
	return buildV4(out{
		src: in.DstIP, dst: in.SrcIP,
		srcPort: in.DstPort, dstPort: in.SrcPort,
		seq: c.sndNext, ack: c.rcvNext,
		flags: flags, window: p.Window, ttl: p.TTL, df: p.DF,
		payload: payload,
	})
}

// rst synthesizes a reset for a segment to a closed port (or a stray
// segment), following RFC 793 reset generation so the seq/ack a real host
// would use are reproduced.
func (s *Stack) rst(seg *Segment) []byte {
	p := s.profile(seg.DstIP)
	o := out{
		src: seg.DstIP, dst: seg.SrcIP,
		srcPort: seg.DstPort, dstPort: seg.SrcPort,
		ttl: p.TTL, df: p.DF,
	}
	if seg.Flags&ACK != 0 {
		o.flags = RST
		o.seq = seg.Ack
	} else {
		segLen := uint32(len(seg.Payload))
		if seg.Flags&SYN != 0 {
			segLen++
		}
		if seg.Flags&FIN != 0 {
			segLen++
		}
		o.flags = RST | ACK
		o.ack = seg.Seq + segLen
	}
	return buildV4(o)
}

func (s *Stack) tsVal() uint32 {
	return uint32(s.now().UnixNano() / int64(time.Millisecond))
}

// Sweep drops flows idle longer than the configured timeout. tunnet calls
// it on a ticker so the table can't grow without bound under a SYN flood.
func (s *Stack) Sweep() {
	cut := s.now().Add(-s.idle)
	s.mu.Lock()
	for k, c := range s.flows {
		if c.seen.Before(cut) {
			delete(s.flows, k)
		}
	}
	s.mu.Unlock()
}

// Stats returns a snapshot of the cumulative counters and live flow count.
func (s *Stack) Stats() Stats {
	s.mu.Lock()
	n := len(s.flows)
	s.mu.Unlock()
	return Stats{
		Handshakes: atomic.LoadUint64(&s.cHandshakes),
		Requests:   atomic.LoadUint64(&s.cRequests),
		Malformed:  atomic.LoadUint64(&s.cMalformed),
		Resets:     atomic.LoadUint64(&s.cResets),
		Flows:      n,
	}
}

// corrupt reports whether a segment's problem is structural corruption
// (bad checksum, truncation, fragmentation) as opposed to a deliberate
// stealth-scan flag combination with otherwise valid framing.
func corrupt(s *Segment) bool {
	return !s.IPChecksumOK || s.MF || s.FragOff != 0 ||
		s.TCPShort || s.BadDataOff || !s.TCPChecksumOK
}

func randISN() uint32 {
	var b [4]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}
