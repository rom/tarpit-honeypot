package tcpstack

import (
	"testing"
	"time"
)

var (
	tClient = [4]byte{1, 2, 3, 4}
	tHost   = [4]byte{10, 0, 0, 5}
)

func testStack(open ...uint16) *Stack {
	om := map[uint16]bool{}
	for _, p := range open {
		om[p] = true
	}
	return NewStack(Config{
		Profile: func([4]byte) OSProfile { return profiles["linux"] },
		Open:    func(_ [4]byte, port uint16) bool { return om[port] },
		Responder: Responder{
			Banner: func(_ [4]byte, port uint16) []byte {
				if port == 22 {
					return []byte("SSH-2.0-OpenSSH_9.6\r\n")
				}
				return nil
			},
			Respond: func(_ [4]byte, port uint16, _ []byte) []byte {
				if port == 80 {
					return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
				}
				return nil
			},
		},
		Now: func() time.Time { return time.Unix(1700000000, 0) },
		ISN: func() uint32 { return 0x5000 },
	})
}

func TestHandshakeSynAckFingerprint(t *testing.T) {
	st := testStack(80)
	syn := clientPkt(tClient, tHost, 40000, 80, 1000, 0, SYN, tsOpt(111, 0), nil)
	res := st.OnPacket(syn)

	if len(res.Out) != 1 {
		t.Fatalf("SYN produced %d packets; want 1 SYN-ACK", len(res.Out))
	}
	if len(res.Events) != 1 || res.Events[0].Kind != EventHandshake || res.Events[0].DstPort != 80 {
		t.Fatalf("handshake event = %+v", res.Events)
	}
	sa, ok := ParseV4(res.Out[0])
	if !ok || !sa.IPChecksumOK || !sa.TCPChecksumOK {
		t.Fatalf("SYN-ACK invalid: ok=%v ip=%v tcp=%v", ok, sa.IPChecksumOK, sa.TCPChecksumOK)
	}
	if sa.Flags != SYN|ACK {
		t.Errorf("flags = %#x; want SYN|ACK", sa.Flags)
	}
	if sa.Seq != 0x5000 || sa.Ack != 1001 {
		t.Errorf("seq/ack = %d/%d; want 0x5000/1001", sa.Seq, sa.Ack)
	}
	if sa.Window != 64240 || sa.TTL != 64 || !sa.DF {
		t.Errorf("fingerprint: win=%d ttl=%d df=%v; want 64240/64/true", sa.Window, sa.TTL, sa.DF)
	}
	// addresses swapped back toward the client
	if sa.SrcIP != tHost || sa.DstIP != tClient {
		t.Errorf("addr swap wrong: %v -> %v", sa.SrcIP, sa.DstIP)
	}
	if sa.SrcPort != 80 || sa.DstPort != 40000 {
		t.Errorf("port swap wrong: %d -> %d", sa.SrcPort, sa.DstPort)
	}
	if !sa.HasTS || sa.TSEcr != 111 {
		t.Errorf("timestamp echo: has=%v ecr=%d; want true/111", sa.HasTS, sa.TSEcr)
	}
	if st.Stats().Flows != 1 || st.Stats().Handshakes != 1 {
		t.Errorf("stats = %+v", st.Stats())
	}
}

func TestFullHTTPRequestResponseAndClose(t *testing.T) {
	st := testStack(80)
	st.OnPacket(clientPkt(tClient, tHost, 40000, 80, 1000, 0, SYN, nil, nil))
	// handshake-completing ACK: no banner on port 80, so no output.
	if res := st.OnPacket(clientPkt(tClient, tHost, 40000, 80, 1001, 0x5001, ACK, nil, nil)); len(res.Out) != 0 {
		t.Fatalf("ACK produced %d packets; want 0 (HTTP is client-first)", len(res.Out))
	}

	req := []byte("GET / HTTP/1.0\r\n\r\n")
	res := st.OnPacket(clientPkt(tClient, tHost, 40000, 80, 1001, 0x5001, PSH|ACK, nil, req))
	if len(res.Events) != 1 || res.Events[0].Kind != EventRequest || string(res.Events[0].Payload) != string(req) {
		t.Fatalf("request event = %+v", res.Events)
	}
	if len(res.Out) != 2 {
		t.Fatalf("request produced %d packets; want 2 (data + FIN)", len(res.Out))
	}
	data, _ := ParseV4(res.Out[0])
	if data.Flags != PSH|ACK || string(data.Payload) != "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi" {
		t.Errorf("response data: flags=%#x payload=%q", data.Flags, data.Payload)
	}
	if data.Seq != 0x5001 || data.Ack != 1001+uint32(len(req)) {
		t.Errorf("response seq/ack = %d/%d; want 0x5001/%d", data.Seq, data.Ack, 1001+len(req))
	}
	fin, _ := ParseV4(res.Out[1])
	if fin.Flags != FIN|ACK {
		t.Errorf("close flags = %#x; want FIN|ACK", fin.Flags)
	}
	wantFinSeq := uint32(0x5001 + len("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
	if fin.Seq != wantFinSeq {
		t.Errorf("FIN seq = %d; want %d", fin.Seq, wantFinSeq)
	}

	// Client acknowledges our FIN -> the flow is reaped.
	st.OnPacket(clientPkt(tClient, tHost, 40000, 80, 1001+uint32(len(req)), fin.Seq+1, ACK, nil, nil))
	if st.Stats().Flows != 0 {
		t.Errorf("flow not closed: %d live", st.Stats().Flows)
	}
}

func TestServerFirstBannerOnPort22(t *testing.T) {
	st := testStack(22)
	st.OnPacket(clientPkt(tClient, tHost, 50000, 22, 5, 0, SYN, nil, nil))
	res := st.OnPacket(clientPkt(tClient, tHost, 50000, 22, 6, 0x5001, ACK, nil, nil))
	if len(res.Out) != 1 {
		t.Fatalf("handshake ACK produced %d packets; want 1 banner", len(res.Out))
	}
	b, _ := ParseV4(res.Out[0])
	if b.Flags != PSH|ACK || string(b.Payload) != "SSH-2.0-OpenSSH_9.6\r\n" {
		t.Errorf("banner: flags=%#x payload=%q", b.Flags, b.Payload)
	}
	if b.Seq != 0x5001 || b.Ack != 6 {
		t.Errorf("banner seq/ack = %d/%d; want 0x5001/6", b.Seq, b.Ack)
	}
}

func TestClosedPortRsts(t *testing.T) {
	st := testStack() // nothing open
	res := st.OnPacket(clientPkt(tClient, tHost, 40000, 81, 1000, 0, SYN, nil, nil))
	if len(res.Out) != 1 {
		t.Fatalf("closed-port SYN produced %d packets; want 1 RST", len(res.Out))
	}
	rst, _ := ParseV4(res.Out[0])
	if rst.Flags != RST|ACK || rst.Ack != 1001 {
		t.Errorf("RST flags=%#x ack=%d; want RST|ACK/1001", rst.Flags, rst.Ack)
	}
	if len(res.Events) != 0 {
		t.Errorf("closed-port probe emitted events: %+v", res.Events)
	}
	if st.Stats().Flows != 0 {
		t.Errorf("closed-port probe created a flow")
	}
}

func TestMalformedToOpenPortIsDropped(t *testing.T) {
	st := testStack(80)
	// NULL scan to an open port: emit malformed, send nothing (real open
	// ports ignore stealth probes).
	res := st.OnPacket(clientPkt(tClient, tHost, 40000, 80, 1000, 0, 0, nil, nil))
	if len(res.Out) != 0 {
		t.Errorf("open-port NULL scan produced %d packets; want 0", len(res.Out))
	}
	if len(res.Events) != 1 || res.Events[0].Kind != EventMalformed || !has(res.Events[0].Markers, "tcp-null") {
		t.Fatalf("malformed event = %+v", res.Events)
	}
	if res.Events[0].Raw == nil {
		t.Error("malformed event missing raw packet capture")
	}
}

func TestMalformedToClosedPortRsts(t *testing.T) {
	st := testStack()
	res := st.OnPacket(clientPkt(tClient, tHost, 40000, 81, 1000, 0, FIN, nil, nil))
	if len(res.Events) != 1 || !has(res.Events[0].Markers, "tcp-fin-scan") {
		t.Fatalf("expected fin-scan marker: %+v", res.Events)
	}
	if len(res.Out) != 1 {
		t.Errorf("closed-port FIN scan produced %d packets; want 1 RST", len(res.Out))
	}
}

func TestCorruptPacketNeverReplies(t *testing.T) {
	st := testStack() // closed port: a clean SYN here would RST...
	syn := clientPkt(tClient, tHost, 40000, 81, 1000, 0, SYN, nil, nil)
	syn[20+16] ^= 0xff // ...but a corrupt TCP checksum must be dropped silently
	res := st.OnPacket(syn)
	if len(res.Out) != 0 {
		t.Errorf("corrupt packet drew a reply: %d packets", len(res.Out))
	}
	if len(res.Events) != 1 || !has(res.Events[0].Markers, "tcp-bad-checksum") {
		t.Fatalf("expected bad-checksum marker: %+v", res.Events)
	}
}

func TestSweepReapsIdleFlows(t *testing.T) {
	st := testStack(80)
	st.OnPacket(clientPkt(tClient, tHost, 40000, 80, 1, 0, SYN, nil, nil))
	if st.Stats().Flows != 1 {
		t.Fatalf("flow not created")
	}
	st.now = func() time.Time { return time.Unix(1700000000, 0).Add(time.Hour) }
	st.Sweep()
	if st.Stats().Flows != 0 {
		t.Errorf("idle flow not reaped: %d live", st.Stats().Flows)
	}
}

func TestSynRetransmitResendsSynAck(t *testing.T) {
	st := testStack(80)
	syn := clientPkt(tClient, tHost, 40000, 80, 1000, 0, SYN, nil, nil)
	first := st.OnPacket(syn)
	second := st.OnPacket(syn) // duplicate SYN before the ACK
	if len(second.Out) != 1 {
		t.Fatalf("SYN retransmit produced %d packets; want 1", len(second.Out))
	}
	a, _ := ParseV4(first.Out[0])
	b, _ := ParseV4(second.Out[0])
	if a.Seq != b.Seq {
		t.Errorf("retransmitted SYN-ACK changed ISN: %d vs %d", a.Seq, b.Seq)
	}
	if st.Stats().Handshakes != 1 || st.Stats().Flows != 1 {
		t.Errorf("retransmit double-counted: %+v", st.Stats())
	}
}

func TestDefaultStackRstOnly(t *testing.T) {
	// A zero-config stack (no Open callback) behaves like the legacy
	// L3 responder: every SYN gets a RST, nothing is ever "open".
	st := NewStack(Config{Now: func() time.Time { return time.Unix(1, 0) }, ISN: func() uint32 { return 1 }})
	res := st.OnPacket(clientPkt(tClient, tHost, 40000, 443, 1000, 0, SYN, nil, nil))
	if len(res.Out) != 1 {
		t.Fatalf("want 1 RST, got %d", len(res.Out))
	}
	rst, _ := ParseV4(res.Out[0])
	if rst.Flags != RST|ACK {
		t.Errorf("flags = %#x; want RST|ACK", rst.Flags)
	}
}
