//go:build linux

package tunnet

import (
	"encoding/binary"
	"testing"
)

func TestTTLForDefaultsAndPersona(t *testing.T) {
	a := &Adapter{
		ttlV4: map[[4]byte]byte{{10, 0, 0, 5}: 128},
		ttlV6: map[[16]byte]byte{},
	}
	if got := a.ttlFor4([4]byte{10, 0, 0, 5}); got != 128 {
		t.Errorf("ttlFor4(persona) = %d; want 128", got)
	}
	if got := a.ttlFor4([4]byte{10, 0, 0, 9}); got != defaultTTL {
		t.Errorf("ttlFor4(unset) = %d; want %d", got, defaultTTL)
	}
	if got := a.ttlFor6([16]byte{}); got != defaultTTL {
		t.Errorf("ttlFor6(unset) = %d; want %d", got, defaultTTL)
	}
}

// A minimal IPv4 + ICMP echo request frame (no Ethernet — TUN is L3).
func icmpEchoRequestV4(src, dst [4]byte, ttl byte) []byte {
	pkt := make([]byte, 20+8)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = ttl
	pkt[9] = 1 // ICMP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[10:12], internetChecksum(pkt[:20]))
	pkt[20] = 8 // echo request
	binary.BigEndian.PutUint16(pkt[22:24], internetChecksum(pkt[20:]))
	return pkt
}

func TestBuildEchoReplyV4StampsTTLAndSwaps(t *testing.T) {
	src := [4]byte{1, 2, 3, 4}  // prober
	dst := [4]byte{10, 0, 0, 5} // our host
	req := icmpEchoRequestV4(src, dst, 49)
	reply := buildEchoReplyV4(req, 20, src, dst, 128)

	if reply[8] != 128 {
		t.Errorf("reply TTL = %d; want 128 (our persona, not the prober's 49)", reply[8])
	}
	if [4]byte{reply[12], reply[13], reply[14], reply[15]} != dst {
		t.Errorf("reply src IP not set to our host")
	}
	if [4]byte{reply[16], reply[17], reply[18], reply[19]} != src {
		t.Errorf("reply dst IP not set to the prober")
	}
	if reply[20] != 0 {
		t.Errorf("reply ICMP type = %d; want 0 (echo reply)", reply[20])
	}
	// IP header checksum must verify (0 when summed correctly).
	if internetChecksum(reply[:20]) != 0 {
		t.Errorf("reply IP checksum invalid")
	}
}

// TCP RST / SYN-ACK generation moved to the userspace stack
// (internal/tcpstack); see its packet_test.go and stack_test.go.

func TestNewStackRstsClosedPorts(t *testing.T) {
	// A tunnet stack built from an empty decoy map must RST any SYN — the
	// legacy "every port closed" behavior the L3 responder used to provide.
	st := newStack(nil)
	syn := buildSynV4([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 5}, 40000, 80, 0x11223344)
	res := st.OnPacket(syn)
	if len(res.Out) != 1 {
		t.Fatalf("closed-port SYN produced %d packets; want 1 RST", len(res.Out))
	}
	rst := res.Out[0]
	if rst[20+13] != 0x14 {
		t.Errorf("RST flags = %#02x; want 0x14 (RST+ACK)", rst[20+13])
	}
	if ack := binary.BigEndian.Uint32(rst[20+8 : 20+12]); ack != 0x11223345 {
		t.Errorf("RST ack = %#x; want client_seq+1", ack)
	}
	if internetChecksum(rst[:20]) != 0 {
		t.Errorf("RST IP checksum invalid")
	}
}

// buildSynV4 is a minimal client SYN (no options) for the tunnet-level test.
func buildSynV4(src, dst [4]byte, sport, dport uint16, seq uint32) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[10:12], internetChecksum(pkt[:20]))
	t := pkt[20:]
	binary.BigEndian.PutUint16(t[0:2], sport)
	binary.BigEndian.PutUint16(t[2:4], dport)
	binary.BigEndian.PutUint32(t[4:8], seq)
	t[12] = 0x50
	t[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(t[14:16], 0xffff)
	binary.BigEndian.PutUint16(t[16:18], tcpCsumForTest(src[:], dst[:], t))
	return pkt
}

// tcpCsumForTest mirrors the stack's pseudo-header TCP checksum so the
// synthetic SYN parses as well-formed.
func tcpCsumForTest(src, dst, tcp []byte) uint16 {
	var sum uint32
	add := func(s []byte) {
		for i := 0; i+1 < len(s); i += 2 {
			sum += uint32(s[i])<<8 | uint32(s[i+1])
		}
		if len(s)%2 == 1 {
			sum += uint32(s[len(s)-1]) << 8
		}
	}
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	add(pseudo)
	add(tcp)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
