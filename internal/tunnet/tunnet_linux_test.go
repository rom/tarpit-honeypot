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

func TestBuildRSTV4StampsTTL(t *testing.T) {
	src := [4]byte{1, 2, 3, 4}
	dst := [4]byte{10, 0, 0, 5}
	out := buildRSTV4(src, dst, 40000, 80, 0x11223344, 255)

	if out[8] != 255 {
		t.Errorf("RST TTL = %d; want 255", out[8])
	}
	if out[9] != 6 {
		t.Errorf("RST proto = %d; want 6 (TCP)", out[9])
	}
	if out[20+13] != 0x14 {
		t.Errorf("RST flags = %#02x; want 0x14 (RST+ACK)", out[20+13])
	}
	// ack = client_seq + 1
	if ack := binary.BigEndian.Uint32(out[20+8 : 20+12]); ack != 0x11223345 {
		t.Errorf("RST ack = %#x; want client_seq+1", ack)
	}
	if internetChecksum(out[:20]) != 0 {
		t.Errorf("RST IP checksum invalid")
	}
}
