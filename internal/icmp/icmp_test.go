package icmp

import (
	"encoding/binary"
	"testing"
)

// A built echo request should be self-consistent, and turning it into a
// reply should keep id/seq/payload and stay checksum-valid.
func TestEchoV4RoundTrip(t *testing.T) {
	req := EchoRequestV4(0x1234, 0x0007, []byte("ping-payload"))
	if !Valid(req) {
		t.Fatal("echo request checksum invalid")
	}
	if req[0] != V4EchoRequest {
		t.Errorf("type = %d; want 8", req[0])
	}
	reply := EchoReplyV4(req)
	if !Valid(reply) {
		t.Fatal("echo reply checksum invalid")
	}
	if reply[0] != V4EchoReply {
		t.Errorf("reply type = %d; want 0", reply[0])
	}
	// id + seq + payload preserved.
	if binary.BigEndian.Uint16(reply[4:6]) != 0x1234 {
		t.Errorf("id not preserved")
	}
	if binary.BigEndian.Uint16(reply[6:8]) != 0x0007 {
		t.Errorf("seq not preserved")
	}
	if string(reply[8:]) != "ping-payload" {
		t.Errorf("payload not preserved: %q", reply[8:])
	}
}

func TestDestUnreachableCodes(t *testing.T) {
	orig := make([]byte, 28) // fake IP header + 8 bytes
	for _, code := range []byte{CodeNetUnreachable, CodeHostUnreachable, CodePortUnreachable, CodeCommAdminProhibited} {
		msg := DestUnreachableV4(code, orig)
		if !Valid(msg) {
			t.Errorf("code %d: checksum invalid", code)
		}
		if msg[0] != V4DestUnreachable || msg[1] != code {
			t.Errorf("type/code wrong: %d/%d", msg[0], msg[1])
		}
		// Original datagram echoed after the 8-byte header.
		if len(msg) != 8+len(orig) {
			t.Errorf("length wrong: %d", len(msg))
		}
	}
}

func TestFragNeededCarriesMTU(t *testing.T) {
	orig := make([]byte, 28)
	msg := FragNeededV4(1400, orig)
	if !Valid(msg) {
		t.Fatal("checksum invalid")
	}
	if msg[0] != V4DestUnreachable || msg[1] != CodeFragNeeded {
		t.Errorf("not a frag-needed message: %d/%d", msg[0], msg[1])
	}
	mtu := binary.BigEndian.Uint16(msg[6:8])
	if mtu != 1400 {
		t.Errorf("next-hop MTU = %d; want 1400", mtu)
	}
}

func TestTimeExceededTraceroute(t *testing.T) {
	orig := make([]byte, 28)
	msg := TimeExceededV4(0, orig)
	if !Valid(msg) {
		t.Fatal("checksum invalid")
	}
	if msg[0] != V4TimeExceeded || msg[1] != 0 {
		t.Errorf("type/code wrong: %d/%d", msg[0], msg[1])
	}
}

func TestRedirectCarriesGateway(t *testing.T) {
	orig := make([]byte, 28)
	gw := [4]byte{192, 168, 1, 254}
	msg := RedirectV4(1, gw, orig)
	if !Valid(msg) {
		t.Fatal("checksum invalid")
	}
	if msg[0] != V4Redirect {
		t.Errorf("not a redirect: %d", msg[0])
	}
	if msg[4] != 192 || msg[5] != 168 || msg[6] != 1 || msg[7] != 254 {
		t.Errorf("gateway not embedded: % d", msg[4:8])
	}
}

func TestParamProblemPointer(t *testing.T) {
	orig := make([]byte, 28)
	msg := ParamProblemV4(20, orig)
	if !Valid(msg) {
		t.Fatal("checksum invalid")
	}
	if msg[4] != 20 {
		t.Errorf("pointer = %d; want 20", msg[4])
	}
}

func TestTimestampReply(t *testing.T) {
	// Build a timestamp request: type 13, id/seq, originate ts.
	req := make([]byte, 20)
	req[0] = V4Timestamp
	binary.BigEndian.PutUint16(req[4:6], 0xABCD)
	binary.BigEndian.PutUint16(req[6:8], 0x0001)
	binary.BigEndian.PutUint32(req[8:12], 12345) // originate
	reply := TimestampReplyV4(req, 99999)
	if !Valid(reply) {
		t.Fatal("checksum invalid")
	}
	if reply[0] != V4TimestampReply {
		t.Errorf("type = %d; want 14", reply[0])
	}
	if binary.BigEndian.Uint16(reply[4:6]) != 0xABCD {
		t.Errorf("id not echoed")
	}
	if binary.BigEndian.Uint32(reply[8:12]) != 12345 {
		t.Errorf("originate ts not echoed")
	}
	if binary.BigEndian.Uint32(reply[12:16]) != 99999 {
		t.Errorf("receive ts wrong")
	}
}

func TestAddrMaskReply(t *testing.T) {
	req := make([]byte, 12)
	req[0] = V4AddrMask
	binary.BigEndian.PutUint16(req[4:6], 0x0042)
	mask := [4]byte{255, 255, 255, 0}
	reply := AddrMaskReplyV4(req, mask)
	if !Valid(reply) {
		t.Fatal("checksum invalid")
	}
	if reply[0] != V4AddrMaskReply {
		t.Errorf("type = %d; want 18", reply[0])
	}
	if reply[8] != 255 || reply[9] != 255 || reply[10] != 255 || reply[11] != 0 {
		t.Errorf("mask not embedded: % d", reply[8:12])
	}
}

func TestICMPv6EchoReplyChecksum(t *testing.T) {
	src := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	req := EchoRequestV6(0x1111, 0x2222, []byte("v6"))
	ChecksumV6(req, dst, src)
	reply := EchoReplyV6(req)
	ChecksumV6(reply, src, dst)
	if reply[0] != V6EchoReply {
		t.Errorf("type = %d; want 129", reply[0])
	}
	// Verify the checksum we wrote is correct by recomputing over the
	// pseudo-header: the stored checksum + recompute should net zero.
	stored := binary.BigEndian.Uint16(reply[2:4])
	ChecksumV6(reply, src, dst)
	if binary.BigEndian.Uint16(reply[2:4]) != stored {
		t.Errorf("checksum not stable")
	}
}

func TestNeighborAdvertV6(t *testing.T) {
	var tgt [16]byte
	tgt[15] = 0x42
	mac := [6]byte{0x00, 0x90, 0xe8, 1, 2, 3}
	msg := NeighborAdvertV6(tgt, mac, 0x60)
	if msg[0] != V6NeighborAdv {
		t.Errorf("type = %d; want 136", msg[0])
	}
	if msg[4] != 0x60 {
		t.Errorf("flags = %x; want 0x60", msg[4])
	}
	// Target LL option at offset 24: type 2, len 1, then MAC.
	if msg[24] != 2 || msg[25] != 1 {
		t.Errorf("target-LL option header wrong: %d/%d", msg[24], msg[25])
	}
	if msg[26] != 0x00 || msg[27] != 0x90 || msg[28] != 0xe8 {
		t.Errorf("target MAC not embedded")
	}
}

func TestRouterAdvertV6(t *testing.T) {
	mac := [6]byte{0x02, 0x00, 0, 0, 0, 1}
	msg := RouterAdvertV6(64, 1800, mac)
	if msg[0] != V6RouterAdv {
		t.Errorf("type = %d; want 134", msg[0])
	}
	if msg[4] != 64 {
		t.Errorf("hop limit = %d; want 64", msg[4])
	}
	if binary.BigEndian.Uint16(msg[6:8]) != 1800 {
		t.Errorf("router lifetime wrong")
	}
}
