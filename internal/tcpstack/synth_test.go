package tcpstack

import "encoding/binary"

// clientPkt builds a synthetic client->host IPv4+TCP packet with valid
// checksums, mirroring what the TUN would hand the stack. Options are
// NOP-padded to a 4-byte boundary so callers can pass raw option fragments.
func clientPkt(src, dst [4]byte, sp, dp uint16, seq, ack uint32, flags byte, opts, payload []byte) []byte {
	o := append([]byte(nil), opts...)
	for len(o)%4 != 0 {
		o = append(o, optNOP)
	}
	return buildV4(out{
		src: src, dst: dst, srcPort: sp, dstPort: dp,
		seq: seq, ack: ack, flags: flags,
		window: 65535, ttl: 64, df: true,
		options: o, payload: payload,
	})
}

// tsOpt is a client SYN timestamp option (NOP,NOP,TS) the way Linux lays
// it out, used to verify SYN-ACK timestamp echo.
func tsOpt(val, ecr uint32) []byte {
	b := []byte{optNOP, optNOP, optTimestamp, 10, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[4:8], val)
	binary.BigEndian.PutUint32(b[8:12], ecr)
	return b
}

func has(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
