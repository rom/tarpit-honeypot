package capture

import (
	"encoding/binary"
	"net"
	"os"
)

// writePcap emits a libpcap-format file with DLT_RAW packets containing
// synthesized IPv4+TCP headers per record. Wireshark loads this directly
// and reconstructs the application-layer stream via "Follow TCP".
//
// The TCP sequence numbers are tracked so the stream is coherent; no
// SYN/FIN markers are emitted because we never saw the real ones.
func writePcap(path string, s *Session) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Global header.
	// magic=0xa1b2c3d4 (native byte order, microsecond ts), version 2.4,
	// thiszone=0, sigfigs=0, snaplen=65535, network=DLT_RAW(101).
	gh := make([]byte, 24)
	binary.LittleEndian.PutUint32(gh[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(gh[4:], 2)
	binary.LittleEndian.PutUint16(gh[6:], 4)
	binary.LittleEndian.PutUint32(gh[8:], 0)
	binary.LittleEndian.PutUint32(gh[12:], 0)
	binary.LittleEndian.PutUint32(gh[16:], 65535)
	binary.LittleEndian.PutUint32(gh[20:], 101)
	if _, err := f.Write(gh); err != nil {
		return err
	}

	srcIP, srcPort := splitAddr(s.src)
	dstIP, dstPort := splitAddr(s.dst)

	// Track sequence numbers in each direction.
	var seqClient uint32 = 1 // client -> server
	var seqServer uint32 = 1 // server -> client

	for _, r := range s.records {
		var pkt []byte
		switch r.dir {
		case DirIn:
			pkt = buildIPv4TCP(srcIP, dstIP, srcPort, dstPort, seqClient, seqServer, r.data)
			seqClient += uint32(len(r.data))
		case DirOut:
			pkt = buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, seqServer, seqClient, r.data)
			seqServer += uint32(len(r.data))
		default:
			continue
		}
		// Record header: ts_sec, ts_usec, incl_len, orig_len.
		rh := make([]byte, 16)
		binary.LittleEndian.PutUint32(rh[0:], uint32(r.when.Unix()))
		binary.LittleEndian.PutUint32(rh[4:], uint32(r.when.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rh[8:], uint32(len(pkt)))
		binary.LittleEndian.PutUint32(rh[12:], uint32(len(pkt)))
		if _, err := f.Write(rh); err != nil {
			return err
		}
		if _, err := f.Write(pkt); err != nil {
			return err
		}
	}
	return nil
}

// buildIPv4TCP synthesizes one IPv4 + TCP packet with payload. Falls back
// to IPv4-mapped form when given a v6 address so the format is stable.
func buildIPv4TCP(src, dst net.IP, srcPort, dstPort int, seq, ack uint32, payload []byte) []byte {
	src4 := src.To4()
	dst4 := dst.To4()
	if src4 == nil {
		src4 = net.IPv4(0, 0, 0, 0).To4()
	}
	if dst4 == nil {
		dst4 = net.IPv4(0, 0, 0, 0).To4()
	}

	tcpLen := 20 + len(payload)
	ipLen := 20 + tcpLen
	pkt := make([]byte, ipLen)

	// IPv4 header.
	pkt[0] = 0x45                                      // version=4, IHL=5 (20 bytes)
	pkt[1] = 0x00                                      // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:], uint16(ipLen)) // total length
	binary.BigEndian.PutUint16(pkt[4:], 0)             // identification
	binary.BigEndian.PutUint16(pkt[6:], 0x4000)        // flags=DF, frag=0
	pkt[8] = 64                                        // TTL
	pkt[9] = 6                                         // protocol = TCP
	binary.BigEndian.PutUint16(pkt[10:], 0)            // checksum (filled below)
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	binary.BigEndian.PutUint16(pkt[10:], ipChecksum(pkt[:20]))

	// TCP header.
	off := 20
	binary.BigEndian.PutUint16(pkt[off:], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[off+2:], uint16(dstPort))
	binary.BigEndian.PutUint32(pkt[off+4:], seq)
	binary.BigEndian.PutUint32(pkt[off+8:], ack)
	pkt[off+12] = 0x50                               // data offset=5 (20 bytes)
	pkt[off+13] = 0x18                               // PSH+ACK
	binary.BigEndian.PutUint16(pkt[off+14:], 0xffff) // window
	binary.BigEndian.PutUint16(pkt[off+16:], 0)      // checksum
	binary.BigEndian.PutUint16(pkt[off+18:], 0)      // urgent

	copy(pkt[off+20:], payload)

	// TCP checksum requires a pseudo-header.
	binary.BigEndian.PutUint16(pkt[off+16:], tcpChecksum(src4, dst4, pkt[off:]))
	return pkt
}

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	if len(hdr)%2 == 1 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(src, dst net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))

	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(pseudo)
	add(tcp)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func splitAddr(a net.Addr) (net.IP, int) {
	host, portStr, err := net.SplitHostPort(a.String())
	if err != nil {
		return net.IPv4zero, 0
	}
	port := 0
	for _, c := range portStr {
		if c < '0' || c > '9' {
			port = 0
			break
		}
		port = port*10 + int(c-'0')
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4zero
	}
	return ip, port
}
