//go:build linux

package honeynet

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// startICMPResponder opens an AF_PACKET socket on the named interface,
// filters for IPv4 ICMP, and answers ICMP echo requests (type 8) addressed
// to any honeynet host IP with an echo reply (type 0) carrying the same
// identifier / sequence / payload, sourced from the virtual host's IP and
// MAC.
//
// Same constraints as ARP: needs CAP_NET_RAW. Returns when ctx cancels.
// Operating on raw frames is the only way to answer pings for IPs that
// aren't actually configured on a local interface — for "this virtual
// host responds to ping" without `ip addr add`.
func startICMPResponder(ctx context.Context, ifaceName string, topo *Topology) error {
	if topo == nil || topo.Empty() {
		return errors.New("icmp_responder: no honeynet hosts configured")
	}
	iface, err := pickInterface(ifaceName)
	if err != nil {
		return err
	}
	const ethPIP = 0x0800
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPIP)))
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return fmt.Errorf("icmp_responder: need CAP_NET_RAW: %w", err)
		}
		return fmt.Errorf("icmp_responder: socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(ethPIP),
		Ifindex:  iface.Index,
	}); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("icmp_responder: bind: %w", err)
	}
	slog.Info("honeynet icmp responder up",
		"interface", iface.Name,
		"if_index", iface.Index,
		"hosts", len(topo.hostByIP),
	)
	go func() {
		<-ctx.Done()
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		_ = unix.Close(fd)
	}()
	go icmpLoop(fd, iface, topo)
	return nil
}

func icmpLoop(fd int, iface *net.Interface, topo *Topology) {
	buf := make([]byte, 2048)
	for {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINTR) {
				return
			}
			slog.Debug("icmp responder recv", "err", err)
			continue
		}
		if n < 14+20+8 { // Eth + min IPv4 + min ICMP
			continue
		}
		if binary.BigEndian.Uint16(buf[12:14]) != 0x0800 {
			continue
		}
		ip := buf[14:n]
		// Minimum IPv4 header sanity.
		ihl := int(ip[0]&0x0F) * 4
		if ihl < 20 || ihl > len(ip) {
			continue
		}
		if ip[9] != 1 { // protocol 1 = ICMP
			continue
		}
		srcIP := net.IP(ip[12:16])
		dstIP := net.IP(ip[16:20]).String()
		host, ok := topo.hostByIP[dstIP]
		if !ok {
			continue
		}
		icmp := ip[ihl:]
		if len(icmp) < 8 {
			continue
		}
		if icmp[0] != 8 { // type=8 echo request
			continue
		}
		// Build echo reply. Same identifier (icmp[4:6]) and sequence
		// (icmp[6:8]) so the requester's ping matches up. Payload is
		// whatever followed.
		reply := buildICMPEchoReply(host.MAC, dstIP, buf[6:12], srcIP, icmp)
		ll, ok := from.(*unix.SockaddrLinklayer)
		if !ok {
			continue
		}
		dst := &unix.SockaddrLinklayer{
			Protocol: htons(0x0800),
			Ifindex:  ll.Ifindex,
			Halen:    6,
		}
		copy(dst.Addr[:], buf[6:12])
		if err := unix.Sendto(fd, reply, 0, dst); err != nil {
			slog.Debug("icmp responder send", "err", err, "host", dstIP)
			continue
		}
		slog.Debug("icmp echo replied",
			"requester", srcIP.String(),
			"as_host", dstIP,
			"as_hostname", host.Hostname,
		)
	}
}

// buildICMPEchoReply constructs a full Ethernet+IPv4+ICMP frame replying to
// the supplied echo request. ourMAC is the virtual host's derived MAC,
// ourIP is the virtual host IP, requesterMAC/IP come from the request,
// origICMP is the original ICMP message (echo request) which we copy
// verbatim with only type+checksum changed.
func buildICMPEchoReply(ourMAC [6]byte, ourIP string, requesterMAC []byte, requesterIP net.IP, origICMP []byte) []byte {
	ourIP4 := net.ParseIP(ourIP).To4()
	if ourIP4 == nil || requesterIP.To4() == nil {
		return nil
	}
	// Echo reply ICMP: type=0, code=0, then re-checksummed body.
	icmp := append([]byte(nil), origICMP...)
	icmp[0] = 0
	icmp[1] = 0
	icmp[2] = 0
	icmp[3] = 0
	cs := internetChecksum(icmp)
	icmp[2] = byte(cs >> 8)
	icmp[3] = byte(cs)

	totalLen := 20 + len(icmp)
	frame := make([]byte, 14+totalLen)
	// Ethernet
	copy(frame[0:6], requesterMAC)
	copy(frame[6:12], ourMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	// IPv4 header
	ip := frame[14:]
	ip[0] = 0x45 // version=4, IHL=5
	ip[1] = 0
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:6], 0) // identification
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // DF, frag=0
	ip[8] = 64 // TTL
	ip[9] = 1  // ICMP
	copy(ip[12:16], ourIP4)
	copy(ip[16:20], requesterIP.To4())
	ipcs := internetChecksum(ip[:20])
	ip[10] = byte(ipcs >> 8)
	ip[11] = byte(ipcs)
	copy(ip[20:], icmp)
	return frame
}

// internetChecksum is the standard 16-bit one's-complement sum used by
// IPv4 / ICMP / TCP / UDP. Pads with a trailing zero byte for odd lengths.
func internetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
