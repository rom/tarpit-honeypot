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
	"time"

	"golang.org/x/sys/unix"

	icmppkg "github.com/rom/tarpit-honeypot/internal/icmp"
)

// msSinceMidnightUTC is the RFC 792 timestamp format used in ICMP
// Timestamp replies (milliseconds since midnight UTC).
func msSinceMidnightUTC() uint32 {
	now := time.Now().UTC()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	return uint32(now.Sub(midnight).Milliseconds())
}

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
		icmpMsg := ip[ihl:]
		if len(icmpMsg) < 8 {
			continue
		}
		// Answer the request type with the matching reply:
		//   8  echo request      -> 0  echo reply
		//   13 timestamp request -> 14 timestamp reply
		//   17 addr-mask request -> 18 address mask reply
		// Other types are captured (logged) but not answered.
		var icmpReply []byte
		switch icmpMsg[0] {
		case icmppkg.V4EchoRequest:
			icmpReply = icmppkg.EchoReplyV4(icmpMsg)
		case icmppkg.V4Timestamp:
			icmpReply = icmppkg.TimestampReplyV4(icmpMsg, msSinceMidnightUTC())
		case icmppkg.V4AddrMask:
			icmpReply = icmppkg.AddrMaskReplyV4(icmpMsg, [4]byte{255, 255, 255, 0})
		default:
			continue
		}
		if icmpReply == nil {
			continue
		}
		reply := buildICMPFrame(host.MAC, dstIP, buf[6:12], srcIP, icmpReply)
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

// buildICMPFrame wraps a fully-formed ICMP message (already typed +
// checksummed by the icmp package) in an Ethernet + IPv4 frame sourced
// from the virtual host and addressed to the requester.
func buildICMPFrame(ourMAC [6]byte, ourIP string, requesterMAC []byte, requesterIP net.IP, icmp []byte) []byte {
	ourIP4 := net.ParseIP(ourIP).To4()
	if ourIP4 == nil || requesterIP.To4() == nil {
		return nil
	}
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
	binary.BigEndian.PutUint16(ip[4:6], 0)      // identification
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // DF, frag=0
	ip[8] = 64                                  // TTL
	ip[9] = 1                                   // ICMP
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
