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

const (
	ethPIPv4 = 0x0800
	ethPIPv6 = 0x86DD
)

// msSinceMidnightUTC is the RFC 792 timestamp format used in ICMP
// Timestamp replies (milliseconds since midnight UTC).
func msSinceMidnightUTC() uint32 {
	now := time.Now().UTC()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	return uint32(now.Sub(midnight).Milliseconds())
}

// startICMPResponder opens AF_PACKET sockets on the named interface (one for
// IPv4, one for IPv6), and answers:
//   - IPv4 ICMP echo (type 8 -> 0), timestamp (13 -> 14) and address-mask
//     (17 -> 18) requests addressed to any honeynet host IP;
//   - IPv6 ICMPv6 echo (type 128 -> 129) addressed to a host's v6 address, plus
//     the Neighbor Solicitation -> Advertisement (135 -> 136) that makes that
//     v6 address resolvable on the segment in the first place.
//
// Replies are sourced from the virtual host's IP + MAC, with the
// archetype-characteristic initial TTL / hop-limit. Each echo / OS-probe is
// reported through onICMP so the sensor can emit a captured-traffic event.
//
// Same constraints as ARP: needs CAP_NET_RAW. Returns when ctx cancels.
// Operating on raw frames is the only way to answer pings for IPs that aren't
// actually configured on a local interface.
func startICMPResponder(ctx context.Context, ifaceName string, topo *Topology, onICMP ICMPObserver) error {
	if topo == nil || topo.Empty() {
		return errors.New("icmp_responder: no honeynet hosts configured")
	}
	iface, err := pickInterface(ifaceName)
	if err != nil {
		return err
	}
	fd4, err := openPacketSocket(iface, ethPIPv4)
	if err != nil {
		return fmt.Errorf("icmp_responder: %w", err)
	}
	// IPv6 is best-effort: a v4-only deployment (or one with no host ipv6
	// addresses) shouldn't fail the whole responder if the v6 socket can't open.
	fd6, err6 := openPacketSocket(iface, ethPIPv6)
	v6 := err6 == nil
	if !v6 {
		slog.Debug("icmp_responder: ipv6 socket unavailable", "err", err6)
	}
	slog.Info("honeynet icmp responder up",
		"interface", iface.Name,
		"if_index", iface.Index,
		"hosts", len(topo.hostByIP),
		"hosts_v6", len(topo.hostByIP6),
		"ipv6", v6,
	)
	go func() {
		<-ctx.Done()
		_ = unix.Shutdown(fd4, unix.SHUT_RDWR)
		_ = unix.Close(fd4)
		if v6 {
			_ = unix.Shutdown(fd6, unix.SHUT_RDWR)
			_ = unix.Close(fd6)
		}
	}()
	go icmpLoop(fd4, iface, topo, onICMP)
	if v6 {
		go icmp6Loop(fd6, iface, topo, onICMP)
	}
	return nil
}

// openPacketSocket opens + binds a raw AF_PACKET socket filtered to a single
// ethertype on the given interface.
func openPacketSocket(iface *net.Interface, ethType uint16) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethType)))
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return -1, fmt.Errorf("need CAP_NET_RAW: %w", err)
		}
		return -1, fmt.Errorf("socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(ethType),
		Ifindex:  iface.Index,
	}); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("bind: %w", err)
	}
	return fd, nil
}

func icmpLoop(fd int, iface *net.Interface, topo *Topology, onICMP ICMPObserver) {
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
		if binary.BigEndian.Uint16(buf[12:14]) != ethPIPv4 {
			continue
		}
		ip := buf[14:n]
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
		if anoms := icmppkg.Anomalies(ip[:ihl], icmpMsg); len(anoms) > 0 {
			slog.Warn("icmp anomaly", "from", srcIP.String(), "as_host", dstIP, "markers", anoms)
		}
		// Answer the request type with the matching reply:
		//   8  echo request      -> 0  echo reply
		//   13 timestamp request -> 14 timestamp reply
		//   17 addr-mask request -> 18 address mask reply
		// Other types are captured (logged) but not answered.
		var icmpReply []byte
		var kind string
		switch icmpMsg[0] {
		case icmppkg.V4EchoRequest:
			icmpReply, kind = icmppkg.EchoReplyV4(icmpMsg), "echo"
		case icmppkg.V4Timestamp:
			icmpReply, kind = icmppkg.TimestampReplyV4(icmpMsg, msSinceMidnightUTC()), "timestamp"
		case icmppkg.V4AddrMask:
			icmpReply, kind = icmppkg.AddrMaskReplyV4(icmpMsg, [4]byte{255, 255, 255, 0}), "address-mask"
		default:
			continue
		}
		if icmpReply == nil {
			continue
		}
		// Per-host ICMP personality: stamp the OS-characteristic initial TTL
		// from the host's archetype (255 OT/network gear, 128 Windows, 64
		// Linux/BSD) so passive OS fingerprinting + traceroute hop-distance
		// estimation see a consistent host.
		ttl := byte(host.Archetype.ICMPTTL())
		reply := buildICMPFrame(host.MAC, dstIP, buf[6:12], srcIP, icmpReply, ttl)
		sendFrame(fd, from, buf[6:12], ethPIPv4, reply)
		reportICMP(onICMP, srcIP.String(), dstIP, host, 4, kind, int(icmpMsg[0]))
		slog.Debug("icmp echo replied", "requester", srcIP.String(), "as_host", dstIP, "as_hostname", host.Hostname)
	}
}

// icmp6Loop answers ICMPv6 Neighbor Solicitation + echo for honeynet hosts that
// carry an ipv6 address. Neighbor Discovery is what makes the v6 address
// resolvable; the echo reply is the actual ping6 answer.
func icmp6Loop(fd int, iface *net.Interface, topo *Topology, onICMP ICMPObserver) {
	buf := make([]byte, 2048)
	for {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINTR) {
				return
			}
			slog.Debug("icmp6 responder recv", "err", err)
			continue
		}
		if n < 14+40+8 { // Eth + IPv6 header + min ICMPv6
			continue
		}
		if binary.BigEndian.Uint16(buf[12:14]) != ethPIPv6 {
			continue
		}
		ip6 := buf[14:n]
		if ip6[6] != 58 { // next header 58 = ICMPv6 (no extension headers)
			continue
		}
		payLen := int(binary.BigEndian.Uint16(ip6[4:6]))
		if payLen < 8 || 40+payLen > len(ip6) {
			continue
		}
		var src, dst [16]byte
		copy(src[:], ip6[8:24])
		copy(dst[:], ip6[24:40])
		msg := ip6[40 : 40+payLen]
		reqMAC := buf[6:12]

		switch msg[0] {
		case icmppkg.V6NeighborSol:
			// Target being resolved sits at offset 8..24 of the NS body.
			if len(msg) < 24 {
				continue
			}
			var target [16]byte
			copy(target[:], msg[8:24])
			host, ok := topo.hostByIP6[net.IP(target[:]).String()]
			if !ok {
				continue
			}
			// Solicited advertisement back to the soliciting node. During DAD
			// the source is unspecified (::) — answer the all-nodes multicast
			// with an unsolicited override instead.
			naDst := src
			flags := byte(0x60) // Router=0, Solicited, Override
			dstMAC := reqMAC
			if isZero16(src) {
				naDst = allNodesV6
				flags = 0x20 // Override only
				dstMAC = allNodesMAC[:]
			}
			na := icmppkg.NeighborAdvertV6(target, host.MAC, flags)
			frame := buildICMP6Frame(host.MAC, target, dstMAC, naDst, na, 255)
			sendFrame(fd, from, dstMAC, ethPIPv6, frame)
		case icmppkg.V6EchoRequest:
			host, ok := topo.hostByIP6[net.IP(dst[:]).String()]
			if !ok {
				continue
			}
			reply := icmppkg.EchoReplyV6(msg)
			if reply == nil {
				continue
			}
			frame := buildICMP6Frame(host.MAC, dst, reqMAC, src, reply, byte(host.Archetype.ICMPTTL()))
			sendFrame(fd, from, reqMAC, ethPIPv6, frame)
			reportICMP(onICMP, net.IP(src[:]).String(), net.IP(dst[:]).String(), host, 6, "echo6", int(msg[0]))
			slog.Debug("icmp6 echo replied", "requester", net.IP(src[:]).String(), "as_host", host.IPv6, "as_hostname", host.Hostname)
		}
	}
}

var (
	allNodesV6  = [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	allNodesMAC = [6]byte{0x33, 0x33, 0, 0, 0, 0x01}
)

func isZero16(a [16]byte) bool {
	for _, b := range a {
		if b != 0 {
			return false
		}
	}
	return true
}

// reportICMP emits a captured-probe notification (nil-safe).
func reportICMP(onICMP ICMPObserver, srcIP, dstIP string, host *Host, family int, kind string, icmpType int) {
	if onICMP == nil {
		return
	}
	meta := map[string]any{
		"icmp_type":   kind,
		"icmp_family": family,
		"icmp_code":   icmpType,
	}
	if host != nil && host.Hostname != "" {
		meta["honeynet_hostname"] = host.Hostname
	}
	onICMP(srcIP, dstIP, meta)
}

// sendFrame writes a fully-formed L2 frame back out the same socket, addressed
// to dstMAC. A nil frame (build failure) is dropped silently.
func sendFrame(fd int, from unix.Sockaddr, dstMAC []byte, ethType uint16, frame []byte) {
	if frame == nil {
		return
	}
	ll, ok := from.(*unix.SockaddrLinklayer)
	if !ok {
		return
	}
	dst := &unix.SockaddrLinklayer{
		Protocol: htons(ethType),
		Ifindex:  ll.Ifindex,
		Halen:    6,
	}
	copy(dst.Addr[:], dstMAC)
	if err := unix.Sendto(fd, frame, 0, dst); err != nil {
		slog.Debug("icmp responder send", "err", err)
	}
}

// buildICMPFrame wraps a fully-formed ICMP message (already typed +
// checksummed by the icmp package) in an Ethernet + IPv4 frame sourced
// from the virtual host and addressed to the requester.
func buildICMPFrame(ourMAC [6]byte, ourIP string, requesterMAC []byte, requesterIP net.IP, icmp []byte, ttl byte) []byte {
	ourIP4 := net.ParseIP(ourIP).To4()
	if ourIP4 == nil || requesterIP.To4() == nil {
		return nil
	}
	if ttl == 0 {
		ttl = 64
	}
	totalLen := 20 + len(icmp)
	frame := make([]byte, 14+totalLen)
	// Ethernet
	copy(frame[0:6], requesterMAC)
	copy(frame[6:12], ourMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], ethPIPv4)
	// IPv4 header
	ip := frame[14:]
	ip[0] = 0x45 // version=4, IHL=5
	ip[1] = 0
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:6], 0)      // identification
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // DF, frag=0
	ip[8] = ttl                                 // TTL (archetype personality)
	ip[9] = 1                                   // ICMP
	copy(ip[12:16], ourIP4)
	copy(ip[16:20], requesterIP.To4())
	ipcs := internetChecksum(ip[:20])
	ip[10] = byte(ipcs >> 8)
	ip[11] = byte(ipcs)
	copy(ip[20:], icmp)
	return frame
}

// buildICMP6Frame wraps an ICMPv6 message in an Ethernet + IPv6 frame. The
// ICMPv6 checksum (which covers the IPv6 pseudo-header) is computed here from
// the chosen src/dst addresses. hop is the IPv6 hop limit (255 for Neighbor
// Discovery; the archetype TTL for echo replies).
func buildICMP6Frame(ourMAC [6]byte, srcIP6 [16]byte, dstMAC []byte, dstIP6 [16]byte, icmp []byte, hop byte) []byte {
	if len(icmp) < 4 {
		return nil
	}
	if hop == 0 {
		hop = 64
	}
	icmppkg.ChecksumV6(icmp, srcIP6, dstIP6)
	payLen := len(icmp)
	frame := make([]byte, 14+40+payLen)
	// Ethernet
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], ourMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], ethPIPv6)
	// IPv6 header
	ip := frame[14:]
	ip[0] = 0x60 // version=6
	binary.BigEndian.PutUint16(ip[4:6], uint16(payLen))
	ip[6] = 58 // next header = ICMPv6
	ip[7] = hop
	copy(ip[8:24], srcIP6[:])
	copy(ip[24:40], dstIP6[:])
	copy(ip[40:], icmp)
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
