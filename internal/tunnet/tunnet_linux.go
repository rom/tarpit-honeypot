//go:build linux

// Package tunnet opens a Linux TUN device, claims the honeynet IP range
// at the L3 layer, and answers reconnaissance probes (ICMP echo for
// IPv4, ICMPv6 echo for IPv6) so the artificial network appears alive
// without the operator running `ip addr add` for every virtual host IP.
//
// TCP is handled by the embedded userspace stack (internal/tcpstack):
// SYNs to a host's configured open ports complete a handshake and get a
// fingerprint-shaped SYN-ACK (TTL/window/MSS/options matched to the
// host's archetype) plus a single request/response, while unbound ports
// answer with RST and malformed/illegal packets are captured as events.
// This makes the honeynet a believable decoy under `nmap -sV`/`-O` and
// p0f without a real socket bound per virtual host. The legacy RST-only
// behavior is preserved automatically when a host exposes no open ports.
//
// IPv6 reconnaissance gets parity at the SYN layer: an IPv6 SYN to an
// open port of an IPv6 virtual host is answered with a SYN-ACK and
// surfaced as a handshake event (so v6 scans are observed and
// correlatable), and closed ports get a RST. The stateful data phase
// (banners, request/response) remains IPv4-only — a second full TCP/IP
// implementation is out of scope; this is detection + "looks open" parity.
//
// CAP_NET_ADMIN is required to create the TUN device; the existing
// systemd unit already grants it via AmbientCapabilities.
package tunnet

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/rom/tarpit-honeypot/internal/tcpstack"
	"golang.org/x/sys/unix"
)

// Config is the per-honeynet TUN parameters.
type Config struct {
	DeviceName string   // requested TUN name; empty = kernel-chosen
	CIDRs      []string // ip ranges the operator wants routed through this TUN
	HostIPs    []string // virtual host IPs this TUN claims
	MTU        int      // 0 -> 1500
	// Personas maps a host IP to the initial IP TTL its synthesized
	// responses should carry (TCP/IP stack personality). 64 = Linux/BSD,
	// 128 = Windows, 255 = network/OT gear. Absent / 0 -> 64. Stamping
	// the host's own TTL (instead of echoing the prober's) makes nmap -O
	// + traceroute hop-distance consistent with the host's archetype.
	Personas map[string]int

	// Hosts supplies the per-host userspace-TCP decoy behavior (open
	// ports, OS fingerprint, banners). Hosts absent here still answer
	// ICMP and RST every TCP port (legacy L3 behavior).
	Hosts map[string]HostDecoy
	// Emit publishes a userspace-stack event (handshake / request /
	// malformed packet) to the sensor bus. nil drops them.
	Emit func(tcpstack.Event)
}

// HostDecoy describes how one virtual host terminates TCP: which ports
// accept, the OS fingerprint the SYN-ACK is shaped to, and the bytes the
// decoy speaks. Banners are sent right after the handshake (server-first
// services like SSH/FTP/SMTP); Replies answer the first client request
// (client-first services like HTTP). A port present in Ports but in
// neither map completes the handshake then stays silent — still "open".
type HostDecoy struct {
	Profile tcpstack.OSProfile
	Ports   map[uint16]bool
	Banners map[uint16][]byte
	Replies map[uint16][]byte
}

// Adapter holds the TUN fd, the parsed host-IP set, and runs the
// per-packet responder in Run.
type Adapter struct {
	cfg     Config
	tunFD   int
	tunName string
	mtu     int

	hostsV4 map[[4]byte]bool
	hostsV6 map[[16]byte]bool

	ttlV4 map[[4]byte]byte
	ttlV6 map[[16]byte]byte

	// decoysV6 maps an IPv6 host to its open-port set so an IPv6 SYN to an
	// open port can be acknowledged (SYN-ACK) and surfaced as a handshake
	// event, giving IPv6 reconnaissance the same visibility as IPv4. The
	// full stateful data-phase stack remains IPv4-only by design.
	decoysV6 map[[16]byte]HostDecoy

	stack *tcpstack.Stack
	emit  func(tcpstack.Event)

	mu     sync.Mutex
	closed bool

	pktsIn      uint64
	icmpReplies uint64
}

// New opens the TUN device + parses the host IPs. The caller must invoke
// Run(ctx) to start the responder loop.
func New(cfg Config) (*Adapter, error) {
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}
	fd, name, err := openTUN(cfg.DeviceName)
	if err != nil {
		return nil, err
	}
	a := &Adapter{
		cfg:      cfg,
		tunFD:    fd,
		tunName:  name,
		mtu:      cfg.MTU,
		hostsV4:  map[[4]byte]bool{},
		hostsV6:  map[[16]byte]bool{},
		ttlV4:    map[[4]byte]byte{},
		ttlV6:    map[[16]byte]byte{},
		decoysV6: map[[16]byte]HostDecoy{},
	}
	for ipStr, d := range cfg.Hosts {
		if addr, err := netip.ParseAddr(ipStr); err == nil && addr.Is6() && !addr.Is4In6() {
			a.decoysV6[addr.As16()] = d
		}
	}
	for _, ipStr := range cfg.HostIPs {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("tunnet: bad host ip %q: %w", ipStr, err)
		}
		ttl := byte(0)
		if t, ok := cfg.Personas[ipStr]; ok && t > 0 && t <= 255 {
			ttl = byte(t)
		}
		if addr.Is4() {
			a.hostsV4[addr.As4()] = true
			if ttl != 0 {
				a.ttlV4[addr.As4()] = ttl
			}
		} else {
			a.hostsV6[addr.As16()] = true
			if ttl != 0 {
				a.ttlV6[addr.As16()] = ttl
			}
		}
	}
	a.emit = cfg.Emit
	a.stack = newStack(cfg.Hosts)
	slog.Info("tunnet up",
		"device", name,
		"cidrs", cfg.CIDRs,
		"hosts_v4", len(a.hostsV4),
		"hosts_v6", len(a.hostsV6),
		"mtu", a.mtu,
	)
	slog.Info("tunnet: route hint",
		"hint", fmt.Sprintf("ip link set %s up; ip route add <cidr> dev %s", name, name))
	return a, nil
}

// Run reads packets from the TUN until ctx is cancelled. Drops packets
// not destined for one of our host IPs; replies to ICMP/ICMPv6 echo
// requests with echo replies and to TCP SYNs for unconfigured ports
// with RST.
func (a *Adapter) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		a.Close()
	}()
	// Reap idle half-open / lingering flows so a SYN flood can't grow the
	// stack's flow table without bound.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.stack.Sweep()
			}
		}
	}()
	buf := make([]byte, a.mtu)
	for {
		n, err := unix.Read(a.tunFD, buf)
		if err != nil {
			if errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINTR) {
				return nil
			}
			if ctx.Err() != nil {
				return nil
			}
			slog.Debug("tunnet read", "err", err)
			continue
		}
		if n < 1 {
			continue
		}
		a.pktsIn++
		switch buf[0] >> 4 {
		case 4:
			a.handleIPv4(buf[:n])
		case 6:
			a.handleIPv6(buf[:n])
		}
	}
}

const defaultTTL = 64

// ttlFor4 returns the configured persona TTL for one of our host IPs, or
// the Linux/BSD default of 64.
func (a *Adapter) ttlFor4(dst [4]byte) byte {
	if t, ok := a.ttlV4[dst]; ok {
		return t
	}
	return defaultTTL
}

func (a *Adapter) ttlFor6(dst [16]byte) byte {
	if t, ok := a.ttlV6[dst]; ok {
		return t
	}
	return defaultTTL
}

func (a *Adapter) handleIPv4(pkt []byte) {
	if len(pkt) < 20 {
		return
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || ihl > len(pkt) {
		return
	}
	proto := pkt[9]
	var dst [4]byte
	copy(dst[:], pkt[16:20])
	if !a.hostsV4[dst] {
		return
	}
	var src [4]byte
	copy(src[:], pkt[12:16])
	switch proto {
	case 1:
		a.handleICMPv4(pkt, ihl, src, dst)
	case 6:
		a.handleTCPv4(pkt)
	}
}

func (a *Adapter) handleICMPv4(pkt []byte, ihl int, src, dst [4]byte) {
	icmp := pkt[ihl:]
	if len(icmp) < 8 || icmp[0] != 8 { // echo request
		return
	}
	reply := buildEchoReplyV4(pkt, ihl, src, dst, a.ttlFor4(dst))
	if _, err := unix.Write(a.tunFD, reply); err != nil {
		slog.Debug("tunnet write icmp", "err", err)
		return
	}
	a.icmpReplies++
}

// buildEchoReplyV4 turns an ICMP echo request into a reply: swaps the
// addresses, stamps our own initial TTL (so the host's OS/hop-distance
// fingerprint is consistent rather than echoing the prober's), flips the
// ICMP type to 0, and recomputes both checksums.
func buildEchoReplyV4(pkt []byte, ihl int, src, dst [4]byte, ttl byte) []byte {
	reply := make([]byte, len(pkt))
	copy(reply, pkt)
	copy(reply[12:16], dst[:])
	copy(reply[16:20], src[:])
	reply[8] = ttl
	reply[10], reply[11] = 0, 0
	binary.BigEndian.PutUint16(reply[10:12], internetChecksum(reply[:ihl]))
	reply[ihl] = 0 // type 0 = echo reply
	reply[ihl+2], reply[ihl+3] = 0, 0
	binary.BigEndian.PutUint16(reply[ihl+2:ihl+4], internetChecksum(reply[ihl:]))
	return reply
}

// newStack builds the userspace TCP engine from the per-host decoy map.
// The Profile/Open/Responder closures index an IPv4-keyed copy so the hot
// path never reparses host-IP strings. With an empty map the stack RSTs
// every TCP port (the legacy L3 responder behavior).
func newStack(hosts map[string]HostDecoy) *tcpstack.Stack {
	decoys := make(map[[4]byte]HostDecoy, len(hosts))
	for ipStr, d := range hosts {
		if addr, err := netip.ParseAddr(ipStr); err == nil && addr.Is4() {
			decoys[addr.As4()] = d
		}
	}
	return tcpstack.NewStack(tcpstack.Config{
		Profile: func(dst [4]byte) tcpstack.OSProfile {
			if d, ok := decoys[dst]; ok && d.Profile.Name != "" {
				return d.Profile
			}
			return tcpstack.ProfileFor("")
		},
		Open: func(dst [4]byte, port uint16) bool {
			d, ok := decoys[dst]
			return ok && d.Ports[port]
		},
		Responder: tcpstack.Responder{
			Banner:  func(dst [4]byte, port uint16) []byte { return decoys[dst].Banners[port] },
			Respond: func(dst [4]byte, port uint16, _ []byte) []byte { return decoys[dst].Replies[port] },
		},
	})
}

// handleTCPv4 feeds the segment to the userspace stack and writes back any
// synthesized packets (SYN-ACK, data, FIN, RST), emitting the handshake,
// request and malformed-packet events the stack surfaces.
func (a *Adapter) handleTCPv4(pkt []byte) {
	res := a.stack.OnPacket(pkt)
	for _, p := range res.Out {
		if _, err := unix.Write(a.tunFD, p); err != nil {
			slog.Debug("tunnet write tcp", "err", err)
		}
	}
	if a.emit != nil {
		for i := range res.Events {
			a.emit(res.Events[i])
		}
	}
}

func (a *Adapter) handleIPv6(pkt []byte) {
	if len(pkt) < 40 {
		return
	}
	nextHdr := pkt[6]
	var dst [16]byte
	copy(dst[:], pkt[24:40])
	if !a.hostsV6[dst] {
		return
	}
	var src [16]byte
	copy(src[:], pkt[8:24])
	switch nextHdr {
	case 58:
		a.handleICMPv6(pkt, src, dst)
	case 6:
		a.handleTCPv6(pkt, src, dst)
	}
}

// handleTCPv6 gives IPv6 TCP reconnaissance the same visibility as IPv4: a SYN
// to an open port of a virtual host is acknowledged (SYN-ACK) and surfaced as a
// handshake event; a SYN to any other port gets a RST, exactly like a real
// host. The stateful data phase (banners, request/response, the full
// userspace stack) remains IPv4-only — this is detection + "looks open"
// parity, not a second TCP/IP implementation.
func (a *Adapter) handleTCPv6(pkt []byte, src, dst [16]byte) {
	const ipv6HdrLen = 40
	if len(pkt) < ipv6HdrLen+20 {
		return
	}
	tcp := pkt[ipv6HdrLen:]
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	seq := binary.BigEndian.Uint32(tcp[4:8])
	flags := tcp[13]
	const synFlag, ackFlag, rstFlag = 0x02, 0x10, 0x04
	// Only react to a bare SYN (connection attempt). Anything else from a
	// flow we never tracked just gets a RST if it's not already one.
	isSyn := flags&synFlag != 0 && flags&ackFlag == 0
	d, isHost := a.decoysV6[dst]
	open := isHost && d.Ports[dstPort]

	if isSyn && open {
		a.writeTCPv6(dst, src, dstPort, srcPort, seq+1, 0x7fffabcd, synFlag|ackFlag)
		if a.emit != nil {
			a.emit(tcpstack.Event{
				Kind:   tcpstack.EventHandshake,
				SrcIP6: src, DstIP6: dst, IsV6: true,
				SrcPort: srcPort, DstPort: dstPort,
			})
		}
		return
	}
	// Closed port (or stray non-SYN): mimic a real host's RST, but never
	// answer a RST with a RST.
	if flags&rstFlag == 0 {
		ack := seq + 1
		a.writeTCPv6(dst, src, dstPort, srcPort, ack, 0, rstFlag|ackFlag)
	}
}

// writeTCPv6 synthesizes a 40-byte-header IPv6 + 20-byte-header TCP segment
// (no options/payload) and writes it to the TUN device.
func (a *Adapter) writeTCPv6(src, dst [16]byte, srcPort, dstPort uint16, ack, seq uint32, flags byte) {
	const ipv6HdrLen, tcpHdrLen = 40, 20
	pkt := make([]byte, ipv6HdrLen+tcpHdrLen)
	// IPv6 header.
	pkt[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(pkt[4:6], tcpHdrLen)
	pkt[6] = 6 // next header = TCP
	pkt[7] = a.ttlFor6(src)
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])
	// TCP header.
	tcp := pkt[ipv6HdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = (tcpHdrLen / 4) << 4 // data offset
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 0xfaf0) // window
	cs := tcpv6Checksum(src[:], dst[:], tcp)
	binary.BigEndian.PutUint16(tcp[16:18], cs)
	if _, err := unix.Write(a.tunFD, pkt); err != nil {
		slog.Debug("tunnet write tcpv6", "err", err)
	}
}

func (a *Adapter) handleICMPv6(pkt []byte, src, dst [16]byte) {
	const ipv6HdrLen = 40
	if len(pkt) < ipv6HdrLen+8 || pkt[ipv6HdrLen] != 128 {
		return
	}
	reply := make([]byte, len(pkt))
	copy(reply, pkt)
	copy(reply[8:24], dst[:])
	copy(reply[24:40], src[:])
	reply[7] = a.ttlFor6(dst) // hop limit = our persona TTL
	reply[ipv6HdrLen] = 129
	reply[ipv6HdrLen+2], reply[ipv6HdrLen+3] = 0, 0
	cs := icmpv6Checksum(dst[:], src[:], reply[ipv6HdrLen:])
	binary.BigEndian.PutUint16(reply[ipv6HdrLen+2:ipv6HdrLen+4], cs)
	if _, err := unix.Write(a.tunFD, reply); err != nil {
		slog.Debug("tunnet write icmpv6", "err", err)
		return
	}
	a.icmpReplies++
}

func (a *Adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	if a.tunFD >= 0 {
		_ = unix.Close(a.tunFD)
		a.tunFD = -1
	}
	var st tcpstack.Stats
	if a.stack != nil {
		st = a.stack.Stats()
	}
	slog.Info("tunnet down",
		"device", a.tunName,
		"packets_in", a.pktsIn,
		"icmp_replies", a.icmpReplies,
		"tcp_handshakes", st.Handshakes,
		"tcp_requests", st.Requests,
		"tcp_rsts", st.Resets,
		"tcp_malformed", st.Malformed,
	)
	return nil
}

func openTUN(want string) (int, string, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("tunnet: open /dev/net/tun: %w", err)
	}
	type ifReq struct {
		Name  [16]byte
		Flags uint16
		_     [22]byte
	}
	var req ifReq
	copy(req.Name[:], want)
	req.Flags = unix.IFF_TUN | unix.IFF_NO_PI
	const TUNSETIFF = 0x400454ca
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		_ = unix.Close(fd)
		return -1, "", fmt.Errorf("tunnet: TUNSETIFF: %w", errno)
	}
	name := ""
	for i, b := range req.Name {
		if b == 0 {
			name = string(req.Name[:i])
			break
		}
	}
	if name == "" {
		name = string(req.Name[:])
	}
	if err := setLinkUp(name); err != nil {
		slog.Warn("tunnet: could not bring interface up",
			"interface", name, "err", err,
			"hint", "run `ip link set "+name+" up` manually")
	}
	return fd, name, nil
}

func setLinkUp(name string) error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(s)
	type ifReq struct {
		Name  [16]byte
		Flags uint16
		_     [22]byte
	}
	var req ifReq
	copy(req.Name[:], name)
	const SIOCGIFFLAGS = 0x8913
	const SIOCSIFFLAGS = 0x8914
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(s), uintptr(SIOCGIFFLAGS), uintptr(unsafe.Pointer(&req))); errno != 0 {
		return errno
	}
	req.Flags |= unix.IFF_UP
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(s), uintptr(SIOCSIFFLAGS), uintptr(unsafe.Pointer(&req))); errno != 0 {
		return errno
	}
	return nil
}

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

func icmpv6Checksum(src, dst net.IP, icmp []byte) uint16 {
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], src)
	copy(pseudo[16:32], dst)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(icmp)))
	pseudo[39] = 58
	return sumOver(pseudo, icmp)
}

// tcpv6Checksum computes the TCP checksum over the IPv6 pseudo-header + segment
// (the segment's checksum field must be zero on entry). src/dst are the source
// and destination IPv6 addresses of the segment being sent.
func tcpv6Checksum(src, dst []byte, tcp []byte) uint16 {
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], src)
	copy(pseudo[16:32], dst)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(tcp)))
	pseudo[39] = 6 // next header = TCP
	return sumOver(pseudo, tcp)
}

func sumOver(a, b []byte) uint16 {
	var sum uint32
	add := func(s []byte) {
		for i := 0; i+1 < len(s); i += 2 {
			sum += uint32(s[i])<<8 | uint32(s[i+1])
		}
		if len(s)%2 == 1 {
			sum += uint32(s[len(s)-1]) << 8
		}
	}
	add(a)
	add(b)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
