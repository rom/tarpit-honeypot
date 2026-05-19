//go:build linux

// Package tunnet opens a Linux TUN device, claims the honeynet IP range
// at the L3 layer, and answers low-level reconnaissance probes (ICMP
// echo for IPv4, ICMPv6 echo for IPv6, TCP RST for unbound ports) so
// the artificial network appears alive without the operator running
// `ip addr add` for every virtual host IP.
//
// Scope intentionally limited: this is an IP-layer responder, NOT a
// userspace TCP stack. Real protocol termination for honeynet hosts
// still flows through the regular socket listeners (which require
// either `ip addr add`, iptables DNAT, or the operator routing the
// TUN destination back into the sensor via NAT). For SYN scans alone
// the TUN responder is enough — `nmap` reports the host as up with
// the configured ports either closed (RST) or, when an actual handler
// is bound via a sibling listener, open.
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
	"unsafe"

	"golang.org/x/sys/unix"
)

// Config is the per-honeynet TUN parameters.
type Config struct {
	DeviceName string   // requested TUN name; empty = kernel-chosen
	CIDRs      []string // ip ranges the operator wants routed through this TUN
	HostIPs    []string // virtual host IPs this TUN claims
	MTU        int      // 0 -> 1500
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

	mu     sync.Mutex
	closed bool

	pktsIn      uint64
	icmpReplies uint64
	tcpRsts     uint64
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
		cfg:     cfg,
		tunFD:   fd,
		tunName: name,
		mtu:     cfg.MTU,
		hostsV4: map[[4]byte]bool{},
		hostsV6: map[[16]byte]bool{},
	}
	for _, ipStr := range cfg.HostIPs {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("tunnet: bad host ip %q: %w", ipStr, err)
		}
		if addr.Is4() {
			a.hostsV4[addr.As4()] = true
		} else {
			a.hostsV6[addr.As16()] = true
		}
	}
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
		a.handleTCPv4(pkt, ihl, src, dst)
	}
}

func (a *Adapter) handleICMPv4(pkt []byte, ihl int, src, dst [4]byte) {
	icmp := pkt[ihl:]
	if len(icmp) < 8 || icmp[0] != 8 { // echo request
		return
	}
	reply := make([]byte, len(pkt))
	copy(reply, pkt)
	copy(reply[12:16], dst[:])
	copy(reply[16:20], src[:])
	reply[10], reply[11] = 0, 0
	binary.BigEndian.PutUint16(reply[10:12], internetChecksum(reply[:ihl]))
	reply[ihl] = 0
	reply[ihl+2], reply[ihl+3] = 0, 0
	binary.BigEndian.PutUint16(reply[ihl+2:ihl+4], internetChecksum(reply[ihl:]))
	if _, err := unix.Write(a.tunFD, reply); err != nil {
		slog.Debug("tunnet write icmp", "err", err)
		return
	}
	a.icmpReplies++
}

func (a *Adapter) handleTCPv4(pkt []byte, ihl int, src, dst [4]byte) {
	tcp := pkt[ihl:]
	if len(tcp) < 20 {
		return
	}
	flags := tcp[13]
	if flags&0x02 == 0 || flags&0x10 != 0 {
		return
	}
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	clientSeq := binary.BigEndian.Uint32(tcp[4:8])

	out := make([]byte, 40)
	out[0] = 0x45
	binary.BigEndian.PutUint16(out[2:4], 40)
	binary.BigEndian.PutUint16(out[6:8], 0x4000)
	out[8] = 64
	out[9] = 6
	copy(out[12:16], dst[:])
	copy(out[16:20], src[:])
	binary.BigEndian.PutUint16(out[10:12], internetChecksum(out[:20]))
	t := out[20:]
	binary.BigEndian.PutUint16(t[0:2], dstPort)
	binary.BigEndian.PutUint16(t[2:4], srcPort)
	binary.BigEndian.PutUint32(t[4:8], 0)
	binary.BigEndian.PutUint32(t[8:12], clientSeq+1)
	t[12] = 0x50
	t[13] = 0x14 // RST + ACK
	binary.BigEndian.PutUint16(t[14:16], 0)
	binary.BigEndian.PutUint16(t[18:20], 0)
	binary.BigEndian.PutUint16(t[16:18], tcpChecksumV4(dst[:], src[:], t))
	if _, err := unix.Write(a.tunFD, out); err != nil {
		slog.Debug("tunnet write tcp", "err", err)
		return
	}
	a.tcpRsts++
	_ = srcPort
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
	slog.Info("tunnet down",
		"device", a.tunName,
		"packets_in", a.pktsIn,
		"icmp_replies", a.icmpReplies,
		"tcp_rsts", a.tcpRsts,
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

func tcpChecksumV4(src, dst net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))
	return sumOver(pseudo, tcp)
}

func icmpv6Checksum(src, dst net.IP, icmp []byte) uint16 {
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], src)
	copy(pseudo[16:32], dst)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(icmp)))
	pseudo[39] = 58
	return sumOver(pseudo, icmp)
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
