//go:build linux

package sniffer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/p0f"
)

type linuxSniffer struct {
	cfg        config.Sniffer
	sensorName string
	sev        event.Severity

	mu    sync.Mutex
	state map[string]*scanState // key: source MAC string

	tcp    *scanTracker  // nil unless TCPScan enabled
	frag   *rateLimiter  // nil unless TCPScan enabled
	encap  *rateLimiter  // nil unless TCPScan enabled (encapsulation + STP dedup)
	goose  *rateLimiter  // nil unless GOOSE enabled
	gooseT *gooseTracker // nil unless GOOSE enabled (stateful attack analysis)

	p0fDB *p0f.DB // passive OS fingerprint DB (embedded curated set + optional p0f.fp)

	// L2 frame counters (atomic; surfaced via Stats).
	cFrames, cARP, cIPv4, cIPv6, cTCP, cUDP, cICMP, cOther atomic.Uint64
}

// Stats returns a snapshot of the L2 frame counters.
func (s *linuxSniffer) Stats() Stats {
	return Stats{
		Frames: s.cFrames.Load(), ARP: s.cARP.Load(), IPv4: s.cIPv4.Load(),
		IPv6: s.cIPv6.Load(), TCP: s.cTCP.Load(), UDP: s.cUDP.Load(),
		ICMP: s.cICMP.Load(), Other: s.cOther.Load(),
	}
}

// countL4 peeks the IP-header protocol byte of a captured frame (eth header
// is 14 bytes on these per-ethertype sockets) and bumps the TCP/UDP/ICMP
// counter. Coarse: it reads only the first next-header on IPv6 (extension
// headers are not unwound) — enough for an at-a-glance traffic mix.
func (s *linuxSniffer) countL4(frame []byte, v6 bool) {
	var proto byte
	if v6 {
		if len(frame) < 21 {
			return
		}
		proto = frame[20] // IPv6 next-header
	} else {
		if len(frame) < 24 {
			return
		}
		proto = frame[23] // IPv4 protocol
	}
	switch proto {
	case 6:
		s.cTCP.Add(1)
	case 17:
		s.cUDP.Add(1)
	case 1:
		if v6 {
			s.cOther.Add(1)
		} else {
			s.cICMP.Add(1)
		}
	case 58:
		if v6 {
			s.cICMP.Add(1) // ICMPv6
		} else {
			s.cOther.Add(1)
		}
	default:
		s.cOther.Add(1)
	}
}

type scanState struct {
	since time.Time
	ips   map[string]struct{}
	// dedup of aggregate emission per source MAC
	lastFired time.Time
}

func newImpl(cfg config.Sniffer, sensorName string) (Sniffer, error) {
	sev, err := event.ParseSeverity(cfg.Severity)
	if err != nil {
		return nil, err
	}
	s := &linuxSniffer{
		cfg:        cfg,
		sensorName: sensorName,
		sev:        sev,
		state:      map[string]*scanState{},
		p0fDB:      p0f.New(),
	}
	if cfg.P0fDB != "" {
		if n, err := s.p0fDB.LoadFile(cfg.P0fDB); err != nil {
			slog.Warn("sniffer: p0f db unavailable; using built-in signatures only", "path", cfg.P0fDB, "err", err)
		} else {
			slog.Info("sniffer: p0f signatures loaded", "path", cfg.P0fDB, "added", n, "total", s.p0fDB.Count())
		}
	}
	if cfg.TCPScan.Enabled {
		s.tcp = newScanTracker(cfg.TCPScan.Window, cfg.TCPScan.DistinctPorts, cfg.TCPScan.StealthPorts)
		s.frag = newRateLimiter(cfg.TCPScan.Window)
		s.encap = newRateLimiter(cfg.TCPScan.Window)
	}
	if cfg.GOOSE.Enabled {
		w := cfg.GOOSE.Window
		if w <= 0 {
			w = 60 * time.Second
		}
		s.goose = newRateLimiter(w)
		s.gooseT = newGOOSETracker()
	}
	return s, nil
}

const (
	ethPARP    = 0x0806
	ethPIP     = 0x0800
	ethPIP6    = 0x86DD
	ethPALL    = 0x0003
	ethPGOOSE  = 0x88B8
	arpRequest = 1
	arpReply   = 2
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func (s *linuxSniffer) Run(ctx context.Context, bus chan<- *event.Event) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return fmt.Errorf("sniffer: need CAP_NET_RAW (try running as root or grant the cap): %w", err)
		}
		return fmt.Errorf("sniffer: socket: %w", err)
	}
	defer unix.Close(fd)

	ifaceIdx := 0
	if s.cfg.Interface != "" {
		iface, err := net.InterfaceByName(s.cfg.Interface)
		if err != nil {
			return fmt.Errorf("sniffer: interface %s: %w", s.cfg.Interface, err)
		}
		ifaceIdx = iface.Index
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(ethPARP),
		Ifindex:  ifaceIdx,
	}); err != nil {
		return fmt.Errorf("sniffer: bind: %w", err)
	}

	slog.Info("sniffer up", "interface", s.cfg.Interface, "arp_scan_threshold", s.cfg.ARPScan.DistinctIPs, "window", s.cfg.ARPScan.Window)

	// Close the fd when ctx cancels so the blocking Recvfrom returns.
	go func() {
		<-ctx.Done()
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		_ = unix.Close(fd)
	}()

	// Packet-capture scan-detection layer (TCP stealth/volume scans),
	// on its own AF_PACKET socket so the ARP path is unaffected.
	if s.tcp != nil {
		go s.runIPCapture(ctx, bus)
		go s.runIP6Capture(ctx, bus)
	}
	if s.goose != nil {
		go s.runGOOSECapture(ctx, bus)
	}

	buf := make([]byte, 2048)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINTR) {
				return nil
			}
			slog.Warn("sniffer: recvfrom", "err", err)
			continue
		}
		if n < 14 {
			continue
		}
		frame := buf[:n]
		s.cFrames.Add(1)
		// Spanning-tree BPDUs are non-IP 802.3/LLC frames on this socket.
		if s.encap != nil && s.handleSTP(ctx, frame, bus) {
			s.cOther.Add(1)
			continue
		}
		if n < 14+28 {
			continue
		}
		s.cARP.Add(1)
		s.handleARP(ctx, frame, bus)
	}
}

// handleSTP recognizes and reports a spanning-tree BPDU (STP/RSTP/MSTP/
// PVST+). Returns true when the frame was a BPDU (handled). BPDUs are
// periodic, so emission is rate-limited per (source MAC, variant); a host
// receiving them at all is worth surfacing (mis-cabled edge port, or an
// injected root-bridge / topology-manipulation attempt → AiTM).
func (s *linuxSniffer) handleSTP(ctx context.Context, frame []byte, bus chan<- *event.Event) bool {
	variant, srcMAC, ok := parseSTP(frame)
	if !ok {
		return false
	}
	if s.encap.allow("stp:"+srcMAC+":"+variant, time.Now()) {
		ev := s.newEvent("sniffer:stp_bpdu", event.SeverityLow, srcMAC, "", "")
		ev.Proto = "stp"
		ev.Meta["stp_variant"] = variant
		send(ctx, bus, ev)
	}
	return true
}

// handleARP parses one Ethernet frame carrying an ARP packet and updates
// the per-source-MAC counter. Emits scan / spoof events as warranted.
func (s *linuxSniffer) handleARP(ctx context.Context, frame []byte, bus chan<- *event.Event) {
	// EtherType check: bytes 12..13.
	if binary.BigEndian.Uint16(frame[12:14]) != ethPARP {
		return
	}
	arp := frame[14:]
	if len(arp) < 28 {
		return
	}
	hwType := binary.BigEndian.Uint16(arp[0:2])
	protoType := binary.BigEndian.Uint16(arp[2:4])
	op := binary.BigEndian.Uint16(arp[6:8])
	if hwType != 1 || protoType != 0x0800 {
		return
	}
	srcMAC := net.HardwareAddr(arp[8:14]).String()
	srcIP := net.IP(arp[14:18]).String()
	dstIP := net.IP(arp[24:28]).String()

	switch op {
	case arpRequest:
		s.updateScan(ctx, srcMAC, srcIP, dstIP, bus)
	case arpReply:
		// Unsolicited reply heuristic: we never tracked a corresponding
		// request and the reply isn't gratuitous (src_ip == target_ip).
		if srcIP != dstIP {
			ev := s.newEvent("sniffer:arp_reply_unsolicited", event.SeverityMedium, srcMAC, srcIP, dstIP)
			ev.Meta["target_ip"] = dstIP
			send(ctx, bus, ev)
		}
	}
}

func (s *linuxSniffer) updateScan(ctx context.Context, srcMAC, srcIP, dstIP string, bus chan<- *event.Event) {
	cfg := s.cfg.ARPScan
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	st, ok := s.state[srcMAC]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &scanState{since: now, ips: map[string]struct{}{}}
		s.state[srcMAC] = st
	}
	st.ips[dstIP] = struct{}{}
	if len(st.ips) < cfg.DistinctIPs {
		return
	}
	if now.Sub(st.lastFired) < cfg.Window {
		return
	}
	st.lastFired = now
	ev := s.newEvent("sniffer:arp_scan", s.sev, srcMAC, srcIP, "")
	ev.Meta["distinct_targets"] = len(st.ips)
	ev.Meta["window_s"] = int(cfg.Window.Seconds())
	send(ctx, bus, ev)
}

func (s *linuxSniffer) newEvent(ruleID string, sev event.Severity, srcMAC, srcIP, dstIP string) *event.Event {
	return &event.Event{
		ID:       event.NewID(),
		Time:     time.Now().UTC(),
		Sensor:   s.sensorName,
		RuleID:   ruleID,
		Severity: sev,
		Source:   event.Endpoint{IP: srcIP},
		Dest:     event.Endpoint{IP: dstIP},
		Proto:    "arp",
		Meta: map[string]any{
			"src_mac": srcMAC,
		},
	}
}

// runIPCapture opens a second AF_PACKET socket filtered to inbound IPv4
// and classifies TCP segments into scan events. Runs until ctx cancels.
func (s *linuxSniffer) runIPCapture(ctx context.Context, bus chan<- *event.Event) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPALL)))
	if err != nil {
		slog.Warn("sniffer: tcp-scan socket (need CAP_NET_RAW)", "err", err)
		return
	}
	defer unix.Close(fd)

	ifaceIdx := 0
	if s.cfg.Interface != "" {
		if iface, err := net.InterfaceByName(s.cfg.Interface); err == nil {
			ifaceIdx = iface.Index
		}
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(ethPIP),
		Ifindex:  ifaceIdx,
	}); err != nil {
		slog.Warn("sniffer: tcp-scan bind", "err", err)
		return
	}
	slog.Info("sniffer: tcp-scan up",
		"distinct_ports", s.cfg.TCPScan.DistinctPorts,
		"stealth_ports", s.cfg.TCPScan.StealthPorts,
		"window", s.cfg.TCPScan.Window,
		"detect_fragments", s.cfg.TCPScan.DetectFragments)

	go func() {
		<-ctx.Done()
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		_ = unix.Close(fd)
	}()

	// Periodic GC keeps the per-source state bounded.
	go func() {
		t := time.NewTicker(s.cfg.TCPScan.Window)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				s.tcp.gc(now)
			}
		}
	}()

	buf := make([]byte, 2048)
	for {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINTR) {
				return
			}
			slog.Warn("sniffer: tcp-scan recvfrom", "err", err)
			continue
		}
		// Only inbound frames — never classify our own replies.
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		s.cFrames.Add(1)
		s.cIPv4.Add(1)
		s.countL4(buf[:n], false)
		s.handleIPFrame(ctx, buf[:n], bus)
	}
}

// runIP6Capture is the IPv6 counterpart of runIPCapture: a third AF_PACKET
// socket bound to ETH_P_IPV6 so the scan / tunnelling / fragmentation
// detectors also see IPv6 traffic (DS-Lite, GRE-over-IPv6, IPv6 scans).
func (s *linuxSniffer) runIP6Capture(ctx context.Context, bus chan<- *event.Event) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPIP6)))
	if err != nil {
		slog.Warn("sniffer: ipv6-scan socket (need CAP_NET_RAW)", "err", err)
		return
	}
	defer unix.Close(fd)

	ifaceIdx := 0
	if s.cfg.Interface != "" {
		if iface, err := net.InterfaceByName(s.cfg.Interface); err == nil {
			ifaceIdx = iface.Index
		}
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(ethPIP6),
		Ifindex:  ifaceIdx,
	}); err != nil {
		slog.Warn("sniffer: ipv6-scan bind", "err", err)
		return
	}
	go func() {
		<-ctx.Done()
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		_ = unix.Close(fd)
	}()

	buf := make([]byte, 2048)
	for {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINTR) {
				return
			}
			slog.Warn("sniffer: ipv6-scan recvfrom", "err", err)
			continue
		}
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		s.cFrames.Add(1)
		s.cIPv6.Add(1)
		s.countL4(buf[:n], true)
		s.handleIP6Frame(ctx, buf[:n], bus)
	}
}

// handleIP6Frame classifies one captured IPv6 frame: fragmentation,
// tunnelling (DS-Lite / GRE-over-IPv6 / IPv6-in-IPv6 / …), ICMPv6 echo
// tunnels, and TCP/UDP scans — the IPv6 mirror of handleIPFrame.
func (s *linuxSniffer) handleIP6Frame(ctx context.Context, frame []byte, bus chan<- *event.Event) {
	info, ok := parseIPv6(frame)
	if !ok {
		return
	}
	now := time.Now()

	if info.fragmented {
		if s.cfg.TCPScan.DetectFragments && s.frag.allow("v6:"+info.srcIP, now) {
			ev := s.newIPEvent("sniffer:ip_fragmented", event.SeverityMedium, info.srcIP, "ipv6")
			ev.Meta["ip_proto"] = int(info.nextHdr)
			addHopGuess(ev, info.hopLimit)
			send(ctx, bus, ev)
		}
		return
	}
	if name := encapByProto6(info.nextHdr); name != "" {
		if s.encap.allow("encap6:"+info.srcIP+":"+name, now) {
			ev := s.newIPEvent("sniffer:encapsulation", event.SeverityMedium, info.srcIP, name)
			ev.Meta["encap_type"] = name
			ev.Meta["ip_proto"] = int(info.nextHdr)
			ev.Meta["ip_version"] = 6
			addHopGuess(ev, info.hopLimit)
			send(ctx, bus, ev)
		}
		return
	}

	switch info.nextHdr {
	case 58: // ICMPv6 — echo-based covert tunnel
		dataLen, tunnel := icmpv6EchoTunnel(info.payload)
		if !tunnel {
			return
		}
		if s.encap.allow("icmptun6:"+info.srcIP, now) {
			ev := s.newIPEvent("sniffer:icmp_tunnel", event.SeverityHigh, info.srcIP, "icm6")
			ev.Meta["icmp_data_len"] = dataLen
			addHopGuess(ev, info.hopLimit)
			send(ctx, bus, ev)
		}
	case 6: // TCP
		port, flags, ok := parseTCP(info.payload)
		if !ok {
			return
		}
		kind := classifyTCP(flags)
		if kind == scanNone {
			return
		}
		count, fire := s.tcp.observe(info.srcIP, port, kind, now)
		if !fire {
			return
		}
		ev := s.newIPEvent(kind.ruleID(), s.sev, info.srcIP, "tcp6")
		ev.Meta["distinct_ports"] = count
		ev.Meta["window_s"] = int(s.cfg.TCPScan.Window.Seconds())
		ev.Meta["tcp_flags"] = fmtTCPFlags(flags)
		addHopGuess(ev, info.hopLimit)
		send(ctx, bus, ev)
	case 17: // UDP
		port, ok := parseUDP(info.payload)
		if !ok {
			return
		}
		if name := encapByUDPPort(port); name != "" {
			if s.encap.allow("encap6:"+info.srcIP+":"+name, now) {
				ev := s.newIPEvent("sniffer:encapsulation", event.SeverityMedium, info.srcIP, "udp6")
				ev.Meta["encap_type"] = name
				ev.Meta["udp_port"] = int(port)
				addHopGuess(ev, info.hopLimit)
				send(ctx, bus, ev)
			}
			return
		}
		count, fire := s.tcp.observe(info.srcIP, port, scanUDP, now)
		if !fire {
			return
		}
		ev := s.newIPEvent(scanUDP.ruleID(), s.sev, info.srcIP, "udp6")
		ev.Meta["distinct_ports"] = count
		ev.Meta["window_s"] = int(s.cfg.TCPScan.Window.Seconds())
		addHopGuess(ev, info.hopLimit)
		send(ctx, bus, ev)
	}
}

// addHopGuess stamps the IPv6 hop limit + passive OS guess (the hop limit is
// the IPv6 analogue of the IPv4 TTL, with the same initial-value buckets).
func addHopGuess(ev *event.Event, hop byte) { addTTLGuess(ev, hop) }

// handleIPFrame classifies one captured IPv4 frame and emits a scan event
// when a per-source threshold trips.
func (s *linuxSniffer) handleIPFrame(ctx context.Context, frame []byte, bus chan<- *event.Event) {
	info, ok := parseIPv4(frame)
	if !ok {
		return
	}
	now := time.Now()

	if info.fragmented {
		if s.cfg.TCPScan.DetectFragments && s.frag.allow(info.srcIP, now) {
			ev := s.newIPEvent("sniffer:ip_fragmented", event.SeverityMedium, info.srcIP, "ip")
			ev.Meta["ip_proto"] = int(info.proto)
			addTTLGuess(ev, info.ttl)
			send(ctx, bus, ev)
		}
		// Non-initial fragments carry no usable L4 header.
		return
	}
	// Tunnelling / encapsulation carried directly in the IP protocol field
	// (GRE, IP-in-IP, 6in4, EtherIP, L2TPv3) — anomalous on a flat segment.
	if name := encapByProto(info.proto); name != "" {
		// Refine IPv6-in-IPv4 into 6in4 / 6to4 / ISATAP from the inner header.
		if info.proto == 41 {
			name = encap41Subtype(info.payload)
		}
		if s.encap.allow("encap:"+info.srcIP+":"+name, now) {
			ev := s.newIPEvent("sniffer:encapsulation", event.SeverityMedium, info.srcIP, name)
			ev.Meta["encap_type"] = name
			ev.Meta["ip_proto"] = int(info.proto)
			addTTLGuess(ev, info.ttl)
			send(ctx, bus, ev)
		}
		return
	}

	switch info.proto {
	case 1: // ICMP — echo-based covert tunnel (ptunnel / icmpsh / Loki)
		dataLen, tunnel := icmpEchoTunnel(info.payload)
		if !tunnel {
			return
		}
		if s.encap.allow("icmptun:"+info.srcIP, now) {
			ev := s.newIPEvent("sniffer:icmp_tunnel", event.SeverityHigh, info.srcIP, "icmp")
			ev.Meta["icmp_data_len"] = dataLen
			addTTLGuess(ev, info.ttl)
			send(ctx, bus, ev)
		}
	case 6: // TCP
		port, flags, ok := parseTCP(info.payload)
		if !ok {
			return
		}
		kind := classifyTCP(flags)
		if kind == scanNone {
			return
		}
		count, fire := s.tcp.observe(info.srcIP, port, kind, now)
		if !fire {
			return
		}
		ev := s.newIPEvent(kind.ruleID(), s.sev, info.srcIP, "tcp")
		ev.Meta["distinct_ports"] = count
		ev.Meta["window_s"] = int(s.cfg.TCPScan.Window.Seconds())
		ev.Meta["tcp_flags"] = fmtTCPFlags(flags)
		addTTLGuess(ev, info.ttl)
		s.addOSFingerprint(ev, info, flags)
		send(ctx, bus, ev)
	case 17: // UDP — nmap -sU sprays datagrams across many ports
		port, ok := parseUDP(info.payload)
		if !ok {
			return
		}
		// UDP-borne overlay/tunnelling (VXLAN, GENEVE, L2TP, Teredo, …).
		if name := encapByUDPPort(port); name != "" {
			if s.encap.allow("encap:"+info.srcIP+":"+name, now) {
				ev := s.newIPEvent("sniffer:encapsulation", event.SeverityMedium, info.srcIP, "udp")
				ev.Meta["encap_type"] = name
				ev.Meta["udp_port"] = int(port)
				addTTLGuess(ev, info.ttl)
				send(ctx, bus, ev)
			}
			return
		}
		count, fire := s.tcp.observe(info.srcIP, port, scanUDP, now)
		if !fire {
			return
		}
		ev := s.newIPEvent(scanUDP.ruleID(), s.sev, info.srcIP, "udp")
		ev.Meta["distinct_ports"] = count
		ev.Meta["window_s"] = int(s.cfg.TCPScan.Window.Seconds())
		addTTLGuess(ev, info.ttl)
		send(ctx, bus, ev)
	}
}

// addTTLGuess stamps the observed IP TTL and the passive OS-family guess
// it implies onto a sniffer event's meta, so the device registry can learn
// an os_guess for the source host (see deviceAttrsFromEvent). No-op for a
// zero TTL.
func addTTLGuess(ev *event.Event, ttl byte) {
	if ttl == 0 {
		return
	}
	ev.Meta["ip_ttl"] = int(ttl)
	if guess, hops := osGuessFromTTL(ttl); guess != "" {
		ev.Meta["os_guess"] = guess
		ev.Meta["ttl_hops"] = hops
	}
}

// addOSFingerprint builds a p0f-v3-style signature from a pure TCP SYN and, on
// a database match, stamps the refined OS fingerprint (os_fingerprint) — a far
// more specific label than the TTL bucket in os_guess. Only fires for a clean
// SYN (no ACK), which is where the SYN-only option layout is meaningful.
func (s *linuxSniffer) addOSFingerprint(ev *event.Event, info ipv4Info, flags byte) {
	if s.p0fDB == nil || flags&flagSYN == 0 || flags&flagACK != 0 {
		return
	}
	sig, ok := p0f.FromSYN(4, info.ttl, info.df, info.ipID, info.optLen, info.payload, 0)
	if !ok {
		return
	}
	ev.Meta["p0f_signature"] = sig.String()
	if label := s.p0fDB.Match(sig); label != "" {
		ev.Meta["os_fingerprint"] = label
	}
}

// runGOOSECapture opens a dedicated AF_PACKET socket bound to the GOOSE
// ethertype (0x88B8) and reports IEC 61850 GOOSE streams seen on the
// segment, rate-limited per source MAC. GOOSE is substation trip/status
// multicast; its presence (or a spoofed stream) is high-signal in OT.
func (s *linuxSniffer) runGOOSECapture(ctx context.Context, bus chan<- *event.Event) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPGOOSE)))
	if err != nil {
		slog.Warn("sniffer: goose socket", "err", err)
		return
	}
	ifaceIdx := 0
	if s.cfg.Interface != "" {
		if iface, err := net.InterfaceByName(s.cfg.Interface); err == nil {
			ifaceIdx = iface.Index
		}
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(ethPGOOSE), Ifindex: ifaceIdx}); err != nil {
		slog.Warn("sniffer: goose bind", "err", err)
		_ = unix.Close(fd)
		return
	}
	slog.Info("sniffer: goose detection up", "interface", s.cfg.Interface)
	go func() {
		<-ctx.Done()
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		_ = unix.Close(fd)
	}()

	buf := make([]byte, 2048)
	for {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINTR) {
				return
			}
			slog.Warn("sniffer: goose recvfrom", "err", err)
			continue
		}
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		s.cFrames.Add(1)
		s.cOther.Add(1)
		s.handleGOOSE(ctx, buf[:n], bus)
	}
}

func (s *linuxSniffer) handleGOOSE(ctx context.Context, frame []byte, bus chan<- *event.Event) {
	gi, ok := parseGOOSE(frame)
	if !ok {
		return
	}
	now := time.Now()

	// Stateful attack analysis: spoofing (a second publisher for a control
	// block), replay (stNum regression), storm (rapid state changes), and
	// simulation (the simulate/test bit). These are high-signal manipulation
	// events and bypass the benign per-source rate limit (they are gated by
	// their own per-source+marker key so an attack flood still can't drown us).
	if markers := s.gooseT.analyze(gi, now); len(markers) > 0 {
		rule, sev := gooseAttackRule(markers)
		if s.goose.allow(gi.srcMAC+"|"+rule, now) {
			ev := s.newEvent(rule, sev, gi.srcMAC, "", "")
			ev.Proto = "goose"
			ev.Meta["appid"] = gi.appid
			if gi.gocbRef != "" {
				ev.Meta["gocb_ref"] = gi.gocbRef
			}
			if gi.goID != "" {
				ev.Meta["go_id"] = gi.goID
			}
			ev.Meta["st_num"] = gi.stNum
			ev.Meta["sq_num"] = gi.sqNum
			ev.Meta["goose_anomalies"] = markers
			ev.Meta["simulated"] = gi.simulated
			ev.Meta["test"] = gi.test
			send(ctx, bus, ev)
		}
		return
	}

	// Benign observation: rate-limit per source MAC so a normal (high-rate)
	// GOOSE stream emits at most one event per window.
	if !s.goose.allow(gi.srcMAC, now) {
		return
	}
	ev := s.newEvent("sniffer:goose", s.sev, gi.srcMAC, "", "")
	ev.Proto = "goose"
	ev.Meta["appid"] = gi.appid
	if gi.gocbRef != "" {
		ev.Meta["gocb_ref"] = gi.gocbRef
	}
	if gi.goID != "" {
		ev.Meta["go_id"] = gi.goID
	}
	ev.Meta["st_num"] = gi.stNum
	ev.Meta["sq_num"] = gi.sqNum
	if gi.confRev != 0 {
		ev.Meta["conf_rev"] = gi.confRev
	}
	send(ctx, bus, ev)
}

// gooseAttackRule picks the rule ID + severity for a set of GOOSE attack
// markers, by priority: spoofing/replay (active manipulation) are critical;
// storm/simulation are high.
func gooseAttackRule(markers []string) (string, event.Severity) {
	has := func(m string) bool {
		for _, x := range markers {
			if x == m {
				return true
			}
		}
		return false
	}
	switch {
	case has("goose-spoofing"):
		return "sniffer:goose_spoof", event.SeverityCritical
	case has("goose-replay"):
		return "sniffer:goose_replay", event.SeverityCritical
	case has("goose-storm"):
		return "sniffer:goose_storm", event.SeverityHigh
	default:
		return "sniffer:goose_simulation", event.SeverityHigh
	}
}

// newIPEvent builds a layer-3/4 sniffer event (no MAC, caller sets proto).
func (s *linuxSniffer) newIPEvent(ruleID string, sev event.Severity, srcIP, proto string) *event.Event {
	return &event.Event{
		ID:       event.NewID(),
		Time:     time.Now().UTC(),
		Sensor:   s.sensorName,
		RuleID:   ruleID,
		Severity: sev,
		Source:   event.Endpoint{IP: srcIP},
		Proto:    proto,
		Meta:     map[string]any{},
	}
}

func send(ctx context.Context, bus chan<- *event.Event, ev *event.Event) {
	select {
	case bus <- ev:
	case <-ctx.Done():
	}
}
