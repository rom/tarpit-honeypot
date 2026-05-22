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
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

type linuxSniffer struct {
	cfg        config.Sniffer
	sensorName string
	sev        event.Severity

	mu    sync.Mutex
	state map[string]*scanState // key: source MAC string

	tcp   *scanTracker // nil unless TCPScan enabled
	frag  *rateLimiter // nil unless TCPScan enabled
	goose *rateLimiter // nil unless GOOSE enabled
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
	}
	if cfg.TCPScan.Enabled {
		s.tcp = newScanTracker(cfg.TCPScan.Window, cfg.TCPScan.DistinctPorts, cfg.TCPScan.StealthPorts)
		s.frag = newRateLimiter(cfg.TCPScan.Window)
	}
	if cfg.GOOSE.Enabled {
		w := cfg.GOOSE.Window
		if w <= 0 {
			w = 60 * time.Second
		}
		s.goose = newRateLimiter(w)
	}
	return s, nil
}

const (
	ethPARP    = 0x0806
	ethPIP     = 0x0800
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
		if n < 14+28 {
			continue
		}
		s.handleARP(ctx, buf[:n], bus)
	}
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
		s.handleIPFrame(ctx, buf[:n], bus)
	}
}

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
	switch info.proto {
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
		send(ctx, bus, ev)
	case 17: // UDP — nmap -sU sprays datagrams across many ports
		port, ok := parseUDP(info.payload)
		if !ok {
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
		s.handleGOOSE(ctx, buf[:n], bus)
	}
}

func (s *linuxSniffer) handleGOOSE(ctx context.Context, frame []byte, bus chan<- *event.Event) {
	gi, ok := parseGOOSE(frame)
	if !ok {
		return
	}
	// Rate-limit per source MAC so a normal (high-rate) GOOSE stream emits
	// at most one event per window.
	if !s.goose.allow(gi.srcMAC, time.Now()) {
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
	send(ctx, bus, ev)
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
