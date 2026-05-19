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
	return &linuxSniffer{
		cfg:        cfg,
		sensorName: sensorName,
		sev:        sev,
		state:      map[string]*scanState{},
	}, nil
}

const (
	ethPARP    = 0x0806
	ethPALL    = 0x0003
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

func send(ctx context.Context, bus chan<- *event.Event, ev *event.Event) {
	select {
	case bus <- ev:
	case <-ctx.Done():
	}
}
