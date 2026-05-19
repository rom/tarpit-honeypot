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

// startARPResponder opens an AF_PACKET socket on the named interface and
// answers ARP requests for any honeynet host IP with that host's derived
// MAC. The reply is sent at L2 so it works without `ip addr add`.
//
// Returns when ctx is cancelled or an unrecoverable error occurs (the
// caller logs the error and continues — ARP responding is opt-in and
// best-effort).
func startARPResponder(ctx context.Context, ifaceName string, topo *Topology) error {
	if topo == nil || topo.Empty() {
		return errors.New("arp_responder: no honeynet hosts configured")
	}
	iface, err := pickInterface(ifaceName)
	if err != nil {
		return err
	}
	const ethPARP = 0x0806
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPARP)))
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return fmt.Errorf("arp_responder: need CAP_NET_RAW: %w", err)
		}
		return fmt.Errorf("arp_responder: socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(ethPARP),
		Ifindex:  iface.Index,
	}); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("arp_responder: bind: %w", err)
	}

	slog.Info("honeynet arp responder up",
		"interface", iface.Name,
		"if_index", iface.Index,
		"hosts", len(topo.hostByIP),
	)

	go func() {
		<-ctx.Done()
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		_ = unix.Close(fd)
	}()

	go arpLoop(fd, iface, topo)
	return nil
}

func arpLoop(fd int, iface *net.Interface, topo *Topology) {
	buf := make([]byte, 60)
	for {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINTR) {
				return
			}
			slog.Debug("arp responder recv", "err", err)
			continue
		}
		if n < 14+28 {
			continue
		}
		// EtherType must be ARP (we filtered at the socket level but defensively check).
		if binary.BigEndian.Uint16(buf[12:14]) != 0x0806 {
			continue
		}
		arp := buf[14:n]
		if len(arp) < 28 {
			continue
		}
		hwType := binary.BigEndian.Uint16(arp[0:2])
		protoType := binary.BigEndian.Uint16(arp[2:4])
		op := binary.BigEndian.Uint16(arp[6:8])
		if hwType != 1 || protoType != 0x0800 || op != 1 {
			continue // only Ethernet/IPv4 requests
		}
		senderMAC := make([]byte, 6)
		copy(senderMAC, arp[8:14])
		senderIP := net.IP(arp[14:18]).String()
		targetIP := net.IP(arp[24:28]).String()

		host, ok := topo.hostByIP[targetIP]
		if !ok {
			continue
		}

		// Build the reply.
		reply := buildARPReply(host.MAC, net.IP(arp[24:28]), senderMAC, net.IP(arp[14:18]))
		ll, ok := from.(*unix.SockaddrLinklayer)
		if !ok {
			continue
		}
		dst := &unix.SockaddrLinklayer{
			Protocol: htons(0x0806),
			Ifindex:  ll.Ifindex,
			Halen:    6,
		}
		copy(dst.Addr[:], senderMAC)
		if err := unix.Sendto(fd, reply, 0, dst); err != nil {
			slog.Debug("arp responder send", "err", err, "target", targetIP)
			continue
		}
		slog.Debug("arp responder answered",
			"requester_ip", senderIP,
			"target_ip", targetIP,
			"replied_with_mac", host.MACString(),
			"hostname", host.Hostname,
		)
	}
}

// buildARPReply constructs an Ethernet+ARP frame announcing that ourMAC
// owns ourIP, addressed to (targetMAC, targetIP). Length is 42 bytes
// (14 Ethernet + 28 ARP).
func buildARPReply(ourMAC [6]byte, ourIP net.IP, targetMAC net.HardwareAddr, targetIP net.IP) []byte {
	frame := make([]byte, 42)
	// Ethernet header
	copy(frame[0:6], targetMAC)
	copy(frame[6:12], ourMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	// ARP packet
	binary.BigEndian.PutUint16(frame[14:16], 1)      // hwtype
	binary.BigEndian.PutUint16(frame[16:18], 0x0800) // protocol
	frame[18] = 6                                    // hwlen
	frame[19] = 4                                    // protolen
	binary.BigEndian.PutUint16(frame[20:22], 2)      // opcode = reply
	copy(frame[22:28], ourMAC[:])                    // sender_hw
	copy(frame[28:32], ourIP.To4())                  // sender_ip
	copy(frame[32:38], targetMAC)                    // target_hw
	copy(frame[38:42], targetIP.To4())               // target_ip
	return frame
}

// pickInterface returns the named interface, or the first non-loopback
// interface that is up if name is empty.
func pickInterface(name string) (*net.Interface, error) {
	if name != "" {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("arp_responder: interface %q: %w", name, err)
		}
		return iface, nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(i.HardwareAddr) == 6 {
			copied := i
			return &copied, nil
		}
	}
	return nil, errors.New("arp_responder: no usable network interface; set arp_responder.interface explicitly")
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
