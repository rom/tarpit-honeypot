//go:build linux

package honeynet

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sys/unix"
)

// startLLDPResponder opens an AF_PACKET socket and periodically
// emits an LLDP frame (and optionally a CDP frame) per honeynet
// host. Both protocols ride on a multicast destination MAC at L2:
//
//   LLDP: dst 01:80:c2:00:00:0e, ethertype 0x88cc
//   CDP:  dst 01:00:0c:cc:cc:cc, LLC SNAP, vendor 00:00:0c, type 0x2000
//
// We only TRANSMIT — there's no listen path here, since LLDP
// listening (passive discovery of attacker switches) lives in the
// sniffer package. This module's job is purely making each virtual
// host look like a real L2 neighbor to anyone running tcpdump /
// `lldpctl` / `show cdp neighbors` on the segment.
func startLLDPResponder(ctx context.Context, cfg LLDPCfg, topo *Topology) error {
	if topo == nil || topo.Empty() {
		return errors.New("lldp_responder: no honeynet hosts configured")
	}
	iface, err := pickInterface(cfg.Interface)
	if err != nil {
		return err
	}
	const ethPALL = 0x0003
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return fmt.Errorf("lldp_responder: need CAP_NET_RAW: %w", err)
		}
		return fmt.Errorf("lldp_responder: socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(ethPALL),
		Ifindex:  iface.Index,
	}); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("lldp_responder: bind: %w", err)
	}

	interval := time.Duration(cfg.Interval) * time.Second
	if interval == 0 {
		interval = 30 * time.Second
	}
	slog.Info("honeynet lldp responder up",
		"interface", iface.Name,
		"interval", interval,
		"cdp", cfg.IncludeCDP,
		"hosts", len(topo.hostByIP),
	)

	go func() {
		<-ctx.Done()
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		_ = unix.Close(fd)
	}()

	go func() {
		// Send immediately, then every interval.
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			emitOnce(fd, iface.Index, topo, cfg.IncludeCDP)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return nil
}

func emitOnce(fd, ifIndex int, topo *Topology, includeCDP bool) {
	for _, h := range topo.hostByIP {
		frame := buildLLDPFrame(h)
		_ = sendOnSocket(fd, ifIndex, lldpDstMAC, frame)
		if includeCDP {
			cdpFrame := buildCDPFrame(h)
			_ = sendOnSocket(fd, ifIndex, cdpDstMAC, cdpFrame)
		}
	}
}

var (
	lldpDstMAC = [6]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
	cdpDstMAC  = [6]byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}
)

// buildLLDPFrame emits the Ethernet header + LLDP PDU for one host.
// LLDP TLV format: 7 bits type + 9 bits length + value. We send the
// required Chassis-ID, Port-ID, TTL, and an optional System-Name,
// System-Description, and System-Capabilities. End-of-LLDPDU
// terminates the frame.
func buildLLDPFrame(h *Host) []byte {
	var pdu []byte
	// Chassis-ID TLV (type=1): subtype 4 = MAC.
	chassisVal := append([]byte{0x04}, h.MAC[:]...)
	pdu = append(pdu, lldpTLV(1, chassisVal)...)
	// Port-ID TLV (type=2): subtype 3 = MAC.
	portVal := append([]byte{0x03}, h.MAC[:]...)
	pdu = append(pdu, lldpTLV(2, portVal)...)
	// TTL TLV (type=3): 2 bytes seconds.
	ttl := make([]byte, 2)
	binary.BigEndian.PutUint16(ttl, 120)
	pdu = append(pdu, lldpTLV(3, ttl)...)
	// System-Name TLV (type=5).
	if h.Hostname != "" {
		pdu = append(pdu, lldpTLV(5, []byte(h.Hostname))...)
	}
	// System-Description TLV (type=6).
	if h.Archetype != nil && h.Archetype.SNMPSysDescr() != "" {
		pdu = append(pdu, lldpTLV(6, []byte(h.Archetype.SNMPSysDescr()))...)
	}
	// System-Capabilities TLV (type=7): 2 bytes available caps + 2
	// bytes enabled caps. Bit 0x01 = "other", 0x04 = "bridge",
	// 0x10 = "router". Pick from archetype family.
	caps := lldpCapsFor(h)
	capBytes := make([]byte, 4)
	binary.BigEndian.PutUint16(capBytes[0:2], caps)
	binary.BigEndian.PutUint16(capBytes[2:4], caps)
	pdu = append(pdu, lldpTLV(7, capBytes)...)
	// End-of-LLDPDU TLV (type=0, length=0).
	pdu = append(pdu, 0x00, 0x00)

	frame := make([]byte, 0, 14+len(pdu))
	frame = append(frame, lldpDstMAC[:]...)
	frame = append(frame, h.MAC[:]...)
	frame = append(frame, 0x88, 0xcc) // ethertype LLDP
	frame = append(frame, pdu...)
	return frame
}

// lldpTLV returns one Type-Length-Value record. Type is 7 bits;
// length is 9 bits. The first byte is (type<<1) | (len>>8); the
// second is len&0xff; then the value.
func lldpTLV(t int, v []byte) []byte {
	n := len(v)
	if n > 511 {
		n = 511
		v = v[:n]
	}
	hdr := []byte{
		byte((t&0x7f)<<1) | byte((n>>8)&0x01),
		byte(n & 0xff),
	}
	out := make([]byte, 0, 2+n)
	out = append(out, hdr...)
	out = append(out, v...)
	return out
}

// lldpCapsFor returns the LLDP system-capabilities bitmask appropriate
// for the host's archetype. Switches advertise "bridge"; PLCs and
// generic Linux/BSD hosts advertise "station-only" (0x80) per
// the LLDP-MIB definitions.
func lldpCapsFor(h *Host) uint16 {
	if h.Archetype == nil {
		return 0x0080 // station-only
	}
	switch h.Archetype.Family {
	case "moxa", "siemens":
		// SCALANCE / EDS-208 advertise as bridge + (S7-1500) station.
		return 0x0024 // bridge | router
	default:
		return 0x0080 // station-only
	}
}

// buildCDPFrame emits the Ethernet + LLC SNAP + CDP PDU. CDP is a
// Cisco-specific proprietary protocol; we ship a minimal Device-ID,
// Software-Version, Platform, and Capabilities so a `show cdp
// neighbors` against the segment renders our host believably.
func buildCDPFrame(h *Host) []byte {
	// CDP body: 1 byte version (2) + 1 byte TTL (180) + 2 byte
	// checksum (skip) + TLVs.
	body := []byte{0x02, 0xb4, 0x00, 0x00}
	// Device-ID TLV: type 0x0001.
	if h.Hostname != "" {
		body = append(body, cdpTLV(0x0001, []byte(h.Hostname))...)
	}
	// Software-Version TLV: type 0x0005.
	if h.Archetype != nil && h.Archetype.SNMPSysDescr() != "" {
		body = append(body, cdpTLV(0x0005, []byte(h.Archetype.SNMPSysDescr()))...)
	}
	// Platform TLV: type 0x0006.
	platform := "Linux"
	if h.Archetype != nil {
		switch h.Archetype.Family {
		case "moxa":
			platform = "Moxa Industrial Switch"
		case "siemens":
			platform = "SIMATIC"
		case "bsd":
			platform = "BSD"
		}
	}
	body = append(body, cdpTLV(0x0006, []byte(platform))...)
	// Capabilities TLV: type 0x0004 (4 bytes, bitmask).
	capBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(capBytes, uint32(lldpCapsFor(h)))
	body = append(body, cdpTLV(0x0004, capBytes)...)

	// LLC + SNAP header: AA AA 03 00 00 0C 20 00 + body.
	llc := []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00}
	payload := append(llc, body...)

	frame := make([]byte, 0, 14+len(payload))
	frame = append(frame, cdpDstMAC[:]...)
	frame = append(frame, h.MAC[:]...)
	// 802.3 length field (not ethertype): payload length.
	ln := make([]byte, 2)
	binary.BigEndian.PutUint16(ln, uint16(len(payload)))
	frame = append(frame, ln...)
	frame = append(frame, payload...)
	return frame
}

func cdpTLV(t uint16, v []byte) []byte {
	out := make([]byte, 4+len(v))
	binary.BigEndian.PutUint16(out[0:2], t)
	binary.BigEndian.PutUint16(out[2:4], uint16(4+len(v)))
	copy(out[4:], v)
	return out
}

// sendOnSocket sends one L2 frame via the bound AF_PACKET socket.
func sendOnSocket(fd, ifIndex int, dstMAC [6]byte, frame []byte) error {
	sa := &unix.SockaddrLinklayer{
		Protocol: htons(0x88cc),
		Ifindex:  ifIndex,
		Halen:    6,
	}
	copy(sa.Addr[:], dstMAC[:])
	return unix.Sendto(fd, frame, 0, sa)
}
