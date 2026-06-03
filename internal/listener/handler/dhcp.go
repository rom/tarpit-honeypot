package handler

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// dhcp is a passive DHCP observer (UDP port 67). It does NOT hand out
// leases — running a rogue DHCP server on someone's segment is exactly
// the kind of damage this tool refuses to do. Instead it parses the
// broadcast DISCOVER / REQUEST / INFORM messages clients emit and
// captures, per device:
//
//   - the client hardware address (chaddr) — the MAC
//   - the requested hostname (option 12)
//   - the vendor class identifier (option 60) — e.g. "MSFT 5.0",
//     "android-dhcp-13", "udhcp 1.x"
//   - the requested IP (option 50) and message type (option 53)
//   - the parameter-request-list (option 55) rendered as a
//     colon-joined fingerprint — a well-known passive OS-detection
//     signal (the basis of fingerbank / p0f DHCP fingerprints)
//
// The handler emits these in res.Meta; the sensor's device observer
// feeds the MAC + hostname + IP into the learned-device registry and
// raises device:new for previously-unseen hosts. The DHCP fingerprint
// also feeds client detection.
type dhcp struct{}

func (d *dhcp) Name() string { return "dhcp" }

const (
	dhcpOpReply = 2
	dhcpMagic   = 0x63825363
)

func (d *dhcp) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	// Fixed BOOTP header is 236 bytes, then the 4-byte magic cookie,
	// then options. Anything shorter isn't DHCP.
	if len(payload) < 240 {
		res.Meta["short_packet"] = true
		return res, nil
	}
	op := payload[0]
	htype := payload[1]
	hlen := int(payload[2])
	res.Meta["op"] = op
	res.Meta["htype"] = htype

	xid := binary.BigEndian.Uint32(payload[4:8])
	res.Meta["xid"] = xid

	// chaddr is 16 bytes at offset 28; the MAC is the first hlen bytes.
	if hlen <= 0 || hlen > 16 {
		hlen = 6
	}
	macBytes, ok := safe.Slice(payload, 28, hlen)
	if !ok {
		res.Meta["bad_chaddr"] = true
		return res, nil
	}
	mac := formatMAC(macBytes)
	res.Meta["client_mac"] = mac

	// Magic cookie at offset 236.
	if binary.BigEndian.Uint32(payload[236:240]) != dhcpMagic {
		res.Meta["no_magic_cookie"] = true
		return res, nil
	}

	// Walk options (TLV) starting at 240.
	off := 240
	var (
		msgType     byte
		hostname    string
		vendorClass string
		requestedIP string
		paramList   []byte
		clientID    string
	)
	for off < len(payload) {
		code := payload[off]
		if code == 0xff { // End
			break
		}
		if code == 0x00 { // Pad
			off++
			continue
		}
		off++
		if off >= len(payload) {
			break
		}
		olen := int(payload[off])
		off++
		val, ok := safe.Slice(payload, off, olen)
		if !ok {
			break
		}
		off += olen
		switch code {
		case 53: // DHCP Message Type
			if len(val) == 1 {
				msgType = val[0]
			}
		case 12: // Host Name
			hostname = string(val)
		case 60: // Vendor Class Identifier
			vendorClass = string(val)
		case 50: // Requested IP Address
			if len(val) == 4 {
				requestedIP = net.IP(val).String()
			}
		case 55: // Parameter Request List
			paramList = append([]byte(nil), val...)
		case 61: // Client Identifier
			clientID = byteToHex(val)
		}
	}

	res.Meta["message_type"] = dhcpMessageTypeName(msgType)
	if hostname != "" {
		res.Meta["hostname"] = safe.SanitizeForLog(hostname)
	}
	if vendorClass != "" {
		res.Meta["vendor_class"] = safe.SanitizeForLog(vendorClass)
	}
	if requestedIP != "" {
		res.Meta["requested_ip"] = requestedIP
	}
	if clientID != "" {
		res.Meta["client_id"] = clientID
	}
	if len(paramList) > 0 {
		// DHCP fingerprint: the option-55 sequence rendered as a
		// comma-joined decimal list (fingerbank format).
		parts := make([]string, len(paramList))
		for i, b := range paramList {
			parts[i] = fmt.Sprintf("%d", b)
		}
		res.Meta["dhcp_fingerprint"] = strings.Join(parts, ",")
	}

	// Message-type-specific signal: DHCPINFORM (8) requests config without
	// taking a lease — a network-recon pattern; DHCPDECLINE (4) in volume is a
	// starvation/DoS tell.
	switch msgType {
	case 8:
		flagAnomaly(&res, "dhcp-inform-probe")
	case 4:
		flagAnomaly(&res, "dhcp-decline")
	}
	// PXEClient vendor class = a network-boot client. Network boot is a
	// firmware/OS-imaging path an attacker can abuse to inject a tampered image.
	if strings.Contains(strings.ToLower(vendorClass), "pxeclient") {
		flagAnomaly(&res, "dhcp-pxe-boot")
	}

	// Flag a device-discovery anomaly so the device observer + SIEM
	// route can pick this up as a learned host signal.
	flagAnomaly(&res, "dhcp-client-observed")
	res.BannerSent = "dhcp passive observe (" + dhcpMessageTypeName(msgType) + ")"
	// We never reply — passive only.
	_ = src
	_ = pc
	_ = op
	return res, nil
}

func formatMAC(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

func dhcpMessageTypeName(t byte) string {
	switch t {
	case 1:
		return "DISCOVER"
	case 2:
		return "OFFER"
	case 3:
		return "REQUEST"
	case 4:
		return "DECLINE"
	case 5:
		return "ACK"
	case 6:
		return "NAK"
	case 7:
		return "RELEASE"
	case 8:
		return "INFORM"
	}
	return "UNKNOWN"
}
