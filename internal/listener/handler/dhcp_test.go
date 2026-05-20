package handler

import (
	"context"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// buildDHCPDiscover crafts a minimal but valid DHCP DISCOVER with a
// hostname, vendor class, and parameter-request-list (the fingerprint).
func buildDHCPDiscover(mac []byte, hostname, vendor string, paramList []byte) []byte {
	pkt := make([]byte, 240)
	pkt[0] = 1 // op = BOOTREQUEST
	pkt[1] = 1 // htype = ethernet
	pkt[2] = 6 // hlen
	pkt[4] = 0xDE
	pkt[5] = 0xAD
	pkt[6] = 0xBE
	pkt[7] = 0xEF
	copy(pkt[28:34], mac) // chaddr
	// Magic cookie.
	pkt[236], pkt[237], pkt[238], pkt[239] = 0x63, 0x82, 0x53, 0x63
	// Options.
	opt := []byte{}
	opt = append(opt, 53, 1, 1) // message type = DISCOVER
	if hostname != "" {
		opt = append(opt, 12, byte(len(hostname)))
		opt = append(opt, []byte(hostname)...)
	}
	if vendor != "" {
		opt = append(opt, 60, byte(len(vendor)))
		opt = append(opt, []byte(vendor)...)
	}
	if len(paramList) > 0 {
		opt = append(opt, 55, byte(len(paramList)))
		opt = append(opt, paramList...)
	}
	opt = append(opt, 0xff) // end
	return append(pkt, opt...)
}

func TestDHCPParsesDiscover(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 68}
	mac := []byte{0x00, 0x90, 0xe8, 0x11, 0x22, 0x33}
	pkt := buildDHCPDiscover(mac, "plc-floor-2", "android-dhcp-13", []byte{1, 3, 6, 15, 51, 54})

	res, _ := (&dhcp{}).Handle(context.Background(), pkt, src, pc, config.Listener{})

	if res.Meta["message_type"] != "DISCOVER" {
		t.Errorf("message_type = %v; want DISCOVER", res.Meta["message_type"])
	}
	if res.Meta["client_mac"] != "00:90:e8:11:22:33" {
		t.Errorf("client_mac = %v; want 00:90:e8:11:22:33", res.Meta["client_mac"])
	}
	if res.Meta["hostname"] != "plc-floor-2" {
		t.Errorf("hostname = %v", res.Meta["hostname"])
	}
	if res.Meta["vendor_class"] != "android-dhcp-13" {
		t.Errorf("vendor_class = %v", res.Meta["vendor_class"])
	}
	if res.Meta["dhcp_fingerprint"] != "1,3,6,15,51,54" {
		t.Errorf("dhcp_fingerprint = %v; want 1,3,6,15,51,54", res.Meta["dhcp_fingerprint"])
	}
	// Passive — never replies.
	if len(pc.written) != 0 {
		t.Errorf("dhcp handler must not reply; wrote %d packets", len(pc.written))
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "dhcp-client-observed") {
		t.Errorf("anomalies = %v; want dhcp-client-observed", anoms)
	}
}

func TestDHCPShortPacket(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 68}
	res, _ := (&dhcp{}).Handle(context.Background(), []byte{1, 2, 3}, src, pc, config.Listener{})
	if res.Meta["short_packet"] != true {
		t.Errorf("expected short_packet flag")
	}
}

func TestDHCPRequestedIP(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 68}
	mac := []byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	pkt := buildDHCPDiscover(mac, "", "", nil)
	// Append a requested-IP option (50) before the end marker. The
	// builder already put 0xff at the end, so rebuild without it.
	pkt = pkt[:len(pkt)-1]
	pkt = append(pkt, 50, 4, 192, 168, 1, 77, 0xff)
	res, _ := (&dhcp{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if res.Meta["requested_ip"] != "192.168.1.77" {
		t.Errorf("requested_ip = %v; want 192.168.1.77", res.Meta["requested_ip"])
	}
}
