package handler

import (
	"context"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestNTPThreatMarkers(t *testing.T) {
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 12345}

	// Crypto-NAK: 48-byte client header + 4-byte zero key-id (no digest).
	t.Run("crypto-nak", func(t *testing.T) {
		p := make([]byte, 52)
		p[0] = 0x23 // LI=0 ver=4 mode=3 (client)
		res, _ := (&ntp{lim: newUDPReflectLimiter()}).Handle(context.Background(), p, src, &fakePacketConn{}, config.Listener{})
		if !hasAnom(res, "ntp-crypto-nak") || !hasAnom(res, "cve:CVE-2016-1547") {
			t.Errorf("crypto-NAK not flagged: %v", res.Meta["anomalies"])
		}
	})

	// Autokey extension field after the header (field type >= 0x0200).
	t.Run("autokey", func(t *testing.T) {
		p := make([]byte, 48+12)
		p[0] = 0x23
		p[48], p[49] = 0x02, 0x00 // extension field type
		res, _ := (&ntp{lim: newUDPReflectLimiter()}).Handle(context.Background(), p, src, &fakePacketConn{}, config.Listener{})
		if !hasAnom(res, "ntp-autokey-extension") || !hasAnom(res, "cve:CVE-2014-9295") {
			t.Errorf("autokey extension not flagged: %v", res.Meta["anomalies"])
		}
	})

	// Mode-7 with the response bit set = reflected ping-pong loop.
	t.Run("mode7-loop", func(t *testing.T) {
		p := make([]byte, 48)
		p[0] = 0x80 | 0x20 | 7 // response bit + ver + mode 7
		res, _ := (&ntp{lim: newUDPReflectLimiter()}).Handle(context.Background(), p, src, &fakePacketConn{}, config.Listener{})
		if !hasAnom(res, "ntp-mode7-reflected-loop") || !hasAnom(res, "cve:CVE-2009-3563") {
			t.Errorf("mode-7 loop not flagged: %v", res.Meta["anomalies"])
		}
	})

	// Mode-6 mrulist read.
	t.Run("mrulist", func(t *testing.T) {
		p := make([]byte, 60)
		p[0] = 0x26                     // ver + mode 6
		p[1] = 0x02                     // opcode READVAR-ish
		copy(p[12:], "mrulist,nonce=0") // control data
		res, _ := (&ntp{lim: newUDPReflectLimiter()}).Handle(context.Background(), p, src, &fakePacketConn{}, config.Listener{})
		if !hasAnom(res, "ntp-mrulist-probe") || !hasAnom(res, "cve:CVE-2016-7434") {
			t.Errorf("mrulist not flagged: %v", res.Meta["anomalies"])
		}
	})

	// Mode-1 symmetric-active = rogue association.
	t.Run("rogue-assoc", func(t *testing.T) {
		p := make([]byte, 48)
		p[0] = 0x21 // ver + mode 1
		res, _ := (&ntp{lim: newUDPReflectLimiter()}).Handle(context.Background(), p, src, &fakePacketConn{}, config.Listener{})
		if !hasAnom(res, "ntp-rogue-association") {
			t.Errorf("rogue association not flagged: %v", res.Meta["anomalies"])
		}
	})
}
