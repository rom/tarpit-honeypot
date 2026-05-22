package sniffer

import "testing"

// FuzzParseFrame feeds arbitrary raw Ethernet frames through the L3/L4
// scan-detection parsers (parseIPv4 + parseTCP + classifyTCP). These run
// on every captured packet, so they must never panic on a truncated or
// malformed frame.
func FuzzParseFrame(f *testing.F) {
	f.Add(buildFrame(nil, 6, 0, tcpSeg(443, flagSYN)))
	f.Add(buildFrame(nil, 1, 0x2000, []byte{0x08, 0x00}))
	f.Add(buildIP6Frame(6, tcpSeg(443, flagSYN)))
	f.Add(buildIP6Frame(44, append([]byte{6, 0, 0, 0, 0, 0, 0, 0}, tcpSeg(80, flagSYN)...)))
	f.Add(buildIP6Frame(0, []byte{17, 0})) // truncated hop-by-hop ext header
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(make([]byte, 14)) // ethernet header only
	f.Fuzz(func(t *testing.T, frame []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("frame parser panicked on %d bytes: %v", len(frame), r)
			}
		}()
		if info, ok := parseIPv4(frame); ok {
			if port, flags, ok := parseTCP(info.payload); ok {
				_ = port
				_ = classifyTCP(flags)
			}
		}
		// The IPv6 parser walks an attacker-controlled extension-header
		// chain, so it must also never panic on a malformed frame.
		if info, ok := parseIPv6(frame); ok {
			_, _, _ = parseTCP(info.payload)
			_ = encapByProto6(info.nextHdr)
			_, _ = icmpv6EchoTunnel(info.payload)
		}
	})
}
