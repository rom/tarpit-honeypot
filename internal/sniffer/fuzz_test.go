package sniffer

import "testing"

// FuzzParseFrame feeds arbitrary raw Ethernet frames through the L3/L4
// scan-detection parsers (parseIPv4 + parseTCP + classifyTCP). These run
// on every captured packet, so they must never panic on a truncated or
// malformed frame.
func FuzzParseFrame(f *testing.F) {
	f.Add(buildFrame(nil, 6, 0, tcpSeg(443, flagSYN)))
	f.Add(buildFrame(nil, 1, 0x2000, []byte{0x08, 0x00}))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(make([]byte, 14)) // ethernet header only
	f.Fuzz(func(t *testing.T, frame []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("frame parser panicked on %d bytes: %v", len(frame), r)
			}
		}()
		info, ok := parseIPv4(frame)
		if !ok {
			return
		}
		if port, flags, ok := parseTCP(info.payload); ok {
			_ = port
			_ = classifyTCP(flags)
		}
	})
}
