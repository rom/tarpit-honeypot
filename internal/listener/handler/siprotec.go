package handler

import (
	"bytes"
	"context"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// siprotecEN100 is a capture-only UDP/50000 decoy for the Siemens SIPROTEC 4 /
// SIPROTEC Compact EN100 Ethernet module. A single crafted UDP datagram on port
// 50000 reboots/bricks the EN100 module (CVE-2015-5374, weaponized by the
// Industroyer/CrashOverride ICS malware). We never reply — a real device would
// crash, and silence keeps this off any reflection/amplification path.
type siprotecEN100 struct{}

func (s *siprotecEN100) Name() string { return "siprotec_en100" }

// siprotecDoSPacket is the documented CVE-2015-5374 denial-of-service datagram.
var siprotecDoSPacket = []byte{
	0x11, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x9e,
}

func (s *siprotecEN100) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	flagAnomaly(&res, "siprotec-en100-probe")
	switch {
	case bytes.Equal(payload, siprotecDoSPacket):
		// Exact match of the published DoS packet.
		flagAnomaly(&res, "siprotec-en100-dos")
		res.Meta["siprotec_dos_exact"] = true
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2015-5374")
		flagAnomaly(&res, "cve:CVE-2015-5374")
	case len(payload) >= 2 && payload[0] == 0x11 && payload[1] == 0x49:
		// EN100 control-frame opcode (0x1149) — the family the DoS packet uses;
		// flag a likely variant of the same attack.
		flagAnomaly(&res, "siprotec-en100-dos")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2015-5374")
		flagAnomaly(&res, "cve:CVE-2015-5374")
	}
	// Capture-only: no reply (a real EN100 would stop responding anyway).
	return res, nil
}

// longestByteRun returns the length of the longest run of a single repeated
// byte in b — used to spot the long filler runs in buffer-overflow payloads.
func longestByteRun(b []byte) int {
	best, cur := 0, 0
	var prev byte
	for i, c := range b {
		if i > 0 && c == prev {
			cur++
		} else {
			cur = 1
		}
		prev = c
		if cur > best {
			best = cur
		}
	}
	return best
}
