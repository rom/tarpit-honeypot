package handler

import (
	"fmt"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// TestSNMPWalkMapBounded proves the per-source walk-rate map cannot grow without
// bound under a spoofed-source flood (every window fresh, nothing to elapsed-GC)
// — the regression guard for the memory-exhaustion DoS.
func TestSNMPWalkMapBounded(t *testing.T) {
	s := &snmp{}
	cfg := config.SNMPListener{WalkRatePerMin: 10}
	now := time.Now()
	// Feed far more distinct (spoofable) source IPs than the hard cap, all within
	// the same sub-minute window so the elapsed-window GC frees nothing.
	for i := 0; i < snmpWalkHardCap*4; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		s.allowWalk(ip, cfg, now, 1)
		if len(s.walks) > snmpWalkHardCap {
			t.Fatalf("walk map grew to %d, exceeds hard cap %d", len(s.walks), snmpWalkHardCap)
		}
	}
	if len(s.walks) == 0 {
		t.Fatal("walk map unexpectedly empty")
	}
}
