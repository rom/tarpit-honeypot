package handler

import (
	"testing"
	"time"

	g "github.com/gosnmp/gosnmp"
)

// sysUpTime must advance from a long-running baseline, not report a frozen
// value (a honeypot tell), and a non-uptime OID passes through unchanged.
func TestSNMPLiveUptime(t *testing.T) {
	sysUpTime := mibEntry{oid: []int{1, 3, 6, 1, 2, 1, 1, 3, 0}, typ: g.TimeTicks, val: uint32(360000)}
	v1, ok := liveMibValue(sysUpTime).(uint32)
	if !ok {
		t.Fatalf("sysUpTime value not uint32: %T", liveMibValue(sysUpTime))
	}
	// Baseline is ~3.6 days => > 30,000,000 ticks (hundredths of a second).
	if v1 < 30_000_000 {
		t.Errorf("sysUpTime ticks = %d; want an established (>30M-tick) uptime", v1)
	}
	// It must not be the frozen cached value.
	if v1 == 360000 {
		t.Errorf("sysUpTime returned the frozen cached value")
	}
	time.Sleep(15 * time.Millisecond)
	v2 := liveMibValue(sysUpTime).(uint32)
	if v2 < v1 {
		t.Errorf("sysUpTime went backwards: %d -> %d", v1, v2)
	}

	// A non-uptime OID is returned unchanged.
	sysName := mibEntry{oid: []int{1, 3, 6, 1, 2, 1, 1, 5, 0}, typ: g.OctetString, val: []byte("router01")}
	if got, _ := liveMibValue(sysName).([]byte); string(got) != "router01" {
		t.Errorf("non-uptime OID mutated: %v", liveMibValue(sysName))
	}
}
