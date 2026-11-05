package filter

import (
	"strconv"
	"testing"
	"time"
)

// With a long window every entry stays unexpired, so the throttled expiry
// sweep reclaims nothing — only the hard cap can bound the table. A flood of
// unique keys must therefore still leave the table at or below dedupMaxKeys.
func TestDedupHardCapUnderFlood(t *testing.T) {
	d := NewDedup(time.Hour)
	for i := 0; i < 5*dedupMaxKeys; i++ {
		d.ShouldSend("k" + strconv.Itoa(i))
	}
	if len(d.seen) > dedupMaxKeys {
		t.Errorf("dedup table = %d; want <= %d (hard cap not enforced under throttling)", len(d.seen), dedupMaxKeys)
	}
}

// Throttling the sweep must not change dedup correctness: a repeat within the
// window is still collapsed even once the table is hot (past the prune
// threshold).
func TestDedupCorrectWhileHot(t *testing.T) {
	d := NewDedup(time.Hour)
	for i := 0; i < dedupPruneThreshold+100; i++ {
		d.ShouldSend("fill" + strconv.Itoa(i))
	}
	if !d.ShouldSend("probe") {
		t.Fatal("first sighting of a new key must send")
	}
	if d.ShouldSend("probe") {
		t.Error("repeat within window must be deduped even with a hot table")
	}
}

// Once the window elapses, the (throttled) sweep still reclaims expired entries.
func TestDedupReclaimsAfterWindow(t *testing.T) {
	d := NewDedup(80 * time.Millisecond)
	for i := 0; i < dedupPruneThreshold+500; i++ {
		d.ShouldSend("k" + strconv.Itoa(i))
	}
	big := len(d.seen)
	if big <= dedupPruneThreshold {
		t.Fatalf("table did not grow past threshold: %d", big)
	}
	time.Sleep(120 * time.Millisecond) // all entries now expired
	// One more call: gap since the last sweep now exceeds the window, so the
	// throttled sweep runs and drops the expired flood.
	d.ShouldSend("after")
	if len(d.seen) > 10 {
		t.Errorf("expired entries not reclaimed: table = %d", len(d.seen))
	}
}
