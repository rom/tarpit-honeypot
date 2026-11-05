package enrich

import (
	"context"
	"testing"
	"time"
)

// waitFor polls fn until it returns true or the deadline passes.
func waitFor(d time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return fn()
}

// A miss returns "" immediately and resolves asynchronously; a later lookup
// picks up the cached name.
func TestRDNSAsyncResolve(t *testing.T) {
	c := newRDNSCache(16, 200*time.Millisecond)
	c.lookupAddr = func(_ context.Context, ip string) ([]string, error) {
		return []string{"host-" + ip + ".example."}, nil
	}
	if got := c.lookup("1.2.3.4"); got != "" {
		t.Fatalf("first lookup (miss) should return \"\" immediately, got %q", got)
	}
	if !waitFor(time.Second, func() bool { return c.lookup("1.2.3.4") == "host-1.2.3.4.example" }) {
		t.Errorf("async resolve never populated the cache: %q", c.lookup("1.2.3.4"))
	}
}

// A failed/empty resolution is negatively cached (returns "", no re-query storm)
// and does not stay pending.
func TestRDNSNegativeCache(t *testing.T) {
	c := newRDNSCache(16, 200*time.Millisecond)
	c.lookupAddr = func(_ context.Context, _ string) ([]string, error) {
		return nil, context.DeadlineExceeded
	}
	c.lookup("9.9.9.9") // trigger async resolve
	if !waitFor(time.Second, func() bool {
		c.mu.Lock()
		_, cached := c.m["9.9.9.9"]
		_, pending := c.pending["9.9.9.9"]
		c.mu.Unlock()
		return cached && !pending
	}) {
		t.Error("failed resolution should be negatively cached and not left pending")
	}
	if got := c.lookup("9.9.9.9"); got != "" {
		t.Errorf("negative cache should return \"\", got %q", got)
	}
}

// Misses never block even when resolution is slow, and the in-flight cap bounds
// concurrent resolves.
func TestRDNSNonBlockingUnderCap(t *testing.T) {
	c := newRDNSCache(1024, time.Second)
	release := make(chan struct{})
	c.lookupAddr = func(_ context.Context, _ string) ([]string, error) {
		<-release // block every resolve until the test releases
		return []string{"x."}, nil
	}
	start := time.Now()
	for i := 0; i < 50; i++ { // far more than rdnsMaxInFlight
		ip := "10.0." + itoa(i/256) + "." + itoa(i%256)
		if got := c.lookup(ip); got != "" {
			t.Fatalf("miss should be non-blocking \"\", got %q", got)
		}
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("50 misses took %v — lookups are blocking on resolution", elapsed)
	}
	c.mu.Lock()
	inflight := len(c.pending)
	c.mu.Unlock()
	if inflight > rdnsMaxInFlight {
		t.Errorf("in-flight resolves = %d; want <= cap %d", inflight, rdnsMaxInFlight)
	}
	close(release) // let the blocked resolves finish and exit (no leak)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [3]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
