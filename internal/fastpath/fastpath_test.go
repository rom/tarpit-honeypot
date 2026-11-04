package fastpath

import (
	"testing"
	"time"
)

func TestShaperTokenBucket(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := NewShaper(Config{PerSourcePPS: 10, Burst: 5, now: func() time.Time { return now }})

	// Burst of 5 admitted immediately; the 6th is shed (no refill at t0).
	for i := 0; i < 5; i++ {
		if !s.Admit("1.2.3.4") {
			t.Fatalf("burst conn %d should be admitted", i)
		}
	}
	if s.Admit("1.2.3.4") {
		t.Error("6th connection within the burst should be shed")
	}
	// A different source has its own bucket.
	if !s.Admit("5.6.7.8") {
		t.Error("a different source must not be rate-limited by the first")
	}
	// After 1s, 10 pps refills the bucket (capped at burst=5), so conns resume.
	now = now.Add(time.Second)
	if !s.Admit("1.2.3.4") {
		t.Error("bucket should have refilled after 1s")
	}
	st := s.Stats()
	if st.Shed == 0 || st.Admitted == 0 {
		t.Errorf("stats look wrong: %+v", st)
	}
}

func TestShaperBlocklist(t *testing.T) {
	s := NewShaper(Config{PerSourcePPS: 1000})
	s.Block("9.9.9.9")
	if s.Admit("9.9.9.9") {
		t.Error("blocklisted source must be refused")
	}
	if !s.Admit("1.1.1.1") {
		t.Error("non-blocklisted source should pass")
	}
	s.SetBlocklist([]string{"1.1.1.1"})
	if s.Admit("1.1.1.1") {
		t.Error("SetBlocklist should now block 1.1.1.1")
	}
	if !s.Admit("9.9.9.9") {
		t.Error("SetBlocklist should have cleared 9.9.9.9")
	}
	if s.Stats().Blocked == 0 {
		t.Error("blocked counter not incremented")
	}
}

func TestShaperEmptyIPAdmitted(t *testing.T) {
	s := NewShaper(Config{PerSourcePPS: 1})
	for i := 0; i < 100; i++ {
		if !s.Admit("") {
			t.Fatal("unknown source must not be shed")
		}
	}
}

func TestShaperBounded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := NewShaper(Config{PerSourcePPS: 1, MaxSources: 10, now: func() time.Time { return now }})
	for i := 0; i < 1000; i++ {
		now = now.Add(time.Millisecond)
		s.Admit(ipN(i))
	}
	if n := s.Stats().Tracked; n > 10 {
		t.Errorf("tracked sources = %d; must be bounded to 10", n)
	}
}

func TestXDPDefaultUnavailable(t *testing.T) {
	if Available() {
		t.Skip("built with -tags tarpit_xdp")
	}
	if _, err := AttachXDP("eth0", NewShaper(Config{})); err == nil {
		t.Error("AttachXDP should return an error in the default build")
	}
}

func ipN(i int) string {
	return "10." + itoa(i>>16&0xff) + "." + itoa(i>>8&0xff) + "." + itoa(i&0xff)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [3]byte
	p := len(b)
	for n > 0 {
		p--
		b[p] = byte('0' + n%10)
		n /= 10
	}
	return string(b[p:])
}
