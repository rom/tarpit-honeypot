package trust

import (
	"testing"
	"time"
)

func TestNilScorerNoops(t *testing.T) {
	var s *Scorer
	if !s.Admit("x") {
		t.Error("nil scorer should admit")
	}
	if s.Observe("x", Malformed) != nil {
		t.Error("nil scorer should not alert")
	}
	if s.Score("x") != 1 {
		t.Error("nil scorer score should be 1")
	}
}

func TestHealthyStreamScoresOne(t *testing.T) {
	s := New(Config{Enabled: true, MinEvents: 3, AlertBelow: 0.5})
	for i := 0; i < 5; i++ {
		if a := s.Observe("good", Accepted); a != nil {
			t.Fatalf("alert on a healthy stream: %+v", a)
		}
	}
	if got := s.Score("good"); got != 1 {
		t.Errorf("score = %v; want 1", got)
	}
}

func TestMalformedRaisesAlertOncePerWindow(t *testing.T) {
	s := New(Config{Enabled: true, MinEvents: 3, AlertBelow: 0.5})
	var alerts int
	for i := 0; i < 8; i++ {
		if a := s.Observe("bad", Malformed); a != nil {
			alerts++
			if a.Sensor != "bad" || a.Score >= 0.5 {
				t.Errorf("alert = %+v; want sensor bad, score < 0.5", a)
			}
		}
	}
	if alerts != 1 {
		t.Errorf("alerts = %d; want exactly 1 per window", alerts)
	}
}

func TestQuarantineRefusesAdmission(t *testing.T) {
	s := New(Config{Enabled: true, MinEvents: 2, QuarantineBelow: 0.5})
	if !s.Admit("q") {
		t.Fatal("admit before any badness should be true")
	}
	for i := 0; i < 3; i++ {
		s.Observe("q", Malformed) // score -> 0
	}
	if s.Admit("q") {
		t.Error("quarantined sensor was admitted")
	}
}

func TestWindowRollClearsQuarantine(t *testing.T) {
	s := New(Config{Enabled: true, MinEvents: 2, QuarantineBelow: 0.5, Window: time.Hour})
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		s.Observe("q", Malformed)
	}
	if s.Admit("q") {
		t.Fatal("not quarantined")
	}
	now = now.Add(2 * time.Hour) // window rolls
	if !s.Admit("q") {
		t.Error("quarantine not cleared after the window rolled")
	}
}

func TestRateLimit(t *testing.T) {
	s := New(Config{Enabled: true, RatePerSec: 5, Burst: 2})
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	if !s.Admit("r") || !s.Admit("r") {
		t.Fatal("burst of 2 should be admitted")
	}
	if s.Admit("r") {
		t.Error("over-burst admitted with no time elapsed")
	}
	now = now.Add(time.Second) // +5 tokens, capped at burst 2
	if !s.Admit("r") {
		t.Error("refilled token not admitted")
	}
}

// TestMaxSensorsCapped guards M2: a peer spraying spoofed sensor_ids must not
// be able to grow the scorer's per-sensor map without bound. Once the cap is
// reached and there are no idle slots to evict, a brand-new sensor is refused.
func TestMaxSensorsCapped(t *testing.T) {
	s := New(Config{Enabled: true, MaxSensors: 4, Window: time.Minute, MinEvents: 1})
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	for _, sid := range []string{"a", "b", "c", "d"} {
		if !s.Admit(sid) {
			t.Fatalf("first %d sensors should be admitted; %q refused", 4, sid)
		}
		s.Observe(sid, Accepted)
	}
	// All four slots are active (within Window) — a 5th distinct id must be
	// refused rather than grow the map.
	if s.Admit("e") {
		t.Error("5th sensor admitted past MaxSensors=4 with all slots active")
	}
	if got := len(s.sensors); got != 4 {
		t.Errorf("sensors len = %d after refused admit; want 4", got)
	}
	// Roll time past 2*Window so the existing slots are idle and eligible for
	// eviction; the 5th sensor now fits.
	now = now.Add(3 * time.Minute)
	if !s.Admit("e") {
		t.Error("5th sensor refused even after idle eviction window")
	}
}
