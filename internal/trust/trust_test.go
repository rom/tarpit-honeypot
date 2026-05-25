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
