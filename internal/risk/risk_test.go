package risk

import (
	"testing"
	"time"
)

func TestScoreAccumulatesAndEscalates(t *testing.T) {
	s := New(Config{Enabled: true, HalfLife: time.Hour, Elevated: 30, High: 75, Critical: 150})
	now := time.Now()
	// A burst of high-severity + cve events from one source should escalate.
	var lastLevel string
	for i := 0; i < 6; i++ {
		lvl, _, crossed := s.Observe("1.2.3.4", "cve:CVE-2021-44228", 4, now.Add(time.Duration(i)*time.Second))
		if crossed {
			lastLevel = lvl
		}
	}
	if lastLevel == "" {
		t.Fatal("expected at least one escalation")
	}
	sr, ok := s.Get("1.2.3.4", now.Add(6*time.Second))
	if !ok || sr.Score < 75 {
		t.Fatalf("score = %v; want >= 75 after cve burst", sr.Score)
	}
}

func TestEscalatesOncePerLevel(t *testing.T) {
	s := New(Config{Enabled: true, HalfLife: time.Hour, Elevated: 10, High: 1e9, Critical: 1e9})
	now := time.Now()
	crossings := 0
	for i := 0; i < 10; i++ {
		if _, _, crossed := s.Observe("9.9.9.9", "correlate:port_scan", 3, now.Add(time.Duration(i)*time.Second)); crossed {
			crossings++
		}
	}
	if crossings != 1 {
		t.Fatalf("expected exactly 1 crossing into elevated; got %d", crossings)
	}
}

func TestDecayCoolsOff(t *testing.T) {
	s := New(Config{Enabled: true, HalfLife: time.Hour, Elevated: 30, High: 75, Critical: 150})
	now := time.Now()
	s.Observe("5.5.5.5", "listener:x", 4, now) // +30
	hot, _ := s.Get("5.5.5.5", now)
	cold, _ := s.Get("5.5.5.5", now.Add(2*time.Hour)) // two half-lives -> ~1/4
	if !(cold.Score < hot.Score/2) {
		t.Errorf("score did not decay: hot=%v cold=%v", hot.Score, cold.Score)
	}
}

func TestTopOrdersBySource(t *testing.T) {
	s := New(Config{Enabled: true, HalfLife: time.Hour})
	now := time.Now()
	s.Observe("1.1.1.1", "listener:x", 1, now)      // low
	s.Observe("2.2.2.2", "malware:capture", 4, now) // high + bonus
	s.Observe("2.2.2.2", "cve:x", 4, now)           // more
	top := s.Top(10, now)
	if len(top) != 2 || top[0].IP != "2.2.2.2" {
		t.Fatalf("Top order wrong: %+v", top)
	}
}

func TestObserveEmptyIgnored(t *testing.T) {
	s := New(Config{Enabled: true})
	if _, _, crossed := s.Observe("", "x", 4, time.Now()); crossed {
		t.Fatal("empty source produced a crossing")
	}
}

// ObserveWithBonus adds the caller-supplied enrichment weight on top of the
// rule/severity weight, so a source carrying high-signal reputation escalates
// faster. A negative bonus is clamped to zero.
func TestObserveWithBonus(t *testing.T) {
	now := time.Now()
	s := New(Config{Enabled: true}) // default thresholds: elevated 30 / high 75

	// A single low-severity event alone (weight 1) stays well below "elevated".
	if lvl, _, crossed := s.Observe("1.2.3.4", "listener:x", 1, now); crossed || lvl != "" {
		t.Fatalf("low event crossed unexpectedly: lvl=%q crossed=%v", lvl, crossed)
	}
	// The same event from a spoofing, high-confidence source (bonus 42) clears
	// "elevated" on its own.
	lvl, score, crossed := s.ObserveWithBonus("5.6.7.8", "listener:x", 1, 42, now)
	if !crossed || lvl != "elevated" {
		t.Fatalf("bonus event should cross to elevated: lvl=%q score=%v crossed=%v", lvl, score, crossed)
	}
	if score < 30 {
		t.Errorf("score with bonus = %v; want >= 30 (elevated)", score)
	}

	// A negative bonus is clamped to 0 — enrichment never lowers risk below the
	// base rule/severity weight.
	s2 := New(Config{Enabled: true})
	if _, sc, _ := s2.ObserveWithBonus("9.9.9.9", "listener:x", 1, -100, now); sc < 1 {
		t.Errorf("negative bonus should clamp to 0, leaving base weight; got %v", sc)
	}
}
