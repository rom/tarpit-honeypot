// Package risk maintains a decaying per-source threat score. Every event
// from a source adds weight (scaled by severity + rule category); the
// score decays with a configurable half-life so a source that goes quiet
// cools off. Crossing a threshold (elevated / high / critical) emits a
// risk:<level> alert once per level, and the top scorers feed the web UI
// so an operator can triage "who is the most dangerous source right now".
package risk

import (
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// Config tunes the scorer. Zero values get sensible defaults via New.
type Config struct {
	Enabled  bool
	HalfLife time.Duration // score halves over this period of silence
	Elevated float64       // threshold for risk:elevated
	High     float64       // threshold for risk:high
	Critical float64       // threshold for risk:critical
}

// SourceRisk is a point-in-time view of one source's risk, for the UI.
type SourceRisk struct {
	IP        string         `json:"ip"`
	Score     float64        `json:"score"`
	Level     string         `json:"level"`
	Events    int            `json:"events"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	TopRules  map[string]int `json:"top_rules,omitempty"`
}

type srcScore struct {
	score      float64
	lastUpdate time.Time
	firstSeen  time.Time
	lastSeen   time.Time
	events     int
	rules      map[string]int
	level      int // 0 none, 1 elevated, 2 high, 3 critical (dedup latch)
}

// Scorer is concurrency-safe: the bus loop calls Observe (one goroutine)
// while the UI calls Top/Get from HTTP goroutines.
type Scorer struct {
	cfg    Config
	mu     sync.Mutex
	src    map[string]*srcScore
	lastGC time.Time
}

const setCap = 4096

func New(cfg Config) *Scorer {
	if cfg.HalfLife <= 0 {
		cfg.HalfLife = time.Hour
	}
	if cfg.Elevated <= 0 {
		cfg.Elevated = 30
	}
	if cfg.High <= 0 {
		cfg.High = 75
	}
	if cfg.Critical <= 0 {
		cfg.Critical = 150
	}
	return &Scorer{cfg: cfg, src: map[string]*srcScore{}}
}

// weight is the points one event contributes, by severity rank (1..4) plus
// a category bonus for the highest-signal rule families.
func weight(ruleID string, sevRank int) float64 {
	base := map[int]float64{1: 1, 2: 4, 3: 12, 4: 30}[sevRank]
	if base == 0 {
		base = 1
	}
	switch {
	case strings.HasPrefix(ruleID, "cve:"):
		base += 25
	case strings.HasPrefix(ruleID, "malware:"):
		base += 20
	case strings.HasPrefix(ruleID, "storyline:"):
		base += 30
	case strings.HasPrefix(ruleID, "canary:"), ruleID == "honeynet:profinet_dcp_identify":
		base += 15
	case strings.HasPrefix(ruleID, "correlate:"):
		base += 8
	}
	return base
}

func levelName(l int) string {
	switch l {
	case 1:
		return "elevated"
	case 2:
		return "high"
	case 3:
		return "critical"
	}
	return ""
}

// Observe folds one event into the source's score and returns the new
// level name + score when the source crosses UP into a higher level (so a
// caller emits one alert per escalation), else ("", score, false).
func (s *Scorer) Observe(srcIP, ruleID string, sevRank int, now time.Time) (level string, score float64, crossed bool) {
	return s.ObserveWithBonus(srcIP, ruleID, sevRank, 0, now)
}

// ObserveWithBonus is Observe plus an extra per-event weight (points) the
// caller derives from source enrichment — e.g. a spoofed-crawler PTR or a high
// cross-feed threat-confidence. The bonus is added on top of the rule/severity
// weight for this event, so a source carrying high-signal reputation accrues
// risk faster; it then decays with the score like any other contribution. A
// negative bonus is clamped to zero (enrichment only ever raises risk).
func (s *Scorer) ObserveWithBonus(srcIP, ruleID string, sevRank int, bonus float64, now time.Time) (level string, score float64, crossed bool) {
	if srcIP == "" {
		return "", 0, false
	}
	if bonus < 0 {
		bonus = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)

	st := s.src[srcIP]
	if st == nil {
		if len(s.src) >= setCap {
			s.evictOldestLocked()
		}
		st = &srcScore{firstSeen: now, lastUpdate: now, rules: map[string]int{}}
		s.src[srcIP] = st
	}
	st.score = decay(st.score, now.Sub(st.lastUpdate), s.cfg.HalfLife) + weight(ruleID, sevRank) + bonus
	st.lastUpdate = now
	st.lastSeen = now
	st.events++
	if len(st.rules) < 64 {
		st.rules[ruleID]++
	}

	newLevel := s.levelFor(st.score)
	if newLevel > st.level {
		st.level = newLevel
		return levelName(newLevel), st.score, true
	}
	// Latch down (without alerting) so a re-escalation can fire again.
	if newLevel < st.level {
		st.level = newLevel
	}
	return "", st.score, false
}

func (s *Scorer) levelFor(score float64) int {
	switch {
	case score >= s.cfg.Critical:
		return 3
	case score >= s.cfg.High:
		return 2
	case score >= s.cfg.Elevated:
		return 1
	}
	return 0
}

// Get returns the current (decayed) risk for one source.
func (s *Scorer) Get(ip string, now time.Time) (SourceRisk, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.src[ip]
	if !ok {
		return SourceRisk{}, false
	}
	return s.view(ip, st, now), true
}

// Top returns the n highest-scoring sources (decayed to now), descending.
func (s *Scorer) Top(n int, now time.Time) []SourceRisk {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SourceRisk, 0, len(s.src))
	for ip, st := range s.src {
		out = append(out, s.view(ip, st, now))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func (s *Scorer) view(ip string, st *srcScore, now time.Time) SourceRisk {
	score := decay(st.score, now.Sub(st.lastUpdate), s.cfg.HalfLife)
	rules := make(map[string]int, len(st.rules))
	for k, v := range st.rules {
		rules[k] = v
	}
	return SourceRisk{
		IP: ip, Score: round1(score), Level: levelName(s.levelFor(score)),
		Events: st.events, FirstSeen: st.firstSeen, LastSeen: st.lastSeen, TopRules: rules,
	}
}

func (s *Scorer) gcLocked(now time.Time) {
	if !s.lastGC.IsZero() && now.Sub(s.lastGC) < 5*time.Minute {
		return
	}
	s.lastGC = now
	// Drop sources whose decayed score is negligible.
	for ip, st := range s.src {
		if decay(st.score, now.Sub(st.lastUpdate), s.cfg.HalfLife) < 0.5 {
			delete(s.src, ip)
		}
	}
}

func (s *Scorer) evictOldestLocked() {
	var oldestIP string
	var oldest time.Time
	for ip, st := range s.src {
		if oldestIP == "" || st.lastSeen.Before(oldest) {
			oldestIP, oldest = ip, st.lastSeen
		}
	}
	if oldestIP != "" {
		delete(s.src, oldestIP)
	}
}

func decay(score float64, dt, halfLife time.Duration) float64 {
	if dt <= 0 || score == 0 {
		return score
	}
	return score * math.Pow(0.5, dt.Seconds()/halfLife.Seconds())
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }
