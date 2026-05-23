package fuzzdos

import (
	"sort"
	"time"
)

// Tracker accumulates per-source connection signals to classify
// denial-of-service activity (flood typing) and sustained fuzzing
// campaigns. Single-goroutine use behind the sensor's serialized bus loop
// (no internal locking), mirroring scananalysis.Tracker.
type Tracker struct {
	window time.Duration
	srcs   map[string]*srcState
	lastGC time.Time
}

type srcState struct {
	first     time.Time
	last      time.Time
	conns     int
	bytes     int64
	fuzz      int
	tech      map[string]int // fuzz technique histogram
	portConns map[int]int    // conns per dest port (app-flood concentration)

	emittedDoS  bool
	emittedFuzz bool
}

// Observation is one connection's worth of signal.
type Observation struct {
	SourceIP string
	DestPort int
	Time     time.Time
	Bytes    int64
	// Fuzz is the per-payload verdict from ClassifyPayload.
	Fuzz Verdict
}

// Result is what Observe returns when a source crosses a threshold. A
// source can be classified as DoS, fuzzing, or both in one Result.
type Result struct {
	SourceIP string
	// DoS classification.
	DoS     bool
	DoSType string // connection-flood | app-flood | volumetric | malformed-flood
	// Fuzzing-campaign classification.
	Fuzzing   bool
	Technique string // dominant fuzz technique across the window
	FuzzCount int
	// Context.
	Conns      int
	Bytes      int64
	Window     time.Duration
	Confidence int // 0..100
}

// Detection thresholds (within one window). Conservative so a legitimate
// burst doesn't trip a flood.
const (
	connFloodThreshold = 100            // total connections from one source
	appFloodThreshold  = 80             // connections to a single dest port
	volumetricBytes    = int64(8) << 20 // 8 MiB cumulative inbound
	malformedFlood     = 20             // fuzz payloads = flood-by-malformed
	fuzzCampaign       = 8              // fuzz payloads = sustained campaign
)

// NewTracker builds a Tracker. window bounds how long a source's state
// lives without new activity (default 60s).
func NewTracker(window time.Duration) *Tracker {
	if window <= 0 {
		window = 60 * time.Second
	}
	return &Tracker{window: window, srcs: map[string]*srcState{}}
}

// Observe records one connection and returns a non-nil Result the first
// time the source crosses a DoS or fuzzing-campaign threshold (each
// category emits at most once per window).
func (t *Tracker) Observe(o Observation) *Result {
	if o.SourceIP == "" {
		return nil
	}
	now := o.Time
	if now.IsZero() {
		now = time.Now()
	}
	// Evict idle sources once per window so the map stays bounded under
	// many distinct / spoofed source IPs.
	if now.Sub(t.lastGC) > t.window {
		for ip, st := range t.srcs {
			if now.Sub(st.last) > t.window {
				delete(t.srcs, ip)
			}
		}
		t.lastGC = now
	}
	st, ok := t.srcs[o.SourceIP]
	if !ok || now.Sub(st.last) > t.window {
		st = &srcState{first: now, tech: map[string]int{}, portConns: map[int]int{}}
		t.srcs[o.SourceIP] = st
	}
	st.last = now
	st.conns++
	if o.Bytes > 0 {
		st.bytes += o.Bytes
	}
	if o.DestPort > 0 {
		st.portConns[o.DestPort]++
	}
	if o.Fuzz.Fuzzing {
		st.fuzz++
		st.tech[o.Fuzz.Technique]++
	}

	var r *Result
	ensure := func() *Result {
		if r == nil {
			r = &Result{
				SourceIP: o.SourceIP,
				Conns:    st.conns,
				Bytes:    st.bytes,
				Window:   t.window,
			}
		}
		return r
	}

	if !st.emittedDoS {
		if dt := classifyDoS(st); dt != "" {
			st.emittedDoS = true
			res := ensure()
			res.DoS = true
			res.DoSType = dt
		}
	}
	if !st.emittedFuzz && st.fuzz >= fuzzCampaign {
		st.emittedFuzz = true
		res := ensure()
		res.Fuzzing = true
		res.Technique = dominantTechnique(st.tech)
		res.FuzzCount = st.fuzz
	}
	if r != nil {
		r.Conns = st.conns
		r.Bytes = st.bytes
		r.FuzzCount = st.fuzz
		r.Confidence = confidence(st, r)
	}
	return r
}

// classifyDoS picks the denial-of-service label for a source's state, or
// "" when no threshold is crossed. app-flood (one port hammered) is
// preferred over generic connection-flood when a single port dominates.
func classifyDoS(st *srcState) string {
	switch {
	case maxPortConns(st) >= appFloodThreshold:
		return "app-flood"
	case st.conns >= connFloodThreshold:
		return "connection-flood"
	case st.bytes >= volumetricBytes:
		return "volumetric"
	case st.fuzz >= malformedFlood:
		return "malformed-flood"
	}
	return ""
}

func maxPortConns(st *srcState) int {
	max := 0
	for _, n := range st.portConns {
		if n > max {
			max = n
		}
	}
	return max
}

// dominantTechnique returns the most-frequent fuzz technique (ties broken
// alphabetically for determinism).
func dominantTechnique(tech map[string]int) string {
	best, bestN := "", -1
	keys := make([]string, 0, len(tech))
	for k := range tech {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if tech[k] > bestN {
			best, bestN = k, tech[k]
		}
	}
	return best
}

// confidence scores 0..100 from how far past threshold the dominant signal
// is, plus a bump when a source is both flooding and fuzzing.
func confidence(st *srcState, r *Result) int {
	score := 50
	if r.DoS {
		switch r.DoSType {
		case "app-flood":
			score += pctOver(maxPortConns(st), appFloodThreshold)
		case "connection-flood":
			score += pctOver(st.conns, connFloodThreshold)
		case "volumetric":
			score += pctOver(int(st.bytes>>20), int(volumetricBytes>>20))
		case "malformed-flood":
			score += pctOver(st.fuzz, malformedFlood)
		}
	}
	if r.Fuzzing {
		score += pctOver(st.fuzz, fuzzCampaign)
	}
	if r.DoS && r.Fuzzing {
		score += 10
	}
	if score > 100 {
		score = 100
	}
	return score
}

// pctOver returns up to 40 points scaled by how far have/threshold exceeds 1x.
func pctOver(have, threshold int) int {
	if threshold <= 0 || have <= threshold {
		return 0
	}
	over := (have - threshold) * 40 / threshold
	if over > 40 {
		over = 40
	}
	return over
}
