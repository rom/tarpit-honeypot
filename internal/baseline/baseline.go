// Package baseline adds lightweight statistical anomaly detection on top of the
// signature + pattern correlators: first-seen ("new") entities and volume
// spikes, plus a consolidated multi-stage kill-chain signal. It holds no ML
// dependency — just rolling sets and an EWMA — and emits derived events in the
// same shape as internal/correlate so the sensor dispatches/scores them
// uniformly.
//
//   - new-entity: the first time (after a warmup learning period) a source ASN,
//     destination port or source country is seen, emit baseline:new-asn /
//     baseline:new-port / baseline:new-country. Warmup lets the detector learn
//     the normal set before it starts flagging, so a fresh sensor doesn't alert
//     on everything at once.
//   - volume-spike: per-bucket event counts tracked with an EWMA mean+variance;
//     a closed bucket exceeding mean + k·stddev (and a floor) emits
//     baseline:volume-spike.
//   - kill-chain: per-source distinct ATT&CK *tactics* within a window; crossing
//     a stage threshold emits one consolidated killchain:multistage event
//     (recon → access → execution → exfil/impact), the "campaign" alert.
package baseline

import (
	"math"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Config tunes the detectors. Zero values fall back to the defaults below.
type Config struct {
	Warmup          time.Duration  // learn-before-flag period for new-entity (default 1h)
	SpikeWindow     time.Duration  // volume bucket width (default 1m)
	SpikeK          float64        // stddev multiplier for a spike (default 4)
	SpikeMin        int            // min events in a bucket before a spike can fire (default 50)
	SpikeWarmup     int            // buckets observed before spikes can fire (default 10)
	KillChainStages int            // distinct tactics to trigger the kill-chain (default 3)
	KillChainWindow time.Duration  // kill-chain observation window (default 30m)
	Severity        event.Severity // severity for emitted events (default High)
	now             func() time.Time
}

func (c *Config) withDefaults() {
	if c.Warmup <= 0 {
		c.Warmup = time.Hour
	}
	if c.SpikeWindow <= 0 {
		c.SpikeWindow = time.Minute
	}
	if c.SpikeK <= 0 {
		c.SpikeK = 4
	}
	if c.SpikeMin <= 0 {
		c.SpikeMin = 50
	}
	if c.SpikeWarmup <= 0 {
		c.SpikeWarmup = 10
	}
	if c.KillChainStages <= 0 {
		c.KillChainStages = 3
	}
	if c.KillChainWindow <= 0 {
		c.KillChainWindow = 30 * time.Minute
	}
	if c.Severity == 0 {
		c.Severity = event.SeverityHigh
	}
	if c.now == nil {
		c.now = time.Now
	}
}

type chainState struct {
	tactics map[string]struct{}
	since   time.Time
	emitted bool
}

// Detector is concurrency-safe; the sensor calls Observe from the bus loop.
type Detector struct {
	cfg   Config
	start time.Time

	mu sync.Mutex
	// first-seen sets (nil value = known).
	seenASN     map[string]struct{}
	seenPort    map[int]struct{}
	seenCountry map[string]struct{}
	// volume-spike EWMA state.
	curBucket int64
	curCount  int
	vMean     float64
	vVar      float64
	vBuckets  int
	// kill-chain per source.
	chain map[string]*chainState
}

// New builds a Detector. A zero Config uses the defaults.
func New(cfg Config) *Detector {
	cfg.withDefaults()
	return &Detector{
		cfg:         cfg,
		start:       cfg.now(),
		seenASN:     map[string]struct{}{},
		seenPort:    map[int]struct{}{},
		seenCountry: map[string]struct{}{},
		chain:       map[string]*chainState{},
	}
}

// Observe folds one event into the baselines and returns any derived alerts.
func (d *Detector) Observe(ev *event.Event) []*event.Event {
	if ev == nil {
		return nil
	}
	now := d.cfg.now()
	d.mu.Lock()
	defer d.mu.Unlock()

	var out []*event.Event
	warm := now.Sub(d.start) >= d.cfg.Warmup

	// --- new-entity (first-seen) ---
	if asn := asnStr(ev); asn != "" {
		if _, ok := d.seenASN[asn]; !ok {
			d.seenASN[asn] = struct{}{}
			if warm {
				out = append(out, d.mk(ev, now, "baseline:new-asn", map[string]any{"asn": asn}))
			}
		}
	}
	if port := ev.Dest.Port; port > 0 {
		if _, ok := d.seenPort[port]; !ok {
			d.seenPort[port] = struct{}{}
			if warm {
				out = append(out, d.mk(ev, now, "baseline:new-port", map[string]any{"dst_port": port}))
			}
		}
	}
	if c, _ := ev.Meta["geo_country"].(string); c != "" {
		if _, ok := d.seenCountry[c]; !ok {
			d.seenCountry[c] = struct{}{}
			if warm {
				out = append(out, d.mk(ev, now, "baseline:new-country", map[string]any{"country": c}))
			}
		}
	}

	// --- volume-spike (EWMA over per-bucket counts) ---
	if spike := d.observeVolume(ev, now); spike != nil {
		out = append(out, spike)
	}

	// --- kill-chain (distinct ATT&CK tactics per source) ---
	if kc := d.observeKillChain(ev, now); kc != nil {
		out = append(out, kc)
	}
	return out
}

// observeVolume rolls the time bucket; when the bucket advances it evaluates the
// just-closed bucket against the EWMA baseline and returns a spike event if it
// exceeded mean + k·stddev (after a warmup of buckets).
func (d *Detector) observeVolume(ev *event.Event, now time.Time) *event.Event {
	b := now.UnixNano() / int64(d.cfg.SpikeWindow)
	if d.vBuckets == 0 && d.curCount == 0 && d.curBucket == 0 {
		d.curBucket = b
	}
	if b == d.curBucket {
		d.curCount++
		return nil
	}
	// Bucket advanced: finalize the previous bucket.
	prev := d.curCount
	prevBucket := d.curBucket
	var spike *event.Event
	if d.vBuckets >= d.cfg.SpikeWarmup && prev >= d.cfg.SpikeMin {
		std := math.Sqrt(d.vVar)
		if float64(prev) > d.vMean+d.cfg.SpikeK*std {
			spike = d.mk(ev, now, "baseline:volume-spike", map[string]any{
				"bucket_events": prev,
				"baseline_mean": math.Round(d.vMean*10) / 10,
				"baseline_std":  math.Round(std*10) / 10,
				"window_s":      int(d.cfg.SpikeWindow.Seconds()),
				"bucket_start":  time.Unix(0, prevBucket*int64(d.cfg.SpikeWindow)).UTC().Format(time.RFC3339),
			})
		}
	}
	// Update EWMA with the closed bucket (alpha = 0.2), count skipped empty
	// buckets as zeros so a quiet gap lowers the mean.
	gap := b - prevBucket
	for i := int64(0); i < gap; i++ {
		v := 0.0
		if i == 0 {
			v = float64(prev)
		}
		const alpha = 0.2
		diff := v - d.vMean
		d.vMean += alpha * diff
		d.vVar = (1 - alpha) * (d.vVar + alpha*diff*diff)
		d.vBuckets++
	}
	d.curBucket = b
	d.curCount = 1
	return spike
}

// observeKillChain tracks distinct ATT&CK tactics per source IP within the
// window and emits one consolidated event when the stage threshold is crossed.
func (d *Detector) observeKillChain(ev *event.Event, now time.Time) *event.Event {
	ip := ev.Source.IP
	if ip == "" || len(ev.MitreTactics) == 0 {
		return nil
	}
	st := d.chain[ip]
	if st == nil || now.Sub(st.since) > d.cfg.KillChainWindow {
		st = &chainState{tactics: map[string]struct{}{}, since: now}
		d.chain[ip] = st
	}
	for _, t := range ev.MitreTactics {
		if t != "" {
			st.tactics[t] = struct{}{}
		}
	}
	if st.emitted || len(st.tactics) < d.cfg.KillChainStages {
		return nil
	}
	st.emitted = true
	tactics := make([]string, 0, len(st.tactics))
	for t := range st.tactics {
		tactics = append(tactics, t)
	}
	sort.Strings(tactics)
	return d.mk(ev, now, "killchain:multistage", map[string]any{
		"tactics":       tactics,
		"stage_count":   len(tactics),
		"window_s":      int(d.cfg.KillChainWindow.Seconds()),
		"first_seen":    st.since.UTC().Format(time.RFC3339),
		"intent":        "multi-stage kill chain from a single source — consolidated campaign alert",
		"severity_note": "statistical/sequence correlation",
	})
}

// mk builds a derived event in the correlate shape.
func (d *Detector) mk(ev *event.Event, now time.Time, ruleID string, meta map[string]any) *event.Event {
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   ruleID,
		Severity: d.cfg.Severity,
		Source:   ev.Source,
		Meta:     meta,
	}
}

// asnStr returns the event's ASN as a string ("" when absent), handling the
// JSON-number (float64) and int/string shapes meta can carry.
func asnStr(ev *event.Event) string {
	switch v := ev.Meta["asn"].(type) {
	case float64:
		if v == 0 {
			return ""
		}
		return strconv.FormatInt(int64(v), 10)
	case int:
		if v == 0 {
			return ""
		}
		return strconv.Itoa(v)
	case int64:
		if v == 0 {
			return ""
		}
		return strconv.FormatInt(v, 10)
	case string:
		return v
	}
	return ""
}
