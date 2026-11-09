// Package detonate closes the capture→intelligence loop for malware the
// honeypot collects. When a handler captures a binary/dropper artifact, the
// sensor hands its sha256 (and, when available, the stored file path) to a
// Detonator. The Detonator looks the hash up on VirusTotal and — only when the
// operator opts in to uploading samples — submits unknown samples to a CAPE
// sandbox for dynamic detonation. The resulting verdict (AV detection ratio,
// malware family) and the network IOCs it yields (contacted domains / IPs /
// URLs, dropped-file hashes) are emitted back onto the event bus as a
// `malware:detonation` event, which flows through the normal IOC pipeline into
// the IOC store and the TAXII/MISP exporters.
//
// Design constraints, all honoured here:
//   - Outbound goes through the process egress policy (egress.HTTPClient), so a
//     locked-down deployment fails closed.
//   - Secrets (VT / CAPE keys) are read from env-var NAMES, never stored inline.
//   - Uploading captured samples (which can make them public and tip off the
//     attacker) is OFF by default; hash-lookup only unless SubmitSamples is set.
//   - Work is async and bounded: a fixed worker pool drains a bounded queue
//     (drop-on-full, counted), a per-hash TTL cache suppresses re-queries, and a
//     min-interval limiter respects the backend's rate limit.
package detonate

import (
	"context"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/tarpit-honeypot/internal/egress"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// Config controls malware detonation / intel lookup. Zero value is disabled.
type Config struct {
	Enabled bool
	// VTAPIKeyEnv names the environment variable holding the VirusTotal API key.
	// Empty disables the VirusTotal lookup.
	VTAPIKeyEnv string
	// VTBaseURL overrides the VirusTotal API base (tests). Default production URL.
	VTBaseURL string
	// SubmitSamples allows UPLOADING unknown samples to the configured sandbox
	// (CAPE) for dynamic detonation. Off by default: uploading a captured sample
	// can expose it publicly and tip off the attacker. Hash-lookup needs no upload.
	SubmitSamples bool
	// CAPE is the optional CAPE/Cuckoo sandbox backend (used only when
	// SubmitSamples is true and CAPE.URL is set).
	CAPE CAPEConfig

	Workers        int           // worker goroutines (default 2)
	QueueSize      int           // bounded submission queue (default 256)
	Timeout        time.Duration // per-HTTP-request timeout (default 20s)
	CacheTTL       time.Duration // per-hash result cache TTL (default 24h)
	RequestsPerMin int           // outbound request cap (default 4 = VT free tier)
	MaxSampleBytes int64         // max sample size to upload (default 32 MiB)
}

// CAPEConfig configures a CAPE sandbox REST backend.
type CAPEConfig struct {
	URL       string // base, e.g. https://cape.example.internal
	TokenEnv  string // env var holding the CAPE API token (Authorization: Token <v>)
	PollEvery time.Duration
	MaxWait   time.Duration
}

// Verdict is the result of a lookup/detonation.
type Verdict struct {
	SHA256    string
	Source    string // "virustotal" | "cape"
	Found     bool
	Positives int
	Total     int
	Family    string
	Label     string
	TypeTags  []string
	Domains   []string
	IPs       []string
	URLs      []string
	Dropped   []string // dropped-file sha256s
}

// job is one queued artifact to analyse.
type job struct {
	sha256 string
	path   string // stored sample path ("" if bytes unavailable)
	src    event.Endpoint
	proto  string
}

// Detonator runs the async lookup/detonation pipeline.
type Detonator struct {
	cfg    Config
	vtKey  string
	capeTk string
	client *http.Client
	emit   func(*event.Event)

	queue chan job
	wg    sync.WaitGroup

	mu     sync.Mutex
	cache  map[string]time.Time // sha256 -> expiry (dedup / TTL)
	last   time.Time            // last outbound request (min-interval limiter)
	minGap time.Duration

	Submitted atomic.Int64
	Dropped   atomic.Int64
	Verdicts  atomic.Int64
	Errors    atomic.Int64
}

// New builds a Detonator. emit is called (off the caller's goroutine) with each
// malware:detonation event to inject onto the bus; it must be non-blocking-safe.
// Returns (nil, nil) when disabled so callers can hold the result unconditionally.
func New(cfg Config, emit func(*event.Event)) (*Detonator, error) {
	if !cfg.Enabled || emit == nil {
		return nil, nil
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 256
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 24 * time.Hour
	}
	if cfg.RequestsPerMin <= 0 {
		cfg.RequestsPerMin = 4
	}
	if cfg.MaxSampleBytes <= 0 {
		cfg.MaxSampleBytes = 32 << 20
	}
	if cfg.VTBaseURL == "" {
		cfg.VTBaseURL = "https://www.virustotal.com/api/v3"
	}
	d := &Detonator{
		cfg:    cfg,
		client: egress.HTTPClient(cfg.Timeout),
		emit:   emit,
		queue:  make(chan job, cfg.QueueSize),
		cache:  map[string]time.Time{},
		minGap: time.Minute / time.Duration(cfg.RequestsPerMin),
	}
	if cfg.VTAPIKeyEnv != "" {
		d.vtKey = os.Getenv(cfg.VTAPIKeyEnv)
	}
	if cfg.CAPE.TokenEnv != "" {
		d.capeTk = os.Getenv(cfg.CAPE.TokenEnv)
	}
	for i := 0; i < cfg.Workers; i++ {
		d.wg.Add(1)
		go d.worker()
	}
	return d, nil
}

// Submit queues an artifact for analysis. Non-blocking and dedup'd: a hash seen
// within CacheTTL, or a full queue, is dropped (and counted). Safe to call with
// a nil receiver (disabled).
func (d *Detonator) Submit(sha256, path string, src event.Endpoint, proto string) {
	if d == nil || !validSHA256(sha256) {
		return
	}
	if !d.reserve(sha256) {
		return // already seen within TTL
	}
	select {
	case d.queue <- job{sha256: sha256, path: path, src: src, proto: proto}:
		d.Submitted.Add(1)
	default:
		d.Dropped.Add(1)
		d.release(sha256) // let a later sighting retry rather than cache a no-op
	}
}

// Close stops the workers and waits for in-flight jobs. Safe on a nil receiver.
func (d *Detonator) Close() error {
	if d == nil {
		return nil
	}
	close(d.queue)
	d.wg.Wait()
	return nil
}

func (d *Detonator) worker() {
	defer d.wg.Done()
	for j := range d.queue {
		d.process(j)
	}
}

func (d *Detonator) process(j job) {
	ctx, cancel := context.WithTimeout(context.Background(), d.cfg.Timeout+d.cfg.CAPE.MaxWait+10*time.Second)
	defer cancel()

	var v *Verdict
	// 1) VirusTotal hash lookup (no upload).
	if d.vtKey != "" {
		if got, err := d.virusTotalLookup(ctx, j.sha256); err != nil {
			d.Errors.Add(1)
		} else if got != nil {
			v = got
		}
	}
	// 2) If unknown to VT (or VT disabled) and uploading is permitted, detonate
	//    the stored sample in CAPE.
	if (v == nil || !v.Found) && d.cfg.SubmitSamples && d.cfg.CAPE.URL != "" && j.path != "" {
		if got, err := d.capeDetonate(ctx, j.sha256, j.path); err != nil {
			d.Errors.Add(1)
		} else if got != nil {
			v = mergeVerdict(v, got)
		}
	}
	// Emit only a meaningful verdict: an AV hit, a named family, or network
	// IOCs. A file VT has never seen (Found=false) or knows to be clean
	// (0 detections, no IOCs) produces nothing.
	if v == nil || !(v.Positives > 0 || v.Family != "" || len(v.Domains)+len(v.IPs)+len(v.URLs)+len(v.Dropped) > 0) {
		return
	}
	d.Verdicts.Add(1)
	d.emit(verdictEvent(v, j))
}

// reserve records a hash as in-progress/seen; returns false if already present
// and unexpired. release undoes a reserve (used when the job was dropped).
func (d *Detonator) reserve(h string) bool {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if exp, ok := d.cache[h]; ok && now.Before(exp) {
		return false
	}
	// Opportunistic sweep so the cache can't grow without bound.
	if len(d.cache) > 8192 {
		for k, exp := range d.cache {
			if now.After(exp) {
				delete(d.cache, k)
			}
		}
	}
	d.cache[h] = now.Add(d.cfg.CacheTTL)
	return true
}

func (d *Detonator) release(h string) {
	d.mu.Lock()
	delete(d.cache, h)
	d.mu.Unlock()
}

// wait enforces the min-interval between outbound requests (shared across
// workers) so the honeypot never exceeds the backend's rate limit.
func (d *Detonator) wait(ctx context.Context) error {
	d.mu.Lock()
	now := time.Now()
	earliest := d.last.Add(d.minGap)
	if now.Before(earliest) {
		d.last = earliest
	} else {
		d.last = now
	}
	sleep := time.Until(d.last)
	d.mu.Unlock()
	if sleep <= 0 {
		return nil
	}
	t := time.NewTimer(sleep)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// verdictEvent builds the malware:detonation event. Its meta carries the
// contacted-* IOC lists in the keys ioc.Extract reads, so they persist and
// export through the normal pipeline.
func verdictEvent(v *Verdict, j job) *event.Event {
	sev := event.SeverityHigh
	if v.Positives >= 5 || v.Family != "" || len(v.Domains)+len(v.IPs)+len(v.URLs) > 0 {
		sev = event.SeverityCritical
	}
	meta := map[string]any{
		"file_sha256":       v.SHA256,
		"detonation_source": v.Source,
		"av_positives":      v.Positives,
		"av_total":          v.Total,
	}
	if v.Family != "" {
		meta["malware_family"] = v.Family
	}
	if v.Label != "" {
		meta["av_label"] = v.Label
	}
	if len(v.TypeTags) > 0 {
		meta["file_type_tags"] = v.TypeTags
	}
	if len(v.Domains) > 0 {
		meta["contacted_domains"] = v.Domains
	}
	if len(v.IPs) > 0 {
		meta["contacted_ips"] = v.IPs
	}
	if len(v.URLs) > 0 {
		meta["contacted_urls"] = v.URLs
	}
	if len(v.Dropped) > 0 {
		meta["dropped_sha256"] = v.Dropped
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     time.Now(),
		RuleID:   "malware:detonation",
		Severity: sev,
		Source:   j.src,
		Proto:    j.proto,
		Meta:     meta,
	}
}

func mergeVerdict(a, b *Verdict) *Verdict {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if !a.Found && b.Found {
		a.Found = true
	}
	if a.Family == "" {
		a.Family = b.Family
	}
	if a.Source == "" || (b.Found && !a.Found) {
		a.Source = b.Source
	}
	a.Domains = dedupAppend(a.Domains, b.Domains)
	a.IPs = dedupAppend(a.IPs, b.IPs)
	a.URLs = dedupAppend(a.URLs, b.URLs)
	a.Dropped = dedupAppend(a.Dropped, b.Dropped)
	return a
}

func dedupAppend(a, b []string) []string {
	seen := map[string]bool{}
	for _, v := range a {
		seen[v] = true
	}
	for _, v := range b {
		if v != "" && !seen[v] {
			seen[v] = true
			a = append(a, v)
		}
	}
	return a
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
