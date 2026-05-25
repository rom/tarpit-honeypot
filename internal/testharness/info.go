package testharness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RunInfo is the before/during/after context gathered about a run and the
// program under test — beyond the pass/fail of individual cases. It answers
// "what exactly was tested, in what environment, and how did the target hold
// up" so a report is self-describing and reproducible.
type RunInfo struct {
	Host       HostInfo           `json:"host"`
	Config     string             `json:"config_summary"`
	Binary     *BinaryInfo        `json:"binary,omitempty"` // managed network target only
	Baseline   []EndpointSnapshot `json:"baseline,omitempty"`
	Final      []EndpointSnapshot `json:"final,omitempty"`
	Resources  ResourceStats      `json:"resources"`
	StoppedHow string             `json:"stopped_how,omitempty"`
	SelfCheck  string             `json:"self_check,omitempty"`       // harness pass/fail-control result
	Expected   int                `json:"expected_results,omitempty"` // (case,round) pairs dispatched
	Recorded   int                `json:"recorded_results,omitempty"` // results recorded (== Expected)
}

// AccountingOK reports whether every dispatched case produced exactly one
// recorded result (no result silently lost).
func (in RunInfo) AccountingOK() bool { return in.Expected == in.Recorded }

// HostInfo describes the machine the harness ran on.
type HostInfo struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	GoVersion string `json:"go_version"`
	Hostname  string `json:"hostname"`
	NumCPU    int    `json:"num_cpu"`
}

// BinaryInfo identifies the spawned sensor build (provenance / supply chain).
type BinaryInfo struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// EndpointSnapshot captures what an endpoint looked like at a point in time, so
// before/after can be compared for drift (a banner that changes mid-run, or an
// endpoint that goes dark, is itself a finding-worthy signal).
type EndpointSnapshot struct {
	Label     string `json:"label"`
	Handler   string `json:"handler"`
	Proto     string `json:"proto"`
	Port      int    `json:"port"`
	Reachable bool   `json:"reachable"`
	Bytes     int    `json:"bytes"`
	SHA256    string `json:"sha256,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
}

// ResourceStats is the during-run resource envelope (leak / blow-up detector).
type ResourceStats struct {
	Source         string `json:"source"`
	Samples        int    `json:"samples"`
	GoroutineStart int    `json:"goroutine_start"`
	GoroutinePeak  int    `json:"goroutine_peak"`
	GoroutineEnd   int    `json:"goroutine_end"`
	RSSStartKB     int64  `json:"rss_start_kb"`
	RSSPeakKB      int64  `json:"rss_peak_kb"`
	RSSEndKB       int64  `json:"rss_end_kb"`
}

// present reports whether RunInfo was actually collected (a real run), so
// reports rebuilt from the DB — which don't carry it — omit the section.
func (in RunInfo) present() bool {
	return in.Host.OS != "" || in.Resources.Source != "" || len(in.Baseline) > 0
}

func hostInfo() HostInfo {
	h, _ := os.Hostname()
	return HostInfo{OS: runtime.GOOS, Arch: runtime.GOARCH, GoVersion: runtime.Version(), Hostname: h, NumCPU: runtime.NumCPU()}
}

func configSummary(c *Config) string {
	cats := "[all]"
	if len(c.Categories) > 0 {
		cats = fmt.Sprintf("%v", c.Categories)
	}
	return fmt.Sprintf("mode=%s endpoints=%d categories=%s rounds=%d concurrency=%d fuzz=%d timeout=%s seed=%d",
		c.Mode, len(c.Endpoints), cats, c.Rounds, c.Concurrency, c.FuzzIterations, c.Timeout.D(), c.Seed)
}

// binaryInfo hashes the spawned sensor binary for provenance. Best-effort: nil
// if the path can't be read.
func binaryInfo(path string) *BinaryInfo {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return nil
	}
	return &BinaryInfo{Path: path, SHA256: hex.EncodeToString(h.Sum(nil)), SizeBytes: n}
}

// snapshotEndpoints probes every endpoint once and records what it answered, so
// baseline (pre-run) and final (post-run) can be diffed.
func snapshotEndpoints(ctx context.Context, t *Target, cfg *Config) []EndpointSnapshot {
	var out []EndpointSnapshot
	for _, e := range cfg.Endpoints {
		s := EndpointSnapshot{Label: e.Label, Handler: e.Handler, Proto: e.Proto, Port: e.Port}
		if e.Proto == "tcp" {
			spec, known := specFor(e)
			var pr []byte
			if known && !spec.ServerFirst {
				pr = spec.Probe
			}
			if resp, err := probe(ctx, t, e, pr); err == nil {
				// Hash the identity banner (first line) not the whole response:
				// many protocols put a per-connection nonce after it (e.g. the
				// SSH KEXINIT cookie), which would otherwise look like drift.
				sum := sha256.Sum256(bannerLine(resp))
				s.Reachable, s.Bytes, s.SHA256, s.Snippet = true, len(resp), hex.EncodeToString(sum[:]), snippet(resp)
			}
		} else {
			s.Reachable = true // no cheap UDP probe; trust it (matches readiness logic)
		}
		out = append(out, s)
	}
	return out
}

// bannerLine returns the first line of a response (the stable identity part),
// or the whole thing if there is no newline.
func bannerLine(resp []byte) []byte {
	if i := bytes.IndexByte(resp, '\n'); i >= 0 {
		return resp[:i]
	}
	return resp
}

// --- resource sampling ------------------------------------------------------

func readRSSKB(pid int) (int64, bool) {
	name := "/proc/self/statm"
	if pid > 0 {
		name = "/proc/" + strconv.Itoa(pid) + "/statm"
	}
	b, err := os.ReadFile(name)
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0, false
	}
	pages, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return pages * int64(os.Getpagesize()) / 1024, true
}

func runtimeRSSKB() int64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.Sys / 1024)
}

// resourceSampler periodically records RSS + goroutine count for the duration
// of a run. RSS is read from the sensor's /proc entry when managed (so it
// reflects the program under test), else from the harness process — which in
// module mode hosts the handlers, making it the right place to spot a leak.
type resourceSampler struct {
	pidFn   func() int
	useProc bool
	stop    chan struct{}
	done    chan struct{}
	mu      sync.Mutex
	s       ResourceStats
}

func startSampler(pidFn func() int) *resourceSampler {
	rs := &resourceSampler{pidFn: pidFn, stop: make(chan struct{}), done: make(chan struct{})}
	pid := pidFn()
	rss, ok := readRSSKB(pid)
	switch {
	case ok && pid > 0:
		rs.useProc, rs.s.Source = true, "sensor (/proc/"+strconv.Itoa(pid)+")"
	case ok:
		rs.useProc, rs.s.Source = true, "harness (/proc/self)"
	default:
		rss, rs.s.Source = runtimeRSSKB(), "harness (runtime)"
	}
	g := runtime.NumGoroutine()
	rs.s.Samples = 1
	rs.s.GoroutineStart, rs.s.GoroutinePeak, rs.s.GoroutineEnd = g, g, g
	rs.s.RSSStartKB, rs.s.RSSPeakKB, rs.s.RSSEndKB = rss, rss, rss
	go rs.loop()
	return rs
}

func (rs *resourceSampler) sampleLocked() {
	g := runtime.NumGoroutine()
	rss := rs.s.RSSEndKB
	if rs.useProc {
		if v, ok := readRSSKB(rs.pidFn()); ok { // re-resolve pid so a restart is tracked
			rss = v
		}
	} else {
		rss = runtimeRSSKB()
	}
	rs.s.Samples++
	rs.s.GoroutineEnd = g
	if g > rs.s.GoroutinePeak {
		rs.s.GoroutinePeak = g
	}
	rs.s.RSSEndKB = rss
	if rss > rs.s.RSSPeakKB {
		rs.s.RSSPeakKB = rss
	}
}

func (rs *resourceSampler) loop() {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-rs.stop:
			rs.mu.Lock()
			rs.sampleLocked()
			rs.mu.Unlock()
			close(rs.done)
			return
		case <-t.C:
			rs.mu.Lock()
			rs.sampleLocked()
			rs.mu.Unlock()
		}
	}
}

// Stop ends sampling and returns the collected envelope.
func (rs *resourceSampler) Stop() ResourceStats {
	close(rs.stop)
	<-rs.done
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.s
}

// --- rendering --------------------------------------------------------------

func shortHash(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// infoLines renders the RunInfo as plain ASCII lines for the human reports.
func infoLines(rr *RunResult) []string {
	in := rr.Info
	var ls []string
	add := func(f string, a ...interface{}) { ls = append(ls, fmt.Sprintf(f, a...)) }
	ls = append(ls, "environment:")
	add("  host       %s/%s cpus=%d go=%s host=%s", in.Host.OS, in.Host.Arch, in.Host.NumCPU, in.Host.GoVersion, in.Host.Hostname)
	if in.Config != "" {
		add("  config     %s", in.Config)
	}
	if in.Binary != nil {
		add("  binary     %s sha256=%s (%d bytes)", in.Binary.Path, shortHash(in.Binary.SHA256), in.Binary.SizeBytes)
	}
	if in.SelfCheck != "" || in.Expected > 0 {
		acct := fmt.Sprintf("%d/%d results recorded", in.Recorded, in.Expected)
		if !in.AccountingOK() {
			acct += " — MISMATCH (a result was lost)"
		}
		add("  harness    self-check %s; accounting %s", in.SelfCheck, acct)
	}
	r := in.Resources
	add("resources (%s):", r.Source)
	add("  goroutines start=%d peak=%d end=%d  (harness process; in-process handlers included in module mode)", r.GoroutineStart, r.GoroutinePeak, r.GoroutineEnd)
	add("  rss        start=%dKB peak=%dKB end=%dKB", r.RSSStartKB, r.RSSPeakKB, r.RSSEndKB)
	if len(in.Baseline) > 0 {
		ls = append(ls, "target snapshots (baseline -> final):")
		finals := map[string]EndpointSnapshot{}
		for _, s := range in.Final {
			finals[s.Label] = s
		}
		for _, b := range in.Baseline {
			f, ok := finals[b.Label]
			ls = append(ls, "  "+snapshotLine(b, f, ok))
		}
	}
	if in.StoppedHow != "" {
		add("how it stopped: %s", in.StoppedHow)
	}
	return ls
}

func snapshotLine(b, f EndpointSnapshot, haveFinal bool) string {
	desc := func(s EndpointSnapshot) string {
		if !s.Reachable {
			return "unreachable"
		}
		return fmt.Sprintf("%dB sha=%s", s.Bytes, shortHash(s.SHA256))
	}
	if !haveFinal {
		return fmt.Sprintf("%-10s %s", b.Label, desc(b))
	}
	note := "stable"
	switch {
	case b.Reachable && !f.Reachable:
		note = "NOW UNREACHABLE"
	case !b.Reachable && f.Reachable:
		note = "now reachable"
	case b.Reachable && f.Reachable && b.SHA256 != f.SHA256:
		note = "DRIFTED"
	case !b.Reachable && !f.Reachable:
		note = "unreachable"
	}
	return fmt.Sprintf("%-10s %s -> %s  %s", b.Label, desc(b), desc(f), note)
}
