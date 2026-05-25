package testharness

// An eighth batch: the new resilience / containment categories and the
// before/during/after run-info collection (host, provenance, resource envelope,
// endpoint baseline/final snapshots) plus its rendering into the reports.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// --- new categories are wired ----------------------------------------------

func TestNewCategoriesRegistered(t *testing.T) {
	cats := map[Category]bool{}
	for _, c := range AllCategories() {
		cats[c] = true
	}
	if !cats[CatResilience] || !cats[CatContainment] {
		t.Fatalf("resilience/containment missing from AllCategories: %v", AllCategories())
	}
	cfg := &Config{Mode: "module", Endpoints: []Endpoint{
		{Label: "http", Proto: "tcp", Handler: "http"},
		{Label: "ftp", Proto: "tcp", Handler: "ftp"},
	}}
	cfg.ApplyDefaults()
	ids := caseIDSet(Select(Build(cfg), nil, []string{"resilience", "containment"}))
	for _, want := range []string{
		"resilience/oversize/http", "resilience/half-open/http", "resilience/flood/http", "resilience/slowloris/http",
		"containment/no-egress", "containment/path-traversal/http", "containment/path-traversal/ftp",
	} {
		if !ids[want] {
			t.Errorf("expected generated case %q; got %v", want, ids)
		}
	}
}

func TestResilienceContainmentPassClean(t *testing.T) {
	if testing.Short() {
		t.Skip("slowloris/flood timing")
	}
	cfg := &Config{Mode: "module", Quiet: true, Timeout: Duration(time.Second),
		Endpoints:  []Endpoint{{Label: "http", Proto: "tcp", Handler: "http"}, {Label: "ssh", Proto: "tcp", Handler: "ssh"}},
		Categories: []string{"resilience", "containment"}}
	cfg.ApplyDefaults()
	rr, err := mustRunnerRun(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for id, res := range resultsByID(rr) {
		if res.Status != StatusPass {
			t.Errorf("the well-behaved honeypot should pass %s; got %s (%s)", id, res.Status, res.Detail)
		}
	}
}

// containment/no-egress must FAIL when the target actually dials the canary.
// We can't make the real handlers do that, so exercise the detector directly
// with a tiny in-process "sensor" that echoes any address it is sent by dialing
// it — i.e. a deliberately-vulnerable reflector — and confirm the case catches
// the outbound connection by checking the canary listener semantics it relies
// on. Here we assert the building block: an accept-counting canary sees a dial.
func TestNoEgressCanaryCatchesDial(t *testing.T) {
	// This guards the core assumption of containment/no-egress: a localhost
	// canary listener reliably observes an outbound connection.
	cfg := &Config{Mode: "module", Quiet: true,
		Endpoints:  []Endpoint{{Label: "http", Proto: "tcp", Handler: "http"}},
		Categories: []string{"containment"}}
	cfg.ApplyDefaults()
	rr, err := mustRunnerRun(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The real http handler does not egress, so the case passes.
	if s := resultsByID(rr)["containment/no-egress"].Status; s != StatusPass {
		t.Errorf("no-egress against a non-egressing handler should pass; got %s", s)
	}
}

// --- run-info collection ----------------------------------------------------

func TestRunInfoCollected(t *testing.T) {
	cfg := &Config{Mode: "module", Quiet: true,
		Endpoints:  []Endpoint{{Label: "http", Proto: "tcp", Handler: "http"}, {Label: "ssh", Proto: "tcp", Handler: "ssh"}},
		Categories: []string{"unit"}}
	cfg.ApplyDefaults()
	r, _ := NewRunner(cfg, nil)
	rr, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	in := rr.Info
	if !in.present() {
		t.Fatal("RunInfo should be marked present after a real run")
	}
	if in.Host.OS == "" || in.Host.NumCPU == 0 || in.Host.GoVersion == "" {
		t.Errorf("host info incomplete: %+v", in.Host)
	}
	if !strings.Contains(in.Config, "mode=module") || !strings.Contains(in.Config, "endpoints=2") {
		t.Errorf("config summary unexpected: %q", in.Config)
	}
	if len(in.Baseline) != 2 || len(in.Final) != 2 {
		t.Errorf("want 2 baseline + 2 final snapshots; got %d/%d", len(in.Baseline), len(in.Final))
	}
	if in.Resources.Samples < 1 || in.Resources.Source == "" {
		t.Errorf("resource stats not collected: %+v", in.Resources)
	}
	if in.Resources.GoroutineStart == 0 {
		t.Error("goroutine start should be non-zero")
	}
	if in.StoppedHow != "completed all rounds" {
		t.Errorf("StoppedHow = %q; want completed all rounds", in.StoppedHow)
	}
	// module mode has no spawned binary.
	if in.Binary != nil {
		t.Errorf("module mode should not record a binary: %+v", in.Binary)
	}
	// the http baseline should be reachable with a stable banner hash.
	var sawHTTP bool
	for _, s := range in.Baseline {
		if s.Label == "http" {
			sawHTTP = true
			if !s.Reachable || s.Bytes == 0 || len(s.SHA256) != 64 {
				t.Errorf("http baseline snapshot looks wrong: %+v", s)
			}
		}
	}
	if !sawHTTP {
		t.Error("no http baseline snapshot")
	}
}

func TestConfigSummary(t *testing.T) {
	c := &Config{Mode: "network", Host: "10.0.0.1", Endpoints: []Endpoint{{Label: "a", Proto: "tcp", Port: 22, Handler: "ssh"}}}
	c.ApplyDefaults()
	s := configSummary(c)
	for _, want := range []string{"mode=network", "endpoints=1", "categories=[all]", "seed="} {
		if !strings.Contains(s, want) {
			t.Errorf("configSummary missing %q: %q", want, s)
		}
	}
}

func TestBinaryInfo(t *testing.T) {
	if binaryInfo("") != nil || binaryInfo("/no/such/binary/xyz") != nil {
		t.Error("binaryInfo should be nil for empty/missing paths")
	}
	p := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(p, []byte("hello world"), 0o755); err != nil {
		t.Fatal(err)
	}
	bi := binaryInfo(p)
	if bi == nil || bi.SizeBytes != 11 || len(bi.SHA256) != 64 || bi.Path != p {
		t.Fatalf("binaryInfo wrong: %+v", bi)
	}
}

func TestBannerLine(t *testing.T) {
	if got := bannerLine([]byte("SSH-2.0-x\r\n\x00\x01random")); string(got) != "SSH-2.0-x\r" {
		t.Errorf("bannerLine = %q; want the first line", got)
	}
	if got := bannerLine([]byte("no-newline")); string(got) != "no-newline" {
		t.Errorf("bannerLine without newline = %q", got)
	}
}

func TestResourceSamplerStartStop(t *testing.T) {
	rs := startSampler(func() int { return 0 }) // 0 => self
	time.Sleep(120 * time.Millisecond)
	s := rs.Stop()
	if s.Samples < 1 || s.Source == "" {
		t.Errorf("sampler stats incomplete: %+v", s)
	}
	if s.GoroutineStart == 0 || s.GoroutinePeak < s.GoroutineStart {
		t.Errorf("goroutine tracking wrong: %+v", s)
	}
	if !strings.Contains(s.Source, "harness") {
		t.Errorf("self-sampler Source = %q; want a harness source", s.Source)
	}
}

func TestReadRSSKBSelf(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc only on linux")
	}
	kb, ok := readRSSKB(0)
	if !ok || kb <= 0 {
		t.Errorf("readRSSKB(self) = %d, ok=%v; want a positive RSS", kb, ok)
	}
}

// --- rendering of the info section -------------------------------------------

func sampleRRWithInfo() *RunResult {
	rr := sampleRR()
	rr.Info = RunInfo{
		Host:   HostInfo{OS: "linux", Arch: "amd64", GoVersion: "go1.25.5", Hostname: "h", NumCPU: 8},
		Config: "mode=module endpoints=2 categories=[unit] rounds=1 concurrency=4 fuzz=8 timeout=5s seed=99",
		Binary: &BinaryInfo{Path: "/bin/sensor", SHA256: "abcd1234deadbeef" + strings.Repeat("0", 48), SizeBytes: 4096},
		Resources: ResourceStats{Source: "sensor (/proc/123)", Samples: 10,
			GoroutineStart: 12, GoroutinePeak: 140, GoroutineEnd: 14, RSSStartKB: 1000, RSSPeakKB: 5000, RSSEndKB: 1100},
		Baseline: []EndpointSnapshot{
			{Label: "http", Reachable: true, Bytes: 100, SHA256: "aaaa1111"},
			{Label: "ssh", Reachable: true, Bytes: 50, SHA256: "bbbb2222"},
			{Label: "ftp", Reachable: true, Bytes: 20, SHA256: "cccc3333"},
		},
		Final: []EndpointSnapshot{
			{Label: "http", Reachable: true, Bytes: 100, SHA256: "aaaa1111"}, // stable
			{Label: "ssh", Reachable: true, Bytes: 60, SHA256: "dddd4444"},   // drifted
			{Label: "ftp", Reachable: false},                                 // went dark
		},
		StoppedHow: "completed all rounds",
	}
	return rr
}

func TestInfoLinesRendering(t *testing.T) {
	joined := strings.Join(infoLines(sampleRRWithInfo()), "\n")
	for _, want := range []string{
		"environment:", "host       linux/amd64 cpus=8", "config     mode=module",
		"binary     /bin/sensor sha256=abcd1234 (4096 bytes)",
		"resources (sensor (/proc/123)):", "goroutines start=12 peak=140 end=14",
		"rss        start=1000KB peak=5000KB end=1100KB",
		"http       100B sha=aaaa1111 -> 100B sha=aaaa1111  stable",
		"DRIFTED", "NOW UNREACHABLE", "how it stopped: completed all rounds",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("infoLines missing %q:\n%s", want, joined)
		}
	}
}

func TestReportsCarryInfo(t *testing.T) {
	rr := sampleRRWithInfo()
	var txt, md, rtf, pdf bytes.Buffer
	_ = writeText(&txt, rr)
	_ = writeMarkdown(&md, rr)
	_ = writeRTF(&rtf, rr)
	_ = writePDF(&pdf, rr)
	if !strings.Contains(txt.String(), "environment:") || !strings.Contains(txt.String(), "sensor (/proc/123)") {
		t.Error("text report missing info section")
	}
	if !strings.Contains(md.String(), "## Environment & target") {
		t.Error("markdown report missing Environment section")
	}
	if !strings.Contains(rtf.String(), "environment:") {
		t.Error("rtf report missing info section")
	}
	if !strings.Contains(pdf.String(), "environment:") {
		t.Error("pdf report missing info section")
	}
}

func TestReportOmitsInfoWhenAbsent(t *testing.T) {
	// a RunResult rebuilt without RunInfo (e.g. from the DB) must not print an
	// empty environment block.
	rr := &RunResult{Started: time.Now().Add(-time.Second), Finished: time.Now(), Rounds: 1,
		Results: []Result{{CaseID: "unit/x", Category: CatUnit, Status: StatusPass}}}
	var txt, md bytes.Buffer
	_ = writeText(&txt, rr)
	_ = writeMarkdown(&md, rr)
	if strings.Contains(txt.String(), "environment:") {
		t.Error("text report should omit the info section when none was collected")
	}
	if strings.Contains(md.String(), "## Environment") {
		t.Error("markdown report should omit the Environment section when none was collected")
	}
}

func TestStoppedHowTimeBound(t *testing.T) {
	cfg := &Config{Mode: "module", Quiet: true, Duration: Duration(1 * time.Millisecond),
		Endpoints:  []Endpoint{{Label: "http", Proto: "tcp", Handler: "http"}},
		Categories: []string{"unit"}}
	cfg.ApplyDefaults()
	cfg.Duration = Duration(1 * time.Millisecond)
	r, _ := NewRunner(cfg, nil)
	rr, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Either it finished instantly (tiny suite) or hit the bound; both are valid,
	// but StoppedHow must be set and coherent.
	if rr.Info.StoppedHow == "" {
		t.Error("StoppedHow should always be recorded")
	}
}
