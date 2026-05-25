package testharness

// A fifth batch in the same vein: more report/validate/matcher unit tests, more
// scan/sweep/reliability integration against fake targets + a fake events API,
// more low-level exchange edge cases, and a managed kill+respawn stress loop
// (which exercises the reaper/exited-channel synchronisation repeatedly).

import (
	"bytes"
	"context"
	"encoding/xml"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- unit / low-level -------------------------------------------------------

func TestSnippetEllipsisBoundary(t *testing.T) {
	at80 := snippet(bytes.Repeat([]byte("A"), 80))
	if strings.HasSuffix(at80, "…") || strings.Count(at80, "A") != 80 {
		t.Errorf("snippet of exactly 80 bytes should not be truncated: %q", at80)
	}
	over := snippet(bytes.Repeat([]byte("A"), 81))
	if !strings.HasSuffix(over, "…") || strings.Count(over, "A") != 80 {
		t.Errorf("snippet of 81 bytes should keep 80 + an ellipsis: %q", over)
	}
}

func TestConfigValidateReportAndProto(t *testing.T) {
	badReport := &Config{Mode: "network", Host: "127.0.0.1",
		Endpoints: []Endpoint{{Label: "a", Proto: "tcp", Port: 22, Handler: "ssh"}},
		Reports:   []ReportCfg{{Format: "xlsx", Path: "x"}}}
	badReport.ApplyDefaults()
	if err := badReport.Validate(); err == nil {
		t.Error("an unknown report format should be rejected")
	}
	badProto := &Config{Mode: "network", Host: "127.0.0.1",
		Endpoints: []Endpoint{{Label: "a", Proto: "sctp", Port: 22, Handler: "ssh"}}}
	badProto.ApplyDefaults()
	if err := badProto.Validate(); err == nil {
		t.Error("a proto other than tcp/udp should be rejected")
	}
}

func TestMatchRulePrefixEmpty(t *testing.T) {
	ev := apiEvent{RuleID: "listener:ssh"}
	if !MatchRulePrefix("")(ev) {
		t.Error("an empty prefix should match any rule_id")
	}
	if !MatchRulePrefix("listener:")(ev) || MatchRulePrefix("scan:")(ev) {
		t.Error("rule-prefix matching is wrong")
	}
	if MatchAnomaly("")(apiEvent{}) {
		t.Error("an empty anomaly marker should not match an event with no anomalies")
	}
}

func TestBoundedNoteInReports(t *testing.T) {
	rr := &RunResult{Started: time.Now().Add(-time.Second), Finished: time.Now(), Rounds: 1, TimeBounded: true,
		Results: []Result{{CaseID: "unit/x", Category: CatUnit, Status: StatusPass}}}
	var b bytes.Buffer
	_ = writeText(&b, rr)
	if !strings.Contains(b.String(), "time bound") {
		t.Errorf("a time-bounded text report should note it:\n%s", b.String())
	}
	b.Reset()
	_ = writeMarkdown(&b, rr)
	if !strings.Contains(b.String(), "time bound") {
		t.Errorf("a time-bounded markdown report should note it:\n%s", b.String())
	}
}

func TestWriteJUnitEmpty(t *testing.T) {
	rr := &RunResult{Started: time.Now().Add(-time.Second), Finished: time.Now(), Rounds: 1}
	var b bytes.Buffer
	if err := writeJUnit(&b, rr); err != nil {
		t.Fatal(err)
	}
	var suites junitSuites
	if err := xml.Unmarshal(b.Bytes(), &suites); err != nil {
		t.Fatalf("empty junit is not valid XML: %v", err)
	}
	if len(suites.Suites) != 1 || suites.Suites[0].Tests != 0 || len(suites.Suites[0].Cases) != 0 {
		t.Errorf("empty run should yield a 0-test suite: %+v", suites)
	}
}

// --- exchange / probe edge cases --------------------------------------------

func TestExchangeServerFirstNilSend(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		_, _ = server.Write([]byte("BANNER"))
		_ = server.Close()
	}()
	got, err := exchange(client, nil, time.Second) // nil send = server-speaks-first
	_ = client.Close()
	if err != nil || string(got) != "BANNER" {
		t.Errorf("server-first exchange = %q, %v; want BANNER", got, err)
	}
}

func TestExchangeWriteToClosedPeer(t *testing.T) {
	client, server := net.Pipe()
	_ = server.Close() // peer gone before we start
	start := time.Now()
	got, _ := exchange(client, []byte("hi"), time.Second)
	_ = client.Close()
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("exchange hung for %s against a closed peer", d)
	}
	if len(got) != 0 {
		t.Errorf("a closed peer should yield no data, got %q", got)
	}
}

func TestProbeTimedDialError(t *testing.T) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Timeout: Duration(200 * time.Millisecond),
		Endpoints: []Endpoint{{Label: "x", Proto: "tcp", Port: 1, Handler: "ssh"}}}
	cfg.ApplyDefaults()
	tg, _ := NewTarget(cfg)
	if _, err := probeTimed(context.Background(), tg, Endpoint{Proto: "tcp", Port: 1}, []byte("hi"), 200*time.Millisecond); err == nil {
		t.Error("probing a closed port should return a dial error")
	}
}

// --- scan / sweep / reliability integration ---------------------------------

func TestReliabilitySoakPasses(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true,
		Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}}}
	cfg.ApplyDefaults()
	r, _ := NewRunner(cfg, nil)
	cases := Select(Build(cfg), []string{"reliability/soak/ssh"}, nil)
	res := r.runCase(context.Background(), cases[0], 1, time.Time{})
	if res.Status != StatusPass {
		t.Errorf("soak against a healthy target = %s (%s); want pass", res.Status, res.Detail)
	}
}

func TestScanCompletesWithoutAPI(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true,
		Endpoints:  []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}},
		Categories: []string{"scan"}, ScanPorts: []int{port, 1}}
	cfg.ApplyDefaults()
	rr, err := mustRunnerRun(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	byID := resultsByID(rr)
	if s := byID["scan/portscan-seq"].Status; s != StatusPass {
		t.Errorf("portscan without an API should report completed (pass); got %s", s)
	}
	if s := byID["scan/host-sweep"].Status; s != StatusSkip {
		t.Errorf("host-sweep without sweep_cidr should skip; got %s", s)
	}
}

func TestScanDetectionPass(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	url := eventsAPI(t, apiEvent{RuleID: "correlate:port_scan"})
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true,
		Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}},
		Cases:     []string{"scan/portscan-seq"}, ScanPorts: []int{port, 1}, Verify: VerifyCfg{URL: url}}
	cfg.ApplyDefaults()
	rr, err := mustRunnerRun(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s := resultsByID(rr)["scan/portscan-seq"].Status; s != StatusPass {
		t.Errorf("portscan should pass when the API reports correlate:port_scan; got %s", s)
	}
}

func TestSweepsSkipWithoutCIDR(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true,
		Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}},
		Cases:     []string{"scan/host-sweep", "scan/ping-sweep", "scan/arp-sweep"}}
	cfg.ApplyDefaults()
	rr, err := mustRunnerRun(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	byID := resultsByID(rr)
	for _, id := range []string{"scan/host-sweep", "scan/ping-sweep", "scan/arp-sweep"} {
		if byID[id].Status != StatusSkip {
			t.Errorf("%s without sweep_cidr should skip; got %s (%s)", id, byID[id].Status, byID[id].Detail)
		}
	}
}

func TestRunMultiEndpointModule(t *testing.T) {
	cfg := &Config{Mode: "module", Quiet: true, FuzzIterations: 6, Timeout: Duration(300 * time.Millisecond),
		Endpoints: []Endpoint{
			{Label: "http", Proto: "tcp", Handler: "http"},
			{Label: "ssh", Proto: "tcp", Handler: "ssh"},
			{Label: "ftp", Proto: "tcp", Handler: "ftp"},
		},
		Categories: []string{"unit", "emulate", "fuzz-dumb"}}
	cfg.ApplyDefaults()
	rr, err := mustRunnerRun(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(rr.Results) == 0 {
		t.Fatal("no cases ran")
	}
	for _, res := range rr.Results {
		if res.Status == StatusCrash || res.Status == StatusError {
			t.Errorf("%s = %s (%s); real handlers should not crash/error", res.CaseID, res.Status, res.Detail)
		}
	}
}

// --- reporting integration --------------------------------------------------

func TestWriteReportsMultiFormat(t *testing.T) {
	dir := t.TempDir()
	rr := &RunResult{Started: time.Now().Add(-time.Second), Finished: time.Now(), Seed: 1, ToolVersion: "v", Target: "t", Rounds: 1,
		Results: []Result{
			{CaseID: "unit/x", Category: CatUnit, Round: 1, Attempt: 1, Status: StatusPass},
			{CaseID: "fuzz-dumb/y", Category: CatFuzzDumb, Round: 1, Attempt: 1, Status: StatusFail, Detail: "boom"},
		}}
	reps := []ReportCfg{
		{Format: "text", Path: filepath.Join(dir, "r.txt")},
		{Format: "json", Path: filepath.Join(dir, "r.json")},
		{Format: "junit", Path: filepath.Join(dir, "r.xml")},
		{Format: "md", Path: filepath.Join(dir, "r.md")},
	}
	if err := WriteReports(rr, reps); err != nil {
		t.Fatalf("WriteReports: %v", err)
	}
	for _, rep := range reps {
		fi, err := os.Stat(rep.Path)
		if err != nil || fi.Size() == 0 {
			t.Errorf("%s report missing/empty: %v", rep.Format, err)
		}
	}
}

func TestRunRoundsTagged(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true, Rounds: 3,
		Endpoints:  []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}},
		Categories: []string{"unit"}}
	cfg.ApplyDefaults()
	cfg.Rounds = 3
	r, _ := NewRunner(cfg, nil)
	rr, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rounds := map[int]int{}
	for _, res := range rr.Results {
		if res.CaseID == "unit/port-open/ssh" {
			rounds[res.Round]++
		}
	}
	if rounds[1] != 1 || rounds[2] != 1 || rounds[3] != 1 {
		t.Errorf("each round should run the case once; got %v", rounds)
	}
}

// --- managed lifecycle stress -----------------------------------------------

func TestManagedRestartLoop(t *testing.T) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true,
		Spawn: SpawnCfg{Binary: sleeperScript(t, "5"), ReadyTimeout: Duration(2 * time.Second)}}
	cfg.ApplyDefaults()
	tg, _ := NewTarget(cfg)
	defer tg.Stop()
	if err := tg.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := tg.Restart(context.Background()); err != nil {
			t.Fatalf("Restart #%d: %v", i, err)
		}
		if !tg.Alive(context.Background()) {
			t.Fatalf("not Alive after Restart #%d", i)
		}
	}
}
