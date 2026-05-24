package testharness

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	bad := []*Config{
		{Mode: "bogus"},
		{Mode: "network", Endpoints: []Endpoint{{Label: "", Proto: "tcp", Port: 22}}},
		{Mode: "network", Endpoints: []Endpoint{{Label: "a", Proto: "tcp", Port: 22}, {Label: "a", Proto: "tcp", Port: 23}}},
		{Mode: "network", Endpoints: []Endpoint{{Label: "a", Proto: "tcp"}}}, // no port
		{Mode: "module", Endpoints: []Endpoint{{Label: "a", Proto: "tcp"}}},  // no handler
	}
	for i, c := range bad {
		c.ApplyDefaults()
		if err := c.Validate(); err == nil {
			t.Errorf("config[%d] should be invalid", i)
		}
	}
	ok := &Config{Mode: "network", Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: 22, Handler: "ssh"}}}
	ok.ApplyDefaults()
	if err := ok.Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestBuildAndSelect(t *testing.T) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: 22, Handler: "ssh"}}}
	cfg.ApplyDefaults()
	cases := Build(cfg)
	want := map[string]bool{"unit/port-open/ssh": false, "unit/banner/ssh": false, "emulate/ssh": false, "fuzz-dumb/ssh": false, "fuzz-smart/ssh": false, "scan/portscan-seq": false}
	for _, c := range cases {
		if _, ok := want[c.ID]; ok {
			want[c.ID] = true
		}
		if c.ID == "" {
			t.Error("case with empty id")
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected case %q to be generated", id)
		}
	}
	// Selection by glob + category.
	if got := Select(cases, []string{"fuzz-*"}, nil); len(got) == 0 {
		t.Error("glob fuzz-* selected nothing")
	}
	onlyUnit := Select(cases, nil, []string{"unit"})
	for _, c := range onlyUnit {
		if c.Category != CatUnit {
			t.Errorf("category filter leaked %s", c.Category)
		}
	}
}

// fakeHoneypot is a minimal TCP server that greets like SSH and tolerates junk
// — a stand-in target so the runner can be exercised in-process.
func fakeHoneypot(t *testing.T) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("SSH-2.0-fakehoneypot\r\n"))
				_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { close(done); _ = ln.Close() }
}

func TestRunnerAgainstFakeTarget(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	cfg := &Config{
		Mode: "network", Host: "127.0.0.1",
		Endpoints:      []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}},
		Categories:     []string{"unit", "emulate", "fuzz-dumb"},
		FuzzIterations: 12,
		Quiet:          true,
	}
	cfg.ApplyDefaults()
	r, err := NewRunner(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	rr, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Result{}
	for _, res := range rr.Results {
		byID[res.CaseID] = res
	}
	for _, id := range []string{"unit/port-open/ssh", "unit/banner/ssh", "emulate/ssh", "fuzz-dumb/ssh"} {
		if byID[id].Status != StatusPass {
			t.Errorf("%s = %s (%s); want pass", id, byID[id].Status, byID[id].Detail)
		}
	}
	if !rr.OK() {
		t.Errorf("expected no findings against a healthy fake; got %d", len(rr.Findings()))
	}
}

func TestRunnerClosedPortFails(t *testing.T) {
	cfg := &Config{
		Mode: "network", Host: "127.0.0.1",
		Endpoints:  []Endpoint{{Label: "dead", Proto: "tcp", Port: 1, Handler: "ssh"}},
		Categories: []string{"unit"},
		Quiet:      true,
	}
	cfg.ApplyDefaults()
	r, _ := NewRunner(cfg, nil)
	rr, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var sawFail bool
	for _, res := range rr.Results {
		if res.CaseID == "unit/port-open/dead" && res.Status.Bad() {
			sawFail = true
		}
	}
	if !sawFail {
		t.Error("a closed port should produce a finding")
	}
}

func TestModuleBackend(t *testing.T) {
	cfg := &Config{
		Mode:       "module",
		Endpoints:  []Endpoint{{Label: "http", Proto: "tcp", Handler: "http"}},
		Categories: []string{"unit", "emulate"},
		Quiet:      true,
	}
	cfg.ApplyDefaults()
	r, err := NewRunner(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	rr, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range rr.Results {
		if res.CaseID == "emulate/http" && res.Status != StatusPass {
			t.Errorf("module-mode http emulation = %s (%s); want pass", res.Status, res.Detail)
		}
	}
}

func TestRunCaseRetries(t *testing.T) {
	cfg := &Config{Mode: "module", Retries: 2, Timeout: time.Second}
	cfg.ApplyDefaults()
	cfg.Retries = 2
	r, _ := NewRunner(cfg, nil)
	calls := 0
	c := Case{ID: "x/retry", Category: CatReliability, Fn: func(ctx context.Context, run *Run) (Status, string, error) {
		calls++
		if calls < 3 {
			return StatusFail, "not yet", nil
		}
		return StatusPass, "ok", nil
	}}
	res := r.runCase(context.Background(), c, 1, time.Time{})
	if res.Status != StatusPass {
		t.Errorf("status = %s; want pass after retries", res.Status)
	}
	if res.Attempt != 3 || calls != 3 {
		t.Errorf("attempts = %d / calls = %d; want 3", res.Attempt, calls)
	}
}

func TestReportAndDB(t *testing.T) {
	rr := &RunResult{
		Started: time.Now().Add(-time.Second), Finished: time.Now(), Seed: 42,
		ToolVersion: "test", Target: "fake", Rounds: 1,
		Results: []Result{
			{CaseID: "unit/port-open/ssh", Category: CatUnit, Round: 1, Attempt: 1, Status: StatusPass, Duration: time.Millisecond},
			{CaseID: "fuzz-dumb/ssh", Category: CatFuzzDumb, Round: 1, Attempt: 2, Status: StatusFail, Detail: "boom", Duration: 2 * time.Millisecond},
		},
	}
	dir := t.TempDir()
	for _, f := range []string{"text", "json", "junit", "md"} {
		p := filepath.Join(dir, "report."+f)
		if err := WriteReports(rr, []ReportCfg{{Format: f, Path: p}}); err != nil {
			t.Fatalf("%s report: %v", f, err)
		}
		b, _ := os.ReadFile(p)
		if len(b) == 0 {
			t.Errorf("%s report empty", f)
		}
		if f == "junit" && !strings.Contains(string(b), "<testsuite") {
			t.Errorf("junit report malformed: %s", b)
		}
	}
	db, err := OpenDB(filepath.Join(dir, "results.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id, err := db.Record(rr)
	if err != nil || id == 0 {
		t.Fatalf("record: id=%d err=%v", id, err)
	}
	rows, err := db.Recent(5)
	if err != nil || len(rows) != 1 {
		t.Fatalf("recent: %d rows, err=%v", len(rows), err)
	}
	if rows[0].Fail != 1 || rows[0].Pass != 1 || rows[0].Total != 2 {
		t.Errorf("recorded counts wrong: %+v", rows[0])
	}
}

func TestEndpointParsingRoundTrip(t *testing.T) {
	// Guard the network dial path builds a sane address (no panic on missing ep).
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Endpoints: []Endpoint{{Label: "a", Proto: "tcp", Port: 65000, Handler: "ssh"}}}
	cfg.ApplyDefaults()
	tg, _ := NewTarget(cfg)
	if _, err := tg.Dial(context.Background(), Endpoint{Proto: "tcp", Port: 1}); err == nil {
		t.Error("dial to a closed port should error")
	} else if !errors.Is(err, err) {
		_ = err
	}
}
