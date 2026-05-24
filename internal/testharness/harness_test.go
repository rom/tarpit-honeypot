package testharness

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestEventAnomaliesMergesFieldAndMeta(t *testing.T) {
	cases := []struct {
		name string
		e    apiEvent
		want []string
	}{
		{"field only", apiEvent{Anomalies: []string{"a"}}, []string{"a"}},
		{"meta []string", apiEvent{Meta: map[string]any{"anomalies": []string{"b"}}}, []string{"b"}},
		{"meta []any (json)", apiEvent{Meta: map[string]any{"anomalies": []any{"c", "d"}}}, []string{"c", "d"}},
		{"both", apiEvent{Anomalies: []string{"a"}, Meta: map[string]any{"anomalies": []any{"b"}}}, []string{"a", "b"}},
		{"none", apiEvent{}, nil},
	}
	for _, tc := range cases {
		got := eventAnomalies(tc.e)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: eventAnomalies = %v; want %v", tc.name, got, tc.want)
		}
	}
}

func TestMatchers(t *testing.T) {
	// Anomaly carried under meta (as the stored API returns it).
	metaEv := apiEvent{RuleID: "listener:ssh", Meta: map[string]any{"anomalies": []any{"ssh-id-not-ssh"}}}
	if !MatchAnomaly("ssh-id-not-ssh")(metaEv) {
		t.Error("MatchAnomaly should match a marker carried under meta.anomalies")
	}
	if MatchAnomaly("nope")(metaEv) {
		t.Error("MatchAnomaly matched a marker that is not present")
	}
	if !MatchRulePrefix("listener:")(metaEv) || MatchRulePrefix("scan:")(metaEv) {
		t.Error("MatchRulePrefix prefix logic wrong")
	}
	// Tool attribution via meta.tools ([]any from JSON, and []string).
	if !MatchTool("sqlmap")(apiEvent{Meta: map[string]any{"tools": []any{"sqlmap"}}}) {
		t.Error("MatchTool should match meta.tools ([]any)")
	}
	if !MatchTool("nmap")(apiEvent{Meta: map[string]any{"tools": []string{"nmap"}}}) {
		t.Error("MatchTool should match meta.tools ([]string)")
	}
	// Tool attribution via anomaly markers.
	if !MatchTool("nmap")(apiEvent{Anomalies: []string{"tool:nmap"}}) {
		t.Error("MatchTool should match a tool: anomaly")
	}
	if !MatchTool("nessus")(apiEvent{Meta: map[string]any{"anomalies": []any{"vulnerability-scanner"}}}) {
		t.Error("MatchTool should treat a vulnerability-scanner marker as a tool hit")
	}
	if MatchTool("nmap")(apiEvent{Anomalies: []string{"ssh-id-not-ssh"}}) {
		t.Error("MatchTool matched an unrelated anomaly")
	}
}

func TestScanPortsDefaultAndConfigured(t *testing.T) {
	// Explicit list wins verbatim.
	cfg := &Config{ScanPorts: []int{1, 2, 3}}
	if got := scanPorts(cfg); len(got) != 3 || got[0] != 1 {
		t.Errorf("explicit scan_ports = %v; want [1 2 3]", got)
	}
	// Derived: endpoint ports first, then the common set, deduped.
	cfg = &Config{Endpoints: []Endpoint{{Port: 2222}, {Port: 22}, {Port: 2222}}}
	got := scanPorts(cfg)
	seen := map[int]int{}
	for _, p := range got {
		seen[p]++
	}
	if got[0] != 2222 {
		t.Errorf("derived ports should start with endpoint ports; got %v", got)
	}
	for _, want := range []int{2222, 22, 80, 443} {
		if seen[want] == 0 {
			t.Errorf("derived ports missing %d: %v", want, got)
		}
	}
	for p, n := range seen {
		if n != 1 {
			t.Errorf("derived ports has duplicate %d (x%d)", p, n)
		}
	}
}

func TestHostsInCIDR(t *testing.T) {
	if hostsInCIDR("", 256) != nil || hostsInCIDR("not-a-cidr", 256) != nil {
		t.Error("empty/invalid CIDR should yield no hosts")
	}
	got := hostsInCIDR("10.9.0.0/30", 256) // .0 net, .1, .2, .3 broadcast
	if len(got) != 2 || got[0] != "10.9.0.1" || got[1] != "10.9.0.2" {
		t.Errorf("/30 usable hosts = %v; want [10.9.0.1 10.9.0.2]", got)
	}
	if h := hostsInCIDR("10.0.0.0/24", 5); len(h) > 5 {
		t.Errorf("max not respected: got %d hosts", len(h))
	}
}

func TestFuzzDeterminism(t *testing.T) {
	a := randBytes(caseRand(99, "fuzz-dumb/ssh"))
	b := randBytes(caseRand(99, "fuzz-dumb/ssh"))
	if !bytes.Equal(a, b) {
		t.Error("same seed + case id must reproduce identical fuzz input")
	}
	c := randBytes(caseRand(99, "fuzz-dumb/http"))
	if bytes.Equal(a, c) {
		t.Error("different case ids should diverge")
	}
	d := randBytes(caseRand(100, "fuzz-dumb/ssh"))
	if bytes.Equal(a, d) {
		t.Error("different seeds should diverge")
	}
}

func TestCaseRetriesOverride(t *testing.T) {
	cfg := &Config{Retries: 1, RetriesByCase: map[string]int{"fuzz-smart/http": 5}}
	if cfg.CaseRetries("fuzz-smart/http") != 5 {
		t.Error("per-case retry override not applied")
	}
	if cfg.CaseRetries("unit/port-open/ssh") != 1 {
		t.Error("global retry fallback wrong")
	}
}

func TestProtocolSpecsWellFormed(t *testing.T) {
	for name, sp := range specs {
		if !sp.ServerFirst && sp.Probe == nil {
			t.Errorf("spec %q: client-first protocol needs a Probe to elicit a response", name)
		}
		if sp.EmulateOK == nil {
			t.Errorf("spec %q: missing EmulateOK", name)
		}
		for _, s := range sp.Smart {
			if s.Name == "" || len(s.Bytes) == 0 {
				t.Errorf("spec %q: smart shape %q has empty name/bytes", name, s.Name)
			}
		}
		for _, m := range sp.Misimpl {
			if m.Name == "" || len(m.Bytes) == 0 {
				t.Errorf("spec %q: misimpl case %q has empty name/bytes", name, m.Name)
			}
		}
	}
}

func TestDurationUnmarshal(t *testing.T) {
	ok := map[string]time.Duration{
		"0":     0,                       // bare zero (the natural value that plain time.Duration rejects)
		"30":    30 * time.Second,        // bare int => seconds
		"1.5":   1500 * time.Millisecond, // bare float => seconds
		"0s":    0,
		"30m":   30 * time.Minute,
		"500ms": 500 * time.Millisecond,
		"2h45m": 2*time.Hour + 45*time.Minute,
		`"3s"`:  3 * time.Second, // quoted string
		"null":  0,
		`""`:    0,
	}
	for in, want := range ok {
		var d Duration
		if err := yaml.Unmarshal([]byte(in), &d); err != nil {
			t.Errorf("Unmarshal(%q) error: %v", in, err)
			continue
		}
		if d.D() != want {
			t.Errorf("Unmarshal(%q) = %s; want %s", in, d.D(), want)
		}
	}
	for _, in := range []string{"bogus", "30x", "[]"} {
		var d Duration
		if err := yaml.Unmarshal([]byte(in), &d); err == nil {
			t.Errorf("Unmarshal(%q) = %s; want an error", in, d.D())
		}
	}
}

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
	cfg := &Config{Mode: "module", Retries: 2, Timeout: Duration(time.Second)}
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
