package testharness

// A second batch of harness unit tests, broadening coverage of the config /
// duration helpers, case build+selection, the runner lifecycle (rounds, time
// bound, panic recovery, retries), the target backends, reporting (text /
// markdown / json / junit), the results DB, and the detection API client.

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func mustRunner(t *testing.T, cfg *Config) *Runner {
	t.Helper()
	cfg.ApplyDefaults()
	r, err := NewRunner(cfg, nil)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return r
}

func TestDurationStringAndMarshal(t *testing.T) {
	d := Duration(90 * time.Minute)
	if d.String() != "1h30m0s" {
		t.Errorf("String() = %q; want 1h30m0s", d.String())
	}
	out, err := d.MarshalYAML()
	if err != nil || out.(string) != "1h30m0s" {
		t.Errorf("MarshalYAML = %v, %v", out, err)
	}
	b, _ := yaml.Marshal(d)
	var d2 Duration
	if err := yaml.Unmarshal(b, &d2); err != nil || d2.D() != d.D() {
		t.Errorf("yaml round-trip: %s != %s (%v)", d2, d, err)
	}
}

func TestAllCategories(t *testing.T) {
	cats := AllCategories()
	if len(cats) != 11 {
		t.Errorf("AllCategories len = %d; want 11", len(cats))
	}
	seen := map[Category]bool{}
	for _, c := range cats {
		if seen[c] {
			t.Errorf("duplicate category %s", c)
		}
		seen[c] = true
	}
	for _, want := range []Category{CatUnit, CatEmulate, CatMisimpl, CatFuzzDumb, CatFuzzSmart, CatScan, CatFingerprint, CatReliability, CatResilience, CatContainment, CatIntegrity} {
		if !seen[want] {
			t.Errorf("missing category %s", want)
		}
	}
	if cats[0] != CatUnit {
		t.Errorf("first category = %s; want unit", cats[0])
	}
}

func TestSelectEmptyAndAll(t *testing.T) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: 22, Handler: "ssh"}}}
	cfg.ApplyDefaults()
	all := Build(cfg)
	if got := Select(all, nil, nil); len(got) != len(all) {
		t.Errorf("empty selectors should return all: %d != %d", len(got), len(all))
	}
	if got := Select(nil, []string{"unit"}, nil); len(got) != 0 {
		t.Errorf("empty case set should select nothing, got %d", len(got))
	}
	if got := Select(all, []string{"nonexistent/xyz"}, nil); len(got) != 0 {
		t.Errorf("non-matching selector should select nothing, got %d", len(got))
	}
}

func TestBuildModuleHasNoScan(t *testing.T) {
	mod := &Config{Mode: "module", Endpoints: []Endpoint{{Label: "http", Proto: "tcp", Handler: "http"}}}
	mod.ApplyDefaults()
	for _, c := range Build(mod) {
		if c.Category == CatScan || c.Category == CatFingerprint {
			t.Errorf("module mode should not generate %s (%s)", c.Category, c.ID)
		}
	}
	netw := &Config{Mode: "network", Host: "127.0.0.1", Endpoints: []Endpoint{{Label: "http", Proto: "tcp", Port: 80, Handler: "http"}}}
	netw.ApplyDefaults()
	var hasScan bool
	for _, c := range Build(netw) {
		if c.Category == CatScan {
			hasScan = true
		}
	}
	if !hasScan {
		t.Error("network mode should generate scan cases")
	}
}

func TestRunNow(t *testing.T) {
	fixed := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	r := &Run{now: func() time.Time { return fixed }}
	if !r.Now().Equal(fixed) {
		t.Errorf("Run.Now override not used: %s", r.Now())
	}
	if (&Run{}).Now().IsZero() {
		t.Error("Run.Now default should be time.Now (non-zero)")
	}
}

func TestToReport(t *testing.T) {
	start := time.Now().Add(-2 * time.Second)
	rr := &RunResult{
		Started: start, Finished: start.Add(2 * time.Second), Seed: 7, Rounds: 3,
		ToolVersion: "v", Target: "tgt",
		Results: []Result{{Status: StatusPass}, {Status: StatusFail}, {Status: StatusSkip}},
	}
	rep := toReport(rr)
	if rep.Total != 3 || rep.Seed != 7 || rep.Rounds != 3 {
		t.Errorf("toReport scalars wrong: %+v", rep)
	}
	if rep.Counts["pass"] != 1 || rep.Counts["fail"] != 1 || rep.Counts["skip"] != 1 {
		t.Errorf("toReport counts wrong: %v", rep.Counts)
	}
	if rep.DurationMs < 1900 || rep.DurationMs > 2200 {
		t.Errorf("toReport durationMs = %d; want ~2000", rep.DurationMs)
	}
}

func TestWriteTextReport(t *testing.T) {
	clean := &RunResult{Started: time.Now().Add(-time.Second), Finished: time.Now(), Rounds: 1,
		Results: []Result{{CaseID: "unit/x", Category: CatUnit, Status: StatusPass}}}
	var b bytes.Buffer
	if err := writeText(&b, clean); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No findings") {
		t.Errorf("clean text report should say No findings:\n%s", b.String())
	}
	bad := &RunResult{Started: time.Now().Add(-time.Second), Finished: time.Now(), Rounds: 1,
		Results: []Result{{CaseID: "fuzz-dumb/x", Category: CatFuzzDumb, Status: StatusFail, Detail: "boom"}}}
	b.Reset()
	_ = writeText(&b, bad)
	out := b.String()
	if !strings.Contains(out, "FINDINGS") || !strings.Contains(out, "fuzz-dumb/x") || !strings.Contains(out, "boom") {
		t.Errorf("findings text report missing content:\n%s", out)
	}
}

func TestWriteMarkdownReport(t *testing.T) {
	clean := &RunResult{Started: time.Now().Add(-time.Second), Finished: time.Now(), Rounds: 1,
		Results: []Result{{CaseID: "unit/x", Category: CatUnit, Status: StatusPass}}}
	var b bytes.Buffer
	_ = writeMarkdown(&b, clean)
	if !strings.Contains(b.String(), "None.") {
		t.Errorf("clean markdown should say None.:\n%s", b.String())
	}
	bad := &RunResult{Started: time.Now().Add(-time.Second), Finished: time.Now(), Rounds: 1,
		Results: []Result{{CaseID: "scan/x", Category: CatScan, Status: StatusCrash, Detail: "died"}}}
	b.Reset()
	_ = writeMarkdown(&b, bad)
	if !strings.Contains(b.String(), "scan/x") || !strings.Contains(b.String(), "died") {
		t.Errorf("findings markdown missing content:\n%s", b.String())
	}
}

func TestDBMultiRunRecent(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mk := func(seed int64, crashes int) *RunResult {
		res := []Result{{CaseID: "a", Category: CatUnit, Round: 1, Attempt: 1, Status: StatusPass}}
		for i := 0; i < crashes; i++ {
			res = append(res, Result{CaseID: "c", Category: CatScan, Round: 1, Attempt: 1, Status: StatusCrash})
		}
		return &RunResult{Started: time.Now(), Finished: time.Now(), Seed: seed, ToolVersion: "v", Target: "t", Rounds: 1, Results: res}
	}
	id1, _ := db.Record(mk(1, 0))
	id2, _ := db.Record(mk(2, 2))
	if id2 <= id1 {
		t.Errorf("second run id should increase: %d <= %d", id2, id1)
	}
	rows, err := db.Recent(10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("recent: %d rows err=%v", len(rows), err)
	}
	if rows[0].ID != id2 {
		t.Errorf("Recent should be newest-first; rows[0].ID = %d", rows[0].ID)
	}
	if rows[0].Crash != 2 {
		t.Errorf("crash count not persisted: %d", rows[0].Crash)
	}
	if r1, _ := db.Recent(1); len(r1) != 1 {
		t.Errorf("Recent(1) returned %d rows", len(r1))
	}
}

func TestAPIClientEventsErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := NewAPIClient(srv.URL, "")
	if _, err := c.Events(context.Background(), "10m", 10); err == nil {
		t.Error("Events should error on a 500 response")
	}
	if det, checked := c.Detected(context.Background(), MatchRulePrefix("x")); det || checked {
		t.Errorf("Detected on 500: det=%v checked=%v; want false false", det, checked)
	}
}

func TestMatchToolVariants(t *testing.T) {
	if !MatchTool("nmap")(apiEvent{Meta: map[string]any{"tools": []any{"Nmap Scripting Engine"}}}) {
		t.Error("MatchTool should match a substring case-insensitively in []any tools")
	}
	if !MatchTool("SQLMAP")(apiEvent{Meta: map[string]any{"tools": []string{"sqlmap/1.7"}}}) {
		t.Error("MatchTool should be case-insensitive over []string tools")
	}
	if !MatchTool("nessus")(apiEvent{Anomalies: []string{"vulnerability-scanner"}}) {
		t.Error("vulnerability-scanner should count as a tool hit")
	}
	if !MatchTool("masscan")(apiEvent{Anomalies: []string{"tool:masscan"}}) {
		t.Error("a tool: anomaly should count as a tool hit")
	}
	if MatchTool("nmap")(apiEvent{Anomalies: []string{"ssh-id-not-ssh"}}) {
		t.Error("unrelated anomaly should not match")
	}
}

func TestHostsInCIDRVariants(t *testing.T) {
	v4 := hostsInCIDR("10.0.0.0/30", 256) // .0 net, .1, .2, .3 broadcast
	if len(v4) != 2 || v4[0] != "10.0.0.1" {
		t.Errorf("/30 hosts = %v; want [10.0.0.1 10.0.0.2]", v4)
	}
	if h := hostsInCIDR("10.0.0.0/24", 5); len(h) > 5 {
		t.Errorf("max cap not respected: got %d", len(h))
	}
	v6 := hostsInCIDR("2001:db8::/120", 4)
	if len(v6) != 4 {
		t.Errorf("ipv6 hosts = %v; want 4 (no v4 net/broadcast drop)", v6)
	}
}

func TestFuzzTimeoutCap(t *testing.T) {
	if got := fuzzTimeout(&Config{Timeout: Duration(5 * time.Second)}); got != 600*time.Millisecond {
		t.Errorf("fuzzTimeout cap = %s; want 600ms", got)
	}
	if got := fuzzTimeout(&Config{Timeout: Duration(200 * time.Millisecond)}); got != 200*time.Millisecond {
		t.Errorf("fuzzTimeout passthrough = %s; want 200ms", got)
	}
}

func TestCaseTimeoutMinimum(t *testing.T) {
	if got := mustRunner(t, &Config{FuzzIterations: 1, Timeout: Duration(time.Millisecond)}).caseTimeout(); got < 2*time.Minute {
		t.Errorf("caseTimeout = %s; want >= 2m", got)
	}
	if got := mustRunner(t, &Config{FuzzIterations: 10000, Timeout: Duration(time.Second)}).caseTimeout(); got <= 2*time.Minute {
		t.Errorf("caseTimeout for a big fuzz budget = %s; want > 2m", got)
	}
}

func TestDescribeTarget(t *testing.T) {
	mod := mustRunner(t, &Config{Mode: "module", Endpoints: []Endpoint{{Label: "h", Proto: "tcp", Handler: "http"}}})
	if got := mod.describeTarget(); !strings.Contains(got, "module") {
		t.Errorf("describeTarget module = %q", got)
	}
	managed := mustRunner(t, &Config{Mode: "network", Host: "127.0.0.1", Spawn: SpawnCfg{Binary: "/bin/x"}, Endpoints: []Endpoint{{Label: "h", Proto: "tcp", Port: 22, Handler: "ssh"}}})
	if got := managed.describeTarget(); !strings.Contains(got, "managed") {
		t.Errorf("describeTarget managed = %q", got)
	}
	ext := mustRunner(t, &Config{Mode: "network", Host: "10.1.2.3", Endpoints: []Endpoint{{Label: "h", Proto: "tcp", Port: 22, Handler: "ssh"}}})
	if got := ext.describeTarget(); !strings.Contains(got, "external") || !strings.Contains(got, "10.1.2.3") {
		t.Errorf("describeTarget external = %q", got)
	}
}

func TestTargetEndpointLookup(t *testing.T) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: 22, Handler: "ssh"}}}
	cfg.ApplyDefaults()
	tg, _ := NewTarget(cfg)
	if e, ok := tg.Endpoint("ssh"); !ok || e.Port != 22 {
		t.Errorf("Endpoint(ssh) = %+v, %v", e, ok)
	}
	if _, ok := tg.Endpoint("nope"); ok {
		t.Error("Endpoint(nope) should not be found")
	}
}

func TestTargetManagedAndAlive(t *testing.T) {
	managed := &Config{Mode: "network", Host: "127.0.0.1", Spawn: SpawnCfg{Binary: "/x"}, Endpoints: []Endpoint{{Label: "a", Proto: "tcp", Port: 1, Handler: "ssh"}}}
	managed.ApplyDefaults()
	if tg, _ := NewTarget(managed); !tg.Managed() {
		t.Error("network + spawn.binary should be Managed")
	}
	ext := &Config{Mode: "network", Host: "127.0.0.1", Endpoints: []Endpoint{{Label: "a", Proto: "tcp", Port: 1, Handler: "ssh"}}}
	ext.ApplyDefaults()
	if tg, _ := NewTarget(ext); tg.Managed() {
		t.Error("network without spawn.binary should not be Managed")
	}
	mod := &Config{Mode: "module", Endpoints: []Endpoint{{Label: "a", Proto: "tcp", Handler: "http"}}}
	mod.ApplyDefaults()
	if tg, _ := NewTarget(mod); !tg.Alive(context.Background()) {
		t.Error("module target should always be Alive")
	}
}

func TestTCPConnect(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	if !tcpConnect(context.Background(), "127.0.0.1", port, time.Second) {
		t.Error("tcpConnect to an open port should be true")
	}
	if tcpConnect(context.Background(), "127.0.0.1", 1, 300*time.Millisecond) {
		t.Error("tcpConnect to port 1 should be false")
	}
}

func TestEndpointResponds(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}}}
	cfg.ApplyDefaults()
	tg, _ := NewTarget(cfg)
	ep, _ := tg.Endpoint("ssh")
	if !endpointResponds(context.Background(), tg, ep) {
		t.Error("endpointResponds should be true for an open port")
	}
	if endpointResponds(context.Background(), tg, Endpoint{Proto: "tcp", Port: 1}) {
		t.Error("endpointResponds should be false for a closed port")
	}
}

func TestProbeReadsBanner(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}}}
	cfg.ApplyDefaults()
	tg, _ := NewTarget(cfg)
	ep, _ := tg.Endpoint("ssh")
	resp, err := probe(context.Background(), tg, ep, nil)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if !strings.Contains(string(resp), "SSH-") {
		t.Errorf("probe banner = %q; want it to contain SSH-", resp)
	}
}

func TestDialModuleUnknownHandler(t *testing.T) {
	cfg := &Config{Mode: "module", Endpoints: []Endpoint{{Label: "x", Proto: "tcp", Handler: "nope"}}}
	cfg.ApplyDefaults()
	tg, _ := NewTarget(cfg)
	if _, err := tg.Dial(context.Background(), Endpoint{Proto: "tcp", Handler: "definitely-not-a-handler"}); err == nil {
		t.Error("module Dial with an unknown handler should error")
	}
}

func TestNewRunnerAPIWiring(t *testing.T) {
	with := mustRunner(t, &Config{Mode: "module", Endpoints: []Endpoint{{Label: "h", Proto: "tcp", Handler: "http"}}, Verify: VerifyCfg{URL: "http://x:1"}})
	if with.api == nil {
		t.Error("Verify.URL set should wire an API client")
	}
	without := mustRunner(t, &Config{Mode: "module", Endpoints: []Endpoint{{Label: "h", Proto: "tcp", Handler: "http"}}})
	if without.api != nil {
		t.Error("no Verify.URL should leave api nil")
	}
}

func TestRunnerCasesSelection(t *testing.T) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1",
		Endpoints:  []Endpoint{{Label: "ssh", Proto: "tcp", Port: 22, Handler: "ssh"}},
		Categories: []string{"unit"}}
	r := mustRunner(t, cfg)
	cs := r.Cases()
	if len(cs) == 0 {
		t.Fatal("Cases() returned nothing")
	}
	for _, c := range cs {
		if c.Category != CatUnit {
			t.Errorf("Cases() leaked %s (%s)", c.Category, c.ID)
		}
	}
}

func TestConfigValidateUDPModule(t *testing.T) {
	bad := &Config{Mode: "module", Endpoints: []Endpoint{{Label: "a", Proto: "udp", Handler: "dns"}}}
	bad.ApplyDefaults()
	if err := bad.Validate(); err == nil {
		t.Error("a udp endpoint in module mode should be invalid")
	}
	ok := &Config{Mode: "network", Host: "127.0.0.1", Endpoints: []Endpoint{{Label: "a", Proto: "udp", Port: 53, Handler: "dns"}}}
	ok.ApplyDefaults()
	if err := ok.Validate(); err != nil {
		t.Errorf("a udp endpoint in network mode should be valid: %v", err)
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	rr := &RunResult{Started: time.Now().Add(-time.Second), Finished: time.Now(), Seed: 99, ToolVersion: "v1", Target: "t", Rounds: 2,
		Results: []Result{
			{CaseID: "unit/x", Category: CatUnit, Round: 1, Attempt: 1, Status: StatusPass},
			{CaseID: "fuzz-dumb/y", Category: CatFuzzDumb, Round: 1, Attempt: 1, Status: StatusFail, Detail: "boom"},
		}}
	p := filepath.Join(t.TempDir(), "r.json")
	if err := WriteReports(rr, []ReportCfg{{Format: "json", Path: p}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	var rep Report
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if rep.Seed != 99 || rep.Rounds != 2 || rep.Total != 2 || rep.ToolVersion != "v1" {
		t.Errorf("json report scalars wrong: %+v", rep)
	}
	if rep.Counts["pass"] != 1 || rep.Counts["fail"] != 1 {
		t.Errorf("json counts wrong: %v", rep.Counts)
	}
	if len(rep.Results) != 2 {
		t.Errorf("json results len = %d; want 2", len(rep.Results))
	}
}

func TestJUnitClassnameIsCategory(t *testing.T) {
	rr := &RunResult{Started: time.Now().Add(-time.Second), Finished: time.Now(), Rounds: 1,
		Results: []Result{{CaseID: "unit/port-open/ssh", Category: CatUnit, Round: 1, Attempt: 1, Status: StatusPass, Duration: 3 * time.Millisecond}}}
	var b bytes.Buffer
	if err := writeJUnit(&b, rr); err != nil {
		t.Fatal(err)
	}
	var suites junitSuites
	if err := xml.Unmarshal(b.Bytes(), &suites); err != nil {
		t.Fatalf("parse junit: %v", err)
	}
	c := suites.Suites[0].Cases[0]
	if c.Classname != "unit" {
		t.Errorf("junit classname = %q; want unit (the category)", c.Classname)
	}
	if c.Name != "unit/port-open/ssh" {
		t.Errorf("junit case name = %q", c.Name)
	}
}

func TestRunRounds(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	cfg := &Config{Mode: "network", Host: "127.0.0.1",
		Endpoints:  []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}},
		Categories: []string{"unit"}, Rounds: 2, Quiet: true}
	r := mustRunner(t, cfg)
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
	if rounds[1] != 1 || rounds[2] != 1 {
		t.Errorf("expected the case once per round; got %v", rounds)
	}
}

func TestRunNoCasesError(t *testing.T) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1",
		Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: 22, Handler: "ssh"}},
		Cases:     []string{"does-not-match-anything/zzz"}, Quiet: true}
	r := mustRunner(t, cfg)
	if _, err := r.Run(context.Background()); err == nil {
		t.Error("Run with no selected cases should error")
	}
}

func TestRunCaseTimeBoundSkip(t *testing.T) {
	r := mustRunner(t, &Config{Mode: "module", Endpoints: []Endpoint{{Label: "h", Proto: "tcp", Handler: "http"}}, Quiet: true})
	ran := false
	c := Case{ID: "x/tb", Category: CatUnit, Fn: func(ctx context.Context, run *Run) (Status, string, error) {
		ran = true
		return StatusPass, "", nil
	}}
	res := r.runCase(context.Background(), c, 1, time.Now().Add(-time.Hour))
	if res.Status != StatusSkip {
		t.Errorf("a past deadline should skip; got %s", res.Status)
	}
	if ran {
		t.Error("the case Fn must not run past the deadline")
	}
}

func TestSafeRunRecoversPanic(t *testing.T) {
	c := Case{ID: "x/panic", Fn: func(ctx context.Context, r *Run) (Status, string, error) {
		panic("boom")
	}}
	st, _, err := safeRun(context.Background(), c, &Run{})
	if st != StatusError || err == nil {
		t.Errorf("a panicking case should become StatusError; got %s, %v", st, err)
	}
	if err != nil && !strings.Contains(err.Error(), "panic") {
		t.Errorf("error should mention the panic: %v", err)
	}
}
