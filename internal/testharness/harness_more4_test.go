package testharness

// A fourth batch, deepening four areas again:
//   - low-level: IP iteration carry, the tool/anomaly matchers over mixed JSON,
//     case Fn error + non-string panic handling;
//   - integrated detection-verify flow: misimpl + fingerprint cases driven
//     against a fake events API (pass / fail / skip-when-unreachable);
//   - integrated runner behaviour: progress vs quiet vs findings-only output,
//     context cancellation, concurrency >> case count, DB ordering;
//   - the managed-target lifecycle (spawn → alive → exited → restart → stop)
//     against a real child process.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// eventsAPI stands up a fake read-only events API serving the given events.
func eventsAPI(t *testing.T, evs ...apiEvent) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(evs)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// sleeperScript writes an executable shell script that ignores its args and
// sleeps for dur — a stand-in managed "binary" (the harness always invokes it
// as `<binary> run ...`, which the script discards).
func sleeperScript(t *testing.T, dur string) string {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh for the managed-target lifecycle test")
	}
	p := filepath.Join(t.TempDir(), "sleeper.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexec sleep "+dur+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// --- low-level --------------------------------------------------------------

func TestHostsInCIDROctetCarry(t *testing.T) {
	// A /22 spans four /24s; iterating must carry across the .255 boundary.
	hosts := hostsInCIDR("10.0.0.0/22", 600)
	if len(hosts) > 600 {
		t.Fatalf("returned %d hosts; want <= 600", len(hosts))
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		seen[h] = true
	}
	if !seen["10.0.1.0"] || !seen["10.0.0.255"] {
		t.Errorf("iteration did not carry across an octet boundary (missing 10.0.0.255 / 10.0.1.0)")
	}
}

func TestMatchToolMetaToolsMixed(t *testing.T) {
	// meta.tools as []any with a non-string element interleaved.
	ev := apiEvent{Meta: map[string]any{"tools": []any{42, "Nmap Scripting Engine", nil}}}
	if !MatchTool("nmap")(ev) {
		t.Error("MatchTool should find a string tool amid non-string []any elements")
	}
	if MatchTool("masscan")(ev) {
		t.Error("MatchTool matched a tool that isn't present")
	}
}

func TestEventAnomaliesIgnoresNonStrings(t *testing.T) {
	ev := apiEvent{Meta: map[string]any{"anomalies": []any{"ssh-id-not-ssh", 7, true, "tool:nmap"}}}
	got := eventAnomalies(ev)
	if len(got) != 2 || got[0] != "ssh-id-not-ssh" || got[1] != "tool:nmap" {
		t.Errorf("eventAnomalies = %v; want the two string markers only", got)
	}
}

func TestRunCaseReturnsError(t *testing.T) {
	r := mustRunner(t, &Config{Mode: "module", Endpoints: []Endpoint{{Label: "h", Proto: "tcp", Handler: "http"}}, Quiet: true})
	r.cfg.Retries = 0
	c := Case{ID: "x/err", Category: CatUnit, Fn: func(ctx context.Context, run *Run) (Status, string, error) {
		return StatusPass, "", errors.New("boom")
	}}
	res := r.runCase(context.Background(), c, 1, time.Time{})
	if res.Status != StatusError || !strings.Contains(res.Err, "boom") {
		t.Errorf("a Fn error should yield StatusError with the message; got %s / %q", res.Status, res.Err)
	}
}

func TestSafeRunNonStringPanic(t *testing.T) {
	c := Case{ID: "x/panic", Fn: func(ctx context.Context, r *Run) (Status, string, error) {
		panic(errors.New("kaboom"))
	}}
	st, _, err := safeRun(context.Background(), c, &Run{})
	if st != StatusError || err == nil || !strings.Contains(err.Error(), "panic") {
		t.Errorf("a non-string panic should become StatusError mentioning panic; got %s / %v", st, err)
	}
}

// --- detection-verify flow --------------------------------------------------

func TestMisimplDetectionPass(t *testing.T) {
	url := eventsAPI(t, apiEvent{RuleID: "listener:http",
		Anomalies: []string{"http-method-unknown", "http-request-line-non-printable"}})
	cfg := &Config{Mode: "module", Quiet: true, Timeout: Duration(300 * time.Millisecond),
		Endpoints:  []Endpoint{{Label: "http", Proto: "tcp", Handler: "http"}},
		Categories: []string{"misimpl"}, Verify: VerifyCfg{URL: url}}
	cfg.ApplyDefaults()
	rr, err := mustRunnerRun(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	byID := resultsByID(rr)
	for _, id := range []string{"misimpl/http/unknown-method", "misimpl/http/binary-request-line"} {
		if byID[id].Status != StatusPass {
			t.Errorf("%s = %s (%s); want pass (anomaly was recorded)", id, byID[id].Status, byID[id].Detail)
		}
	}
}

func TestMisimplDetectionFail(t *testing.T) {
	url := eventsAPI(t, apiEvent{RuleID: "listener:http", Anomalies: []string{"some-unrelated-marker"}})
	cfg := &Config{Mode: "module", Quiet: true, Timeout: Duration(300 * time.Millisecond),
		Endpoints:  []Endpoint{{Label: "http", Proto: "tcp", Handler: "http"}},
		Categories: []string{"misimpl"}, Verify: VerifyCfg{URL: url}}
	cfg.ApplyDefaults()
	rr, err := mustRunnerRun(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s := resultsByID(rr)["misimpl/http/unknown-method"].Status; s != StatusFail {
		t.Errorf("misimpl with the anomaly absent should fail; got %s", s)
	}
}

func TestMisimplSkipsWhenAPIUnreachable(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := down.URL
	down.Close() // unreachable
	cfg := &Config{Mode: "module", Quiet: true, Timeout: Duration(300 * time.Millisecond),
		Endpoints:  []Endpoint{{Label: "http", Proto: "tcp", Handler: "http"}},
		Categories: []string{"misimpl"}, Verify: VerifyCfg{URL: url}}
	cfg.ApplyDefaults()
	rr, err := mustRunnerRun(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s := resultsByID(rr)["misimpl/http/unknown-method"].Status; s != StatusSkip {
		t.Errorf("misimpl with an unreachable API should skip, not fail; got %s", s)
	}
}

func TestFingerprintDetectionPass(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	url := eventsAPI(t, apiEvent{RuleID: "listener:http", Meta: map[string]any{"tools": []any{"nmap"}}})
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true, Timeout: Duration(300 * time.Millisecond),
		Endpoints:  []Endpoint{{Label: "http", Proto: "tcp", Port: port, Handler: "http"}},
		Categories: []string{"fingerprint"}, Cases: []string{"fingerprint/http-nmap"},
		Verify: VerifyCfg{URL: url}}
	cfg.ApplyDefaults()
	rr, err := mustRunnerRun(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s := resultsByID(rr)["fingerprint/http-nmap"].Status; s != StatusPass {
		t.Errorf("fingerprint/http-nmap should pass when the API attributes nmap; got %s", s)
	}
}

// --- runner behaviour -------------------------------------------------------

func TestRunOutputModes(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	run := func(mut func(*Config)) string {
		cfg := &Config{Mode: "network", Host: "127.0.0.1",
			Endpoints:  []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}},
			Categories: []string{"unit"}}
		mut(cfg)
		cfg.ApplyDefaults()
		var buf bytes.Buffer
		r, _ := NewRunner(cfg, &buf)
		_, _ = r.Run(context.Background())
		return buf.String()
	}
	if out := run(func(c *Config) { c.Progress = true }); !strings.Contains(out, "unit/port-open/ssh") {
		t.Errorf("progress mode should list each case:\n%s", out)
	}
	if out := run(func(c *Config) { c.Quiet = true }); out != "" {
		t.Errorf("quiet mode should print nothing:\n%s", out)
	}
	// default mode prints only findings; a healthy target yields none.
	if out := run(func(c *Config) {}); strings.Contains(out, "unit/port-open/ssh") {
		t.Errorf("default mode should not list passing cases:\n%s", out)
	}
}

func TestRunFindingsOnlyOutput(t *testing.T) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1",
		Endpoints:  []Endpoint{{Label: "dead", Proto: "tcp", Port: 1, Handler: "ssh"}},
		Categories: []string{"unit"}}
	cfg.ApplyDefaults()
	cfg.Retries = 0
	var buf bytes.Buffer
	r, _ := NewRunner(cfg, &buf)
	_, _ = r.Run(context.Background())
	if !strings.Contains(buf.String(), "unit/port-open/dead") {
		t.Errorf("default mode should print the finding for a closed port:\n%s", buf.String())
	}
}

func TestRunContextCancelled(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true,
		Endpoints:  []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}},
		Categories: []string{"unit", "emulate", "fuzz-dumb"}}
	cfg.ApplyDefaults()
	r, _ := NewRunner(cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	rr, err := r.Run(ctx)
	if err != nil {
		t.Fatalf("Run should return cleanly on a cancelled ctx: %v", err)
	}
	if len(rr.Results) != 0 {
		t.Errorf("a cancelled run should execute no cases; got %d", len(rr.Results))
	}
}

func TestRunHighConcurrency(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true, Concurrency: 64, FuzzIterations: 4,
		Endpoints:  []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}},
		Categories: []string{"unit", "emulate", "fuzz-dumb"}}
	cfg.ApplyDefaults()
	r, _ := NewRunner(cfg, nil)
	rr, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rr.Results) != 4 { // concurrency far exceeds the case count: must not deadlock
		t.Errorf("results = %d; want 4", len(rr.Results))
	}
}

func TestDBRecentLimitOrdering(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var ids []int64
	for i := 0; i < 3; i++ {
		id, err := db.Record(&RunResult{Started: time.Now(), Finished: time.Now(), Seed: int64(i),
			ToolVersion: "v", Target: "t", Rounds: 1,
			Results: []Result{{CaseID: "a", Category: CatUnit, Round: 1, Attempt: 1, Status: StatusPass}}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	rows, err := db.Recent(2)
	if err != nil || len(rows) != 2 {
		t.Fatalf("Recent(2) = %d rows, err=%v", len(rows), err)
	}
	if rows[0].ID != ids[2] || rows[1].ID != ids[1] {
		t.Errorf("Recent(2) order = [%d %d]; want newest-first [%d %d]", rows[0].ID, rows[1].ID, ids[2], ids[1])
	}
}

// --- managed-target lifecycle -----------------------------------------------

func TestManagedTargetLifecycle(t *testing.T) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true,
		Spawn: SpawnCfg{Binary: sleeperScript(t, "0.5"), ReadyTimeout: Duration(2 * time.Second)}}
	cfg.ApplyDefaults()
	tg, _ := NewTarget(cfg)
	defer tg.Stop()
	if !tg.Managed() {
		t.Fatal("a network target with spawn.binary should be Managed")
	}
	if err := tg.Start(context.Background()); err != nil {
		t.Fatalf("Start (spawn + waitReady): %v", err)
	}
	if !tg.Alive(context.Background()) {
		t.Error("the spawned child should be Alive immediately after Start")
	}
	time.Sleep(900 * time.Millisecond) // let the 0.5s sleeper exit and be reaped
	if tg.Alive(context.Background()) {
		t.Error("a child that has exited should no longer be Alive")
	}
}

func TestManagedTargetRestart(t *testing.T) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true,
		Spawn: SpawnCfg{Binary: sleeperScript(t, "5"), ReadyTimeout: Duration(2 * time.Second)}}
	cfg.ApplyDefaults()
	tg, _ := NewTarget(cfg)
	defer tg.Stop()
	if err := tg.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := tg.Restart(context.Background()); err != nil {
		t.Fatalf("Restart (kill + respawn): %v", err)
	}
	if !tg.Alive(context.Background()) {
		t.Error("the respawned child should be Alive after Restart")
	}
}

// --- small helpers ----------------------------------------------------------

func mustRunnerRun(t *testing.T, cfg *Config) (*RunResult, error) {
	t.Helper()
	r, err := NewRunner(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r.Run(context.Background())
}

func resultsByID(rr *RunResult) map[string]Result {
	m := make(map[string]Result, len(rr.Results))
	for _, res := range rr.Results {
		m[res.CaseID] = res
	}
	return m
}
