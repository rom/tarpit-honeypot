package testharness

// A sixth batch: selection edges, config-default idempotency, the API request
// shape, the run-result metadata + per-case timing, target "trust the operator"
// readiness, the emulate-incompatible finding path, fuzz-smart pass, DB
// persistence across reopen, and a context-interruptible (hang-safe) case.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- selection / config -----------------------------------------------------

func TestSelectMultipleSelectorsOR(t *testing.T) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Endpoints: []Endpoint{
		{Label: "ssh", Proto: "tcp", Port: 22, Handler: "ssh"},
		{Label: "http", Proto: "tcp", Port: 80, Handler: "http"},
	}}
	cfg.ApplyDefaults()
	got := Select(Build(cfg), []string{"emulate/ssh", "unit/banner/http"}, nil)
	ids := caseIDSet(got)
	if len(got) != 2 || !ids["emulate/ssh"] || !ids["unit/banner/http"] {
		t.Errorf("two selectors should select their union; got %v", ids)
	}
}

func TestSelectTrimsWhitespace(t *testing.T) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: 22, Handler: "ssh"}}}
	cfg.ApplyDefaults()
	got := Select(Build(cfg), []string{"  unit  "}, nil)
	if len(got) == 0 {
		t.Fatal("a padded category selector should still match")
	}
	for _, c := range got {
		if c.Category != CatUnit {
			t.Errorf("padded 'unit' selector leaked %s", c.Category)
		}
	}
}

func TestApplyDefaultsIdempotent(t *testing.T) {
	c := &Config{Mode: "module", Endpoints: []Endpoint{{Label: "h", Proto: "tcp", Handler: "http"}}}
	c.ApplyDefaults()
	snap := *c
	c.ApplyDefaults()
	if c.Mode != snap.Mode || c.Host != snap.Host || c.Rounds != snap.Rounds || c.Retries != snap.Retries ||
		c.Timeout != snap.Timeout || c.Concurrency != snap.Concurrency || c.FuzzIterations != snap.FuzzIterations ||
		c.Seed != snap.Seed || c.Spawn.ReadyTimeout != snap.Spawn.ReadyTimeout {
		t.Errorf("ApplyDefaults is not idempotent:\n first=%+v\nsecond=%+v", snap, *c)
	}
}

// --- API request shape ------------------------------------------------------

func TestAPIClientEventsQuery(t *testing.T) {
	var query, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, auth = r.URL.RawQuery, r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode([]apiEvent{})
	}))
	defer srv.Close()
	if _, err := NewAPIClient(srv.URL, "tok").Events(context.Background(), "10m", 5000); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query, "since=10m") || !strings.Contains(query, "limit=5000") {
		t.Errorf("Events query = %q; want since=10m & limit=5000", query)
	}
	if auth != "Bearer tok" {
		t.Errorf("Authorization = %q; want Bearer tok", auth)
	}
}

func TestAPIClientNoTokenNoHeader(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode([]apiEvent{})
	}))
	defer srv.Close()
	if _, err := NewAPIClient(srv.URL, "").Events(context.Background(), "5m", 10); err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		t.Errorf("an empty token should send no Authorization header; got %q", auth)
	}
}

// --- run-result metadata + per-case timing ----------------------------------

func TestRunResultMetadata(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true, Seed: 12345,
		Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}}, Categories: []string{"unit"}}
	cfg.ApplyDefaults()
	r, _ := NewRunner(cfg, nil)
	rr, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rr.Seed != 12345 {
		t.Errorf("RunResult.Seed = %d; want 12345", rr.Seed)
	}
	if !strings.Contains(rr.ToolVersion, "(") {
		t.Errorf("ToolVersion = %q; want it to carry a commit in parens", rr.ToolVersion)
	}
	if !strings.Contains(rr.Target, "external") {
		t.Errorf("Target = %q; want an external description", rr.Target)
	}
	if rr.Finished.Before(rr.Started) {
		t.Error("Finished is before Started")
	}
}

func TestRunCaseRecordsTiming(t *testing.T) {
	r := mustRunner(t, &Config{Mode: "module", Endpoints: []Endpoint{{Label: "h", Proto: "tcp", Handler: "http"}}, Quiet: true})
	r.cfg.Retries = 0
	c := Case{ID: "x/slow", Category: CatUnit, Fn: func(ctx context.Context, run *Run) (Status, string, error) {
		time.Sleep(20 * time.Millisecond)
		return StatusPass, "ok", nil
	}}
	res := r.runCase(context.Background(), c, 2, time.Time{})
	if res.Status != StatusPass || res.Round != 2 || res.Attempt != 1 {
		t.Errorf("result fields wrong: %+v", res)
	}
	if res.Duration < 15*time.Millisecond || res.Started.IsZero() {
		t.Errorf("timing not recorded: dur=%s started=%v", res.Duration, res.Started)
	}
}

func TestRunCaseInterruptibleByContext(t *testing.T) {
	r := mustRunner(t, &Config{Mode: "module", Endpoints: []Endpoint{{Label: "h", Proto: "tcp", Handler: "http"}}, Quiet: true})
	r.cfg.Retries = 0
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	c := Case{ID: "x/hang", Category: CatUnit, Fn: func(ctx context.Context, run *Run) (Status, string, error) {
		<-ctx.Done() // a well-behaved case honours its context
		return StatusSkip, "interrupted", nil
	}}
	start := time.Now()
	res := r.runCase(ctx, c, 1, time.Time{})
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("a context-honouring case was not interrupted (%s) — caseTimeout would be the only bound", d)
	}
	if res.Status != StatusSkip {
		t.Errorf("status = %s; want skip", res.Status)
	}
}

// --- target readiness "trust the operator" ----------------------------------

func TestExternalTrustedWhenNoEndpoints(t *testing.T) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1"} // no endpoints, no spawn, no health
	cfg.ApplyDefaults()
	tg, _ := NewTarget(cfg)
	if tg.Managed() {
		t.Fatal("no spawn.binary => not managed")
	}
	if !tg.Alive(context.Background()) {
		t.Error("an external target with nothing to probe should be assumed alive")
	}
}

func TestReadyUDPOnlyAssumedUp(t *testing.T) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1",
		Endpoints: []Endpoint{{Label: "dns", Proto: "udp", Port: 53, Handler: "dns"}}}
	cfg.ApplyDefaults()
	tg, _ := NewTarget(cfg)
	if !tg.Alive(context.Background()) {
		t.Error("a UDP-only external target has no TCP to probe and should be assumed alive")
	}
}

func TestRestartModuleNoop(t *testing.T) {
	cfg := &Config{Mode: "module", Endpoints: []Endpoint{{Label: "h", Proto: "tcp", Handler: "http"}}}
	cfg.ApplyDefaults()
	tg, _ := NewTarget(cfg)
	if err := tg.Restart(context.Background()); err != nil {
		t.Errorf("module Restart should be a no-op, got %v", err)
	}
}

// --- case behaviour ---------------------------------------------------------

func TestEmulateIncompatibleResponse(t *testing.T) {
	port, stop := fakeHoneypot(t) // greets with an SSH banner
	defer stop()
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true,
		Endpoints:  []Endpoint{{Label: "http", Proto: "tcp", Port: port, Handler: "http"}},
		Categories: []string{"emulate"}}
	cfg.ApplyDefaults()
	cfg.Retries = 0
	rr, err := mustRunnerRun(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s := resultsByID(rr)["emulate/http"].Status; s != StatusFail {
		t.Errorf("emulating http against an SSH-banner target should fail as incompatible; got %s", s)
	}
}

func TestFuzzSmartPassesModule(t *testing.T) {
	cfg := &Config{Mode: "module", Quiet: true, FuzzIterations: 8, Timeout: Duration(300 * time.Millisecond),
		Endpoints: []Endpoint{{Label: "http", Proto: "tcp", Handler: "http"}}, Categories: []string{"fuzz-smart"}}
	cfg.ApplyDefaults()
	rr, err := mustRunnerRun(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s := resultsByID(rr)["fuzz-smart/http"].Status; s != StatusPass {
		t.Errorf("fuzz-smart against the real http handler should pass (no crash); got %s", s)
	}
}

// --- DB persistence + concurrency stress ------------------------------------

func TestDBReopenPersists(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.db")
	rr := &RunResult{Started: time.Now(), Finished: time.Now(), Seed: 1, ToolVersion: "v", Target: "t", Rounds: 1,
		Results: []Result{{CaseID: "a", Category: CatUnit, Round: 1, Attempt: 1, Status: StatusPass}}}
	db, err := OpenDB(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Record(rr); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	db2, err := OpenDB(p) // reopen the same file
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	rows, err := db2.Recent(5)
	if err != nil || len(rows) != 1 {
		t.Fatalf("reopened DB should retain the prior run: %d rows, err=%v", len(rows), err)
	}
}

func TestRunConcurrentMultiEndpoint(t *testing.T) {
	cfg := &Config{Mode: "module", Quiet: true, Concurrency: 8, FuzzIterations: 4, Timeout: Duration(200 * time.Millisecond),
		Endpoints: []Endpoint{
			{Label: "http", Proto: "tcp", Handler: "http"},
			{Label: "ssh", Proto: "tcp", Handler: "ssh"},
			{Label: "ftp", Proto: "tcp", Handler: "ftp"},
			{Label: "redis", Proto: "tcp", Handler: "redis"},
			{Label: "smtp", Proto: "tcp", Handler: "smtp_recv"},
		},
		Categories: []string{"unit", "emulate", "fuzz-dumb"}}
	cfg.ApplyDefaults()
	r, _ := NewRunner(cfg, nil)
	want := len(r.Cases())
	rr, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rr.Results) != want {
		t.Errorf("concurrent run produced %d results; want %d (no case lost under concurrency)", len(rr.Results), want)
	}
}
