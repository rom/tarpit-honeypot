package testharness

// A third batch of harness tests, broadening four areas:
//   - low-level primitives (exchange bounds + hang-safety, probe, protocol
//     helpers, randBytes distribution, config loading);
//   - crash/hang detection (the harness must turn a dead/silent target into a
//     StatusCrash, and must never hang on a black-hole peer);
//   - integrated runner + target-lifecycle behaviour (concurrency, time bound,
//     retry+restart, managed-spawn errors, readiness probing);
//   - all-category module runs.

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// dyingHoneypot serves `after` SSH-ish connections, then closes its listener so
// the port goes dead — a target that crashes mid-run.
func dyingHoneypot(t *testing.T, after int) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		n := 0
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n++
			if n > after {
				_ = c.Close()
				_ = ln.Close()
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("SSH-2.0-dying\r\n"))
				_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				_, _ = c.Read(make([]byte, 512))
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// blackholeHoneypot accepts connections and holds them open forever, never
// reading or writing — a silent peer the harness must not hang on.
func blackholeHoneypot(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range held {
			_ = c.Close()
		}
		mu.Unlock()
	})
	return ln.Addr().(*net.TCPAddr).Port
}

// --- low-level primitives ---------------------------------------------------

func TestProtocolHelpers(t *testing.T) {
	if !containsAll([]byte("HTTP/1.1 200 OK"), []string{"HTTP/", "200"}) {
		t.Error("containsAll should match present substrings")
	}
	if containsAll([]byte("HTTP/1.1"), []string{"SSH-"}) {
		t.Error("containsAll matched an absent substring")
	}
	if !startsWith([]byte("SSH-2.0-x"), "SSH-2.0") || startsWith([]byte("hi"), "SSH-") {
		t.Error("startsWith logic wrong")
	}
	if _, ok := specFor(Endpoint{Handler: "ssh"}); !ok {
		t.Error("specFor(ssh) should be known")
	}
	if _, ok := specFor(Endpoint{Handler: "definitely-not-a-handler"}); ok {
		t.Error("specFor(unknown) should be false")
	}
}

func TestExchangeMaxReadCap(t *testing.T) {
	client, server := net.Pipe()
	go func() { _, _ = server.Write(make([]byte, 2<<20)) }() // 2 MiB; exchange must stop early
	got, err := exchange(client, nil, 2*time.Second)
	_ = client.Close()
	_ = server.Close()
	if err != nil {
		t.Fatalf("exchange error: %v", err)
	}
	if len(got) < maxRead || len(got) > maxRead+4096 {
		t.Errorf("captured %d bytes; want ~maxRead (%d)", len(got), maxRead)
	}
}

func TestExchangeBlackHolePipe(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	start := time.Now()
	got, err := exchange(client, []byte("PROBE"), 150*time.Millisecond)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("exchange hung for %s against a silent peer", d)
	}
	if err != nil || len(got) != 0 {
		t.Errorf("black-hole exchange = %q, %v; want empty, nil", got, err)
	}
}

func TestExchangeEcho(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		buf := make([]byte, 64)
		n, _ := server.Read(buf)
		_, _ = server.Write(buf[:n])
		_ = server.Close()
	}()
	got, err := exchange(client, []byte("HELLO"), time.Second)
	_ = client.Close()
	if err != nil || string(got) != "HELLO" {
		t.Errorf("echo exchange = %q, %v; want HELLO", got, err)
	}
}

func TestProbeBlackHoleBounded(t *testing.T) {
	port := blackholeHoneypot(t)
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Timeout: Duration(150 * time.Millisecond),
		Endpoints: []Endpoint{{Label: "x", Proto: "tcp", Port: port, Handler: "ssh"}}}
	cfg.ApplyDefaults()
	cfg.Timeout = Duration(150 * time.Millisecond)
	tg, _ := NewTarget(cfg)
	ep, _ := tg.Endpoint("x")
	start := time.Now()
	resp, err := probe(context.Background(), tg, ep, []byte("hi"))
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("probe hung for %s against a black-hole port", d)
	}
	if err != nil || len(resp) != 0 {
		t.Errorf("black-hole probe = %q, %v; want empty, nil", resp, err)
	}
}

func TestRandBytesDistribution(t *testing.T) {
	over := 0
	for s := int64(0); s < 300; s++ {
		n := len(randBytes(caseRand(s, "dist")))
		if n > 16384 {
			t.Fatalf("randBytes produced %d bytes (> 16384 bound)", n)
		}
		if n > 2048 {
			over++
		}
	}
	if over == 0 {
		t.Error("the oversized (>2048) randBytes branch was never hit across 300 seeds")
	}
}

func TestVerifyScanNoAPI(t *testing.T) {
	st, detail := verifyScan(context.Background(), &Run{API: nil}, MatchRulePrefix("scan:"))
	if st != StatusPass || !strings.Contains(detail, "completed") {
		t.Errorf("verifyScan without an API = %s %q; want pass/completed", st, detail)
	}
}

func TestConfigLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	yaml := "mode: module\nendpoints:\n  - {label: http, proto: tcp, handler: http}\nfuzz_iterations: 99\ntimeout: 5s\n"
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Mode != "module" || c.FuzzIterations != 99 || c.Timeout.D() != 5*time.Second {
		t.Errorf("loaded config wrong: %+v", c)
	}
	if c.Host != "127.0.0.1" || c.Rounds != 1 {
		t.Errorf("ApplyDefaults not run on Load: host=%q rounds=%d", c.Host, c.Rounds)
	}
}

func TestConfigLoadErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("Load of a missing file should error")
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	_ = os.WriteFile(bad, []byte("mode: [unterminated"), 0o644)
	if _, err := Load(bad); err == nil {
		t.Error("Load of malformed YAML should error")
	}
	inv := filepath.Join(t.TempDir(), "inv.yaml")
	_ = os.WriteFile(inv, []byte("mode: bogus\n"), 0o644)
	if _, err := Load(inv); err == nil {
		t.Error("Load of an invalid config should error")
	}
}

// --- crash / hang detection -------------------------------------------------

func TestRunCaseReclassifiesCrash(t *testing.T) {
	port, stop := fakeHoneypot(t)
	var once sync.Once
	safeStop := func() { once.Do(stop) }
	defer safeStop()
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true,
		Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}}}
	cfg.ApplyDefaults()
	cfg.Retries = 0
	r, _ := NewRunner(cfg, nil)
	c := Case{ID: "x/die", Category: CatFuzzDumb, Endpoint: "ssh",
		Fn: func(ctx context.Context, run *Run) (Status, string, error) {
			safeStop() // the target "dies" while the case runs
			return StatusFail, "sent input", nil
		}}
	res := r.runCase(context.Background(), c, 1, time.Time{})
	if res.Status != StatusCrash {
		t.Errorf("a Fail against a now-dead target should reclassify to crash; got %s", res.Status)
	}
}

func TestFuzzDumbDetectsDeadTarget(t *testing.T) {
	port := dyingHoneypot(t, 3)
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true,
		Endpoints:      []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}},
		FuzzIterations: 30, Timeout: Duration(200 * time.Millisecond)}
	cfg.ApplyDefaults()
	cfg.Retries = 0
	r, _ := NewRunner(cfg, nil)
	cases := Select(Build(cfg), []string{"fuzz-dumb/ssh"}, nil)
	if len(cases) != 1 {
		t.Fatalf("expected one fuzz-dumb/ssh case, got %d", len(cases))
	}
	res := r.runCase(context.Background(), cases[0], 1, time.Time{})
	if res.Status != StatusCrash {
		t.Errorf("fuzz-dumb against a dying target = %s (%s); want crash", res.Status, res.Detail)
	}
}

func TestReliabilitySoakDetectsDeath(t *testing.T) {
	port := dyingHoneypot(t, 3)
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true, Timeout: Duration(200 * time.Millisecond),
		Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}}}
	cfg.ApplyDefaults()
	cfg.Retries = 0
	r, _ := NewRunner(cfg, nil)
	cases := Select(Build(cfg), []string{"reliability/soak/ssh"}, nil)
	if len(cases) != 1 {
		t.Fatalf("expected one reliability/soak/ssh case, got %d", len(cases))
	}
	res := r.runCase(context.Background(), cases[0], 1, time.Time{})
	if res.Status != StatusCrash {
		t.Errorf("soak against a dying target = %s (%s); want crash", res.Status, res.Detail)
	}
}

// --- integrated runner + target lifecycle -----------------------------------

func TestRunConcurrent(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true, Concurrency: 4, FuzzIterations: 8,
		Endpoints:  []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}},
		Categories: []string{"unit", "emulate", "fuzz-dumb"}}
	cfg.ApplyDefaults()
	r, _ := NewRunner(cfg, nil)
	rr, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rr.Results) != 4 { // port-open, banner, emulate, fuzz-dumb
		t.Errorf("results = %d; want 4", len(rr.Results))
	}
	if !rr.OK() {
		t.Errorf("unexpected findings: %v", rr.Findings())
	}
}

func TestRunTimeBounded(t *testing.T) {
	cfg := &Config{Mode: "module", Quiet: true, Rounds: 1000, Duration: Duration(time.Millisecond),
		Timeout: Duration(100 * time.Millisecond),
		Endpoints: []Endpoint{
			{Label: "a", Proto: "tcp", Handler: "http"},
			{Label: "b", Proto: "tcp", Handler: "ssh"},
			{Label: "c", Proto: "tcp", Handler: "ftp"},
		},
		Categories: []string{"unit"}}
	cfg.ApplyDefaults()
	cfg.Rounds = 1000
	r, _ := NewRunner(cfg, nil)
	rr, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rr.TimeBounded {
		t.Error("a run that hit the duration bound should set TimeBounded")
	}
	if len(rr.Results) >= 6*1000 {
		t.Errorf("time-bounded run did not stop early: %d results", len(rr.Results))
	}
}

func TestRunRetryRestartsExternal(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	marker := filepath.Join(t.TempDir(), "restarted")
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Quiet: true, RestartCmd: "touch " + marker,
		Endpoints: []Endpoint{{Label: "ssh", Proto: "tcp", Port: port, Handler: "ssh"}}}
	cfg.ApplyDefaults() // retries = 1
	r, _ := NewRunner(cfg, nil)
	calls := 0
	c := Case{ID: "x/retry", Category: CatUnit, Fn: func(ctx context.Context, run *Run) (Status, string, error) {
		calls++
		if calls == 1 {
			return StatusFail, "first try", nil
		}
		return StatusPass, "ok", nil
	}}
	res := r.runCase(context.Background(), c, 1, time.Time{})
	if res.Status != StatusPass || res.Attempt != 2 {
		t.Errorf("status=%s attempt=%d; want pass on attempt 2", res.Status, res.Attempt)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("restart_cmd did not run between retries: %v", err)
	}
}

func TestManagedSpawnErrors(t *testing.T) {
	missing := &Config{Mode: "network", Host: "127.0.0.1", Spawn: SpawnCfg{Binary: "/nonexistent/tarpit-xyz"},
		Endpoints: []Endpoint{{Label: "x", Proto: "tcp", Port: 1, Handler: "ssh"}}}
	missing.ApplyDefaults()
	tg, _ := NewTarget(missing)
	if err := tg.Start(context.Background()); err == nil {
		t.Error("spawning a missing binary should error")
	}
	badCfg := &Config{Mode: "network", Host: "127.0.0.1", Spawn: SpawnCfg{Binary: "/bin/sh", Config: "/nonexistent/cfg.yaml"},
		Endpoints: []Endpoint{{Label: "x", Proto: "tcp", Port: 1, Handler: "ssh"}}}
	badCfg.ApplyDefaults()
	tg2, _ := NewTarget(badCfg)
	if err := tg2.Start(context.Background()); err == nil {
		t.Error("spawning with a missing spawn.config should error")
	}
}

func TestRestartExternalCmd(t *testing.T) {
	port, stop := fakeHoneypot(t)
	defer stop()
	mk := func(cmd string) *Target {
		cfg := &Config{Mode: "network", Host: "127.0.0.1", RestartCmd: cmd,
			Endpoints: []Endpoint{{Label: "x", Proto: "tcp", Port: port, Handler: "ssh"}}}
		cfg.ApplyDefaults()
		tg, _ := NewTarget(cfg)
		return tg
	}
	if err := mk("true").Restart(context.Background()); err != nil {
		t.Errorf("restart_cmd 'true' should succeed: %v", err)
	}
	if err := mk("false").Restart(context.Background()); err == nil {
		t.Error("restart_cmd 'false' should error")
	}
	if err := mk("").Restart(context.Background()); err != nil {
		t.Errorf("empty restart_cmd should be a no-op: %v", err)
	}
}

func TestStartWaitReadyHealthURL(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer healthy.Close()
	cfg := &Config{Mode: "network", Host: "127.0.0.1",
		Spawn:     SpawnCfg{HealthURL: healthy.URL, ReadyTimeout: Duration(2 * time.Second)},
		Endpoints: []Endpoint{{Label: "x", Proto: "tcp", Port: 1, Handler: "ssh"}}}
	cfg.ApplyDefaults()
	tg, _ := NewTarget(cfg)
	if err := tg.Start(context.Background()); err != nil {
		t.Errorf("Start with a healthy URL should succeed: %v", err)
	}

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer down.Close()
	cfg2 := &Config{Mode: "network", Host: "127.0.0.1",
		Spawn:     SpawnCfg{HealthURL: down.URL, ReadyTimeout: Duration(500 * time.Millisecond)},
		Endpoints: []Endpoint{{Label: "x", Proto: "tcp", Port: 1, Handler: "ssh"}}}
	cfg2.ApplyDefaults()
	tg2, _ := NewTarget(cfg2)
	if err := tg2.Start(context.Background()); err == nil {
		t.Error("Start should fail readiness when /healthz returns 500")
	}
}

func TestTargetAliveTracksEndpoint(t *testing.T) {
	port, stop := fakeHoneypot(t)
	cfg := &Config{Mode: "network", Host: "127.0.0.1",
		Endpoints: []Endpoint{{Label: "x", Proto: "tcp", Port: port, Handler: "ssh"}}}
	cfg.ApplyDefaults()
	tg, _ := NewTarget(cfg)
	if !tg.Alive(context.Background()) {
		t.Error("a live endpoint should be Alive")
	}
	stop()
	if tg.Alive(context.Background()) {
		t.Error("a stopped endpoint should not be Alive")
	}
}

func TestRunModuleAllCategories(t *testing.T) {
	cfg := &Config{Mode: "module", Quiet: true, FuzzIterations: 8, Timeout: Duration(300 * time.Millisecond),
		Endpoints:  []Endpoint{{Label: "http", Proto: "tcp", Handler: "http"}},
		Categories: []string{"unit", "emulate", "misimpl", "fuzz-dumb", "fuzz-smart", "reliability"}}
	cfg.ApplyDefaults()
	r, _ := NewRunner(cfg, nil)
	rr, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rr.Results) == 0 {
		t.Fatal("no cases ran")
	}
	for _, res := range rr.Results {
		if res.Status == StatusCrash || res.Status == StatusError {
			t.Errorf("%s = %s (%s); the real http handler should not crash/error", res.CaseID, res.Status, res.Detail)
		}
	}
}
