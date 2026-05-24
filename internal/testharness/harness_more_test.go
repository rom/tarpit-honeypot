package testharness

// Additional unit tests that extend coverage of the harness internals not
// exercised by harness_test.go: the case selector forms, status/result
// aggregation, byte/format helpers, config defaulting, the JUnit status
// mapping, the detection API client (over httptest), the exchange I/O
// primitive, and the smart-fuzz mutator.

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func caseIDSet(cs []Case) map[string]bool {
	m := make(map[string]bool, len(cs))
	for _, c := range cs {
		m[c.ID] = true
	}
	return m
}

// TestSelectMatchers exercises every selector form matchAny supports beyond the
// single glob covered by TestBuildAndSelect: exact id, a multi-segment glob, an
// id prefix (trailing slash), a bare prefix/category name, and a category glob.
func TestSelectMatchers(t *testing.T) {
	cfg := &Config{
		Mode: "network", Host: "127.0.0.1",
		Endpoints: []Endpoint{
			{Label: "ssh", Proto: "tcp", Port: 2222, Handler: "ssh"},
			{Label: "http", Proto: "tcp", Port: 8000, Handler: "http"},
			{Label: "modbus", Proto: "tcp", Port: 5020, Handler: "modbus"},
		},
	}
	cfg.ApplyDefaults()
	all := Build(cfg)

	// Exact id selects exactly that case.
	if got := Select(all, []string{"emulate/ssh"}, nil); len(got) != 1 || got[0].ID != "emulate/ssh" {
		t.Errorf("exact id select = %v; want [emulate/ssh]", caseIDSet(got))
	}

	// Multi-segment glob: '*' does not cross '/', so misimpl/*/* matches the
	// three-segment misimpl ids and nothing else.
	mis := Select(all, []string{"misimpl/*/*"}, nil)
	if len(mis) != 5 {
		t.Errorf("misimpl/*/* selected %d; want 5: %v", len(mis), caseIDSet(mis))
	}
	for _, c := range mis {
		if !strings.HasPrefix(c.ID, "misimpl/") {
			t.Errorf("misimpl/*/* leaked %s", c.ID)
		}
	}

	// Id prefix with trailing slash selects all port-open cases (not banner).
	po := Select(all, []string{"unit/port-open/"}, nil)
	if len(po) != 3 {
		t.Errorf("unit/port-open/ selected %d; want 3: %v", len(po), caseIDSet(po))
	}
	for _, c := range po {
		if !strings.HasPrefix(c.ID, "unit/port-open/") {
			t.Errorf("unit/port-open/ leaked %s", c.ID)
		}
	}

	// A bare name selects by category-or-prefix: "scan" picks the five scan cases.
	scan := Select(all, []string{"scan"}, nil)
	if len(scan) != 5 {
		t.Errorf("scan selected %d; want 5: %v", len(scan), caseIDSet(scan))
	}
	for _, c := range scan {
		if c.Category != CatScan {
			t.Errorf("scan selector leaked category %s (%s)", c.Category, c.ID)
		}
	}

	// A bare category name selects that whole category.
	smart := Select(all, []string{"fuzz-smart"}, nil)
	if len(smart) != 3 {
		t.Errorf("fuzz-smart selected %d; want 3: %v", len(smart), caseIDSet(smart))
	}

	// A slash-free glob matches by category: fuzz-* = fuzz-dumb + fuzz-smart.
	fuzz := Select(all, []string{"fuzz-*"}, nil)
	if len(fuzz) != 6 {
		t.Errorf("fuzz-* selected %d; want 6: %v", len(fuzz), caseIDSet(fuzz))
	}
	for _, c := range fuzz {
		if !strings.HasPrefix(string(c.Category), "fuzz-") {
			t.Errorf("fuzz-* leaked category %s (%s)", c.Category, c.ID)
		}
	}
}

func TestStatusBad(t *testing.T) {
	bad := map[Status]bool{
		StatusPass:  false,
		StatusSkip:  false,
		StatusFail:  true,
		StatusCrash: true,
		StatusError: true,
	}
	for s, want := range bad {
		if s.Bad() != want {
			t.Errorf("Status(%q).Bad() = %v; want %v", s, s.Bad(), want)
		}
	}
}

func TestRunResultAggregations(t *testing.T) {
	start := time.Now()
	rr := &RunResult{
		Started:  start,
		Finished: start.Add(5 * time.Second),
		Results: []Result{
			{CaseID: "a", Status: StatusPass},
			{CaseID: "b", Status: StatusPass},
			{CaseID: "c", Status: StatusFail},
			{CaseID: "d", Status: StatusCrash},
			{CaseID: "e", Status: StatusError},
			{CaseID: "f", Status: StatusSkip},
		},
	}
	c := rr.Counts()
	if c[StatusPass] != 2 || c[StatusFail] != 1 || c[StatusCrash] != 1 || c[StatusError] != 1 || c[StatusSkip] != 1 {
		t.Errorf("Counts() = %v", c)
	}
	if f := rr.Findings(); len(f) != 3 {
		t.Errorf("Findings() = %d; want 3 (fail+crash+error)", len(f))
	}
	if rr.OK() {
		t.Error("OK() should be false when there are findings")
	}
	if rr.Duration() != 5*time.Second {
		t.Errorf("Duration() = %s; want 5s", rr.Duration())
	}

	clean := &RunResult{Results: []Result{{Status: StatusPass}, {Status: StatusSkip}}}
	if !clean.OK() || len(clean.Findings()) != 0 {
		t.Error("a pass+skip run should be OK with no findings")
	}
}

func TestSnippet(t *testing.T) {
	if got := snippet([]byte("ok")); got != "ok" {
		t.Errorf("snippet(ok) = %q", got)
	}
	// Non-printable bytes become '.', whitespace control chars are kept.
	if got := snippet([]byte("a\x00b")); got != "a.b" {
		t.Errorf("snippet(a\\x00b) = %q; want a.b", got)
	}
	if got := snippet([]byte("a\r\n\tb")); got != "a\r\n\tb" {
		t.Errorf("snippet kept-whitespace = %q", got)
	}
	if got := snippet([]byte{0x7f}); got != "." {
		t.Errorf("snippet(DEL) = %q; want .", got)
	}
	// Over the 80-byte cap: truncated to 80 visible bytes + an ellipsis.
	long := snippet(bytes.Repeat([]byte("A"), 100))
	if !strings.HasSuffix(long, "…") {
		t.Errorf("oversized snippet should end with an ellipsis: %q", long)
	}
	if n := strings.Count(long, "A"); n != 80 {
		t.Errorf("oversized snippet kept %d bytes; want 80", n)
	}
}

func TestItoa(t *testing.T) {
	for in, want := range map[int]string{0: "0", 7: "7", 42: "42", 65000: "65000", -1: "-1", -42: "-42"} {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q; want %q", in, got, want)
		}
	}
}

func TestApplyDefaults(t *testing.T) {
	c := &Config{}
	c.ApplyDefaults()
	if c.Mode != "network" || c.Host != "127.0.0.1" || c.Rounds != 1 || c.Concurrency != 1 {
		t.Errorf("base defaults wrong: %+v", c)
	}
	if c.Retries != 1 {
		t.Errorf("Retries default = %d; want 1", c.Retries)
	}
	if c.Timeout.D() != 3*time.Second || c.Spawn.ReadyTimeout.D() != 10*time.Second {
		t.Errorf("duration defaults wrong: timeout=%s ready=%s", c.Timeout, c.Spawn.ReadyTimeout)
	}
	if c.FuzzIterations != 64 || c.Seed != DefaultSeed {
		t.Errorf("fuzz defaults wrong: iters=%d seed=%d", c.FuzzIterations, c.Seed)
	}

	// A per-case retry map suppresses the global retry default (stays 0).
	c2 := &Config{RetriesByCase: map[string]int{"x": 3}}
	c2.ApplyDefaults()
	if c2.Retries != 0 {
		t.Errorf("Retries with a by-case map = %d; want 0", c2.Retries)
	}

	// Explicit values are preserved.
	c3 := &Config{Mode: "module", Host: "h", Rounds: 5, Retries: 2, Timeout: Duration(time.Second), Concurrency: 4, FuzzIterations: 9, Seed: 123}
	c3.ApplyDefaults()
	if c3.Mode != "module" || c3.Host != "h" || c3.Rounds != 5 || c3.Retries != 2 || c3.Concurrency != 4 || c3.FuzzIterations != 9 || c3.Seed != 123 {
		t.Errorf("explicit values overwritten: %+v", c3)
	}
}

// TestJUnitStatusMapping confirms each status maps to the right JUnit element
// (fail+crash -> failure, error -> error, skip -> skipped, pass -> none) and
// that the suite counters tally — deeper than the substring check in
// TestReportAndDB.
func TestJUnitStatusMapping(t *testing.T) {
	now := time.Now()
	rr := &RunResult{
		Started: now.Add(-time.Second), Finished: now, ToolVersion: "t", Target: "x", Rounds: 1,
		Results: []Result{
			{CaseID: "p", Category: CatUnit, Round: 1, Attempt: 1, Status: StatusPass},
			{CaseID: "f", Category: CatFuzzDumb, Round: 1, Attempt: 1, Status: StatusFail, Detail: "boom"},
			{CaseID: "c", Category: CatReliability, Round: 1, Attempt: 1, Status: StatusCrash, Detail: "died"},
			{CaseID: "e", Category: CatScan, Round: 1, Attempt: 1, Status: StatusError, Err: "oops"},
			{CaseID: "s", Category: CatEmulate, Round: 1, Attempt: 1, Status: StatusSkip, Detail: "n/a"},
		},
	}
	p := filepath.Join(t.TempDir(), "j.xml")
	if err := WriteReports(rr, []ReportCfg{{Format: "junit", Path: p}}); err != nil {
		t.Fatalf("write junit: %v", err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var suites junitSuites
	if err := xml.Unmarshal(b, &suites); err != nil {
		t.Fatalf("parse junit: %v", err)
	}
	if len(suites.Suites) != 1 {
		t.Fatalf("suites = %d; want 1", len(suites.Suites))
	}
	s := suites.Suites[0]
	if s.Tests != 5 || s.Failures != 2 || s.Errors != 1 || s.Skipped != 1 {
		t.Errorf("counters: tests=%d failures=%d errors=%d skipped=%d", s.Tests, s.Failures, s.Errors, s.Skipped)
	}
	byName := map[string]junitCase{}
	for _, jc := range s.Cases {
		byName[jc.Name] = jc
	}
	if c := byName["p"]; c.Failure != nil || c.Error != nil || c.Skipped != nil {
		t.Error("pass case should have no failure/error/skipped element")
	}
	if c := byName["f"]; c.Failure == nil || strings.TrimSpace(c.Failure.Body) != "boom" {
		t.Errorf("fail case mapping wrong: %+v", c.Failure)
	}
	if byName["c"].Failure == nil {
		t.Error("crash case should map to a <failure>")
	}
	if c := byName["e"]; c.Error == nil || strings.TrimSpace(c.Error.Body) != "oops" {
		t.Errorf("error case mapping wrong: %+v", c.Error)
	}
	if byName["s"].Skipped == nil {
		t.Error("skip case should map to a <skipped>")
	}
}

// TestAPIClientDetected drives the detection client against a fake events API:
// a match returns (true,true), a non-match (false,true), and an unreachable
// API (false,false) so callers skip rather than fail.
func TestAPIClientDetected(t *testing.T) {
	evs := []apiEvent{
		{RuleID: "listener:ssh", Meta: map[string]any{"anomalies": []any{"ssh-id-not-ssh"}}},
		{RuleID: "correlate:port_scan"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/events" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(evs)
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL+"/", "tok")
	if c.base != srv.URL {
		t.Errorf("NewAPIClient base = %q; want trailing slash trimmed to %q", c.base, srv.URL)
	}
	ctx := context.Background()

	if det, checked := c.Detected(ctx, MatchRulePrefix("listener:")); !det || !checked {
		t.Errorf("rule-prefix match: det=%v checked=%v; want true true", det, checked)
	}
	if det, checked := c.Detected(ctx, MatchAnomaly("ssh-id-not-ssh")); !det || !checked {
		t.Errorf("anomaly match: det=%v checked=%v; want true true", det, checked)
	}
	if det, checked := c.Detected(ctx, MatchRulePrefix("nope:")); det || !checked {
		t.Errorf("non-match: det=%v checked=%v; want false true", det, checked)
	}

	// An unreachable API => checked=false so the caller skips, never falsely fails.
	down := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := down.URL
	down.Close()
	if det, checked := NewAPIClient(url, "").Detected(ctx, MatchRulePrefix("listener:")); det || checked {
		t.Errorf("unreachable API: det=%v checked=%v; want false false", det, checked)
	}
}

// TestExchange covers the core I/O primitive: a normal request/reply ending in
// a close, and the server-first path where a read deadline after data is
// treated as success (not an error).
func TestExchange(t *testing.T) {
	t.Run("reply-then-close", func(t *testing.T) {
		client, server := net.Pipe()
		go func() {
			buf := make([]byte, 64)
			_, _ = server.Read(buf) // consume the probe
			_, _ = server.Write([]byte("REPLY"))
			_ = server.Close()
		}()
		got, err := exchange(client, []byte("PROBE"), time.Second)
		_ = client.Close()
		if err != nil {
			t.Fatalf("exchange error: %v", err)
		}
		if string(got) != "REPLY" {
			t.Errorf("exchange read = %q; want REPLY", got)
		}
	})

	t.Run("timeout-with-data", func(t *testing.T) {
		client, server := net.Pipe()
		done := make(chan struct{})
		go func() {
			_, _ = server.Write([]byte("HI"))
			<-done
			_ = server.Close()
		}()
		got, err := exchange(client, nil, 150*time.Millisecond)
		close(done)
		_ = client.Close()
		if err != nil {
			t.Fatalf("a read deadline after data should be success, got: %v", err)
		}
		if string(got) != "HI" {
			t.Errorf("exchange read = %q; want HI", got)
		}
	})
}

// TestMutate checks the smart-fuzz mutator is deterministic for a given
// seed+id, varies across seeds, and never panics on empty/short inputs (all
// four mutation branches).
func TestMutate(t *testing.T) {
	base := []byte("SSH-2.0-base-shape")
	a := mutate(caseRand(7, "m"), base)
	b := mutate(caseRand(7, "m"), base)
	if !bytes.Equal(a, b) {
		t.Error("mutate must be deterministic for the same seed + id")
	}

	seen := map[string]bool{}
	for s := int64(0); s < 50; s++ {
		seen[string(mutate(caseRand(s, "m"), base))] = true
	}
	if len(seen) < 2 {
		t.Errorf("mutate produced no variation across 50 seeds (%d distinct)", len(seen))
	}

	for s := int64(0); s < 200; s++ {
		_ = mutate(caseRand(s, "empty"), nil)
		_ = mutate(caseRand(s, "one"), []byte{0x41})
	}
}

// TestNewProtocolSpecsGenerateCases checks the newly-added handlers produce the
// expected protocol-aware cases (emulate / fuzz-smart / misimpl), and that the
// existing ftp/telnet specs now carry misimpl coverage — so a config that names
// these handlers gets real coverage rather than the generic fallback.
func TestNewProtocolSpecsGenerateCases(t *testing.T) {
	cfg := &Config{
		Mode: "network", Host: "127.0.0.1",
		Endpoints: []Endpoint{
			{Label: "rlogin", Proto: "tcp", Port: 513, Handler: "rlogin"},
			{Label: "rsh", Proto: "tcp", Port: 514, Handler: "rsh"},
			{Label: "rexec", Proto: "tcp", Port: 512, Handler: "rexec"},
			{Label: "tftp", Proto: "udp", Port: 69, Handler: "tftp"},
			{Label: "syslogt", Proto: "tcp", Port: 601, Handler: "syslog_tcp"},
			{Label: "syslogu", Proto: "udp", Port: 514, Handler: "syslog_udp"},
			{Label: "ftp", Proto: "tcp", Port: 21, Handler: "ftp"},
			{Label: "telnet", Proto: "tcp", Port: 23, Handler: "telnet"},
		},
	}
	cfg.ApplyDefaults()
	ids := caseIDSet(Build(cfg))
	for _, want := range []string{
		"emulate/rlogin", "misimpl/rlogin/connect", "fuzz-smart/rlogin",
		"emulate/rsh", "misimpl/rsh/command", "fuzz-smart/rsh",
		"emulate/rexec", "misimpl/rexec/command",
		"emulate/tftp", "misimpl/tftp/write-attempt", "misimpl/tftp/config-read", "fuzz-smart/tftp",
		"unit/banner/tftp",
		"emulate/syslogt", "fuzz-smart/syslogt",
		"emulate/syslogu", "fuzz-smart/syslogu", "fuzz-dumb/syslogu",
		"misimpl/ftp/upload-attempt", "misimpl/ftp/download-attempt",
		"misimpl/telnet/binary-credentials",
	} {
		if !ids[want] {
			t.Errorf("expected case %q to be generated", want)
		}
	}
}

// TestModuleNewProtocolsRespond drives the real rlogin/rsh/rexec/syslog_tcp
// handlers in-process (module mode) to confirm the new specs' probes elicit a
// protocol-compatible response — and that the accept-only syslog passes
// unit/banner via the NoReply path rather than failing on an empty reply.
func TestModuleNewProtocolsRespond(t *testing.T) {
	cfg := &Config{
		Mode: "module",
		Endpoints: []Endpoint{
			{Label: "rlogin", Proto: "tcp", Handler: "rlogin"},
			{Label: "rsh", Proto: "tcp", Handler: "rsh"},
			{Label: "rexec", Proto: "tcp", Handler: "rexec"},
			{Label: "syslog", Proto: "tcp", Handler: "syslog_tcp"},
		},
		Categories: []string{"unit", "emulate"},
		Timeout:    Duration(300 * time.Millisecond),
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
	byID := map[string]Result{}
	for _, res := range rr.Results {
		byID[res.CaseID] = res
	}
	for _, id := range []string{
		"unit/banner/rlogin", "emulate/rlogin",
		"unit/banner/rsh", "emulate/rsh",
		"unit/banner/rexec", "emulate/rexec",
		"unit/banner/syslog", "emulate/syslog",
	} {
		if byID[id].Status != StatusPass {
			t.Errorf("%s = %s (%s); want pass", id, byID[id].Status, byID[id].Detail)
		}
	}
}
