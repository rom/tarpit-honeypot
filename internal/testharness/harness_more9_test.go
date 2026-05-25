package testharness

// A ninth batch: harness self-trust (positive/negative/error/panic controls,
// deterministic selection, the accounting invariant) and the evidence-integrity
// category (capture fidelity / no-dropped-events, which need the sensor API).

import (
	"context"
	"strings"
	"testing"
)

// --- self-trust -------------------------------------------------------------

func TestClassifyFoldsError(t *testing.T) {
	if classify(StatusPass, nil) != StatusPass {
		t.Error("pass+no-error should classify as pass")
	}
	if classify(StatusFail, nil) != StatusFail {
		t.Error("fail+no-error should classify as fail")
	}
	if classify(StatusPass, context.Canceled) != StatusError {
		t.Error("any returned error must classify as error")
	}
}

func TestSelfCheckPasses(t *testing.T) {
	if err := selfCheck(context.Background()); err != nil {
		t.Fatalf("self-check should pass on a healthy harness: %v", err)
	}
}

// TestSelfCheckCatchesBrokenClassifier proves the control table actually
// distinguishes the four outcomes — i.e. if the runner ever mis-classified one,
// selfCheck would catch it. We re-evaluate each control through the same
// safeRun+classify path and assert the expected mapping.
func TestSelfCheckControlsDistinct(t *testing.T) {
	cases := []struct {
		fn   func(context.Context, *Run) (Status, string, error)
		want Status
	}{
		{func(context.Context, *Run) (Status, string, error) { return StatusPass, "", nil }, StatusPass},
		{func(context.Context, *Run) (Status, string, error) { return StatusFail, "", nil }, StatusFail},
		{func(context.Context, *Run) (Status, string, error) { return StatusPass, "", context.Canceled }, StatusError},
		{func(context.Context, *Run) (Status, string, error) { panic("x") }, StatusError},
	}
	for i, c := range cases {
		st, _, err := safeRun(context.Background(), Case{ID: "x", Fn: c.fn}, &Run{})
		if got := classify(st, err); got != c.want {
			t.Errorf("control %d classified %s; want %s", i, got, c.want)
		}
	}
}

func TestRunSelfCheckAndAccounting(t *testing.T) {
	cfg := &Config{Mode: "module", Quiet: true,
		Endpoints:  []Endpoint{{Label: "http", Proto: "tcp", Handler: "http"}, {Label: "ssh", Proto: "tcp", Handler: "ssh"}},
		Categories: []string{"unit"}}
	cfg.ApplyDefaults()
	r, _ := NewRunner(cfg, nil)
	want := len(r.Cases())
	rr, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rr.Info.SelfCheck != "passed" {
		t.Errorf("SelfCheck = %q; want passed", rr.Info.SelfCheck)
	}
	if rr.Info.Expected != want || rr.Info.Recorded != want {
		t.Errorf("accounting: expected=%d recorded=%d; want %d/%d", rr.Info.Expected, rr.Info.Recorded, want, want)
	}
	if !rr.Info.AccountingOK() {
		t.Error("AccountingOK should be true")
	}
	if len(rr.Results) != rr.Info.Recorded {
		t.Errorf("recorded %d != len(results) %d", rr.Info.Recorded, len(rr.Results))
	}
}

func TestCheckDeterministic(t *testing.T) {
	cfg := &Config{Mode: "module",
		Endpoints:  []Endpoint{{Label: "http", Proto: "tcp", Handler: "http"}, {Label: "ftp", Proto: "tcp", Handler: "ftp"}},
		Categories: []string{"unit", "integrity"}}
	cfg.ApplyDefaults()
	r, _ := NewRunner(cfg, nil)
	if err := r.checkDeterministic(); err != nil {
		t.Errorf("case selection should be deterministic: %v", err)
	}
}

func TestInfoLinesShowsHarnessSelfCheck(t *testing.T) {
	rr := &RunResult{}
	rr.Info = RunInfo{Host: HostInfo{OS: "linux"}, SelfCheck: "passed", Expected: 10, Recorded: 10,
		Resources: ResourceStats{Source: "harness (runtime)"}}
	joined := strings.Join(infoLines(rr), "\n")
	if !strings.Contains(joined, "self-check passed") || !strings.Contains(joined, "10/10 results recorded") {
		t.Errorf("infoLines missing harness self-check/accounting line:\n%s", joined)
	}
	// a mismatch is surfaced loudly.
	rr.Info.Recorded = 9
	if !strings.Contains(strings.Join(infoLines(rr), "\n"), "MISMATCH") {
		t.Error("an accounting mismatch should be surfaced")
	}
}

// --- evidence integrity -----------------------------------------------------

func TestIntegrityCasesGenerated(t *testing.T) {
	cfg := &Config{Mode: "module", Endpoints: []Endpoint{
		{Label: "http", Proto: "tcp", Handler: "http"},
		{Label: "ftp", Proto: "tcp", Handler: "ftp"},
		{Label: "ssh", Proto: "tcp", Handler: "ssh"}, // no integrity vector
	}}
	cfg.ApplyDefaults()
	ids := caseIDSet(Select(Build(cfg), nil, []string{"integrity"}))
	for _, want := range []string{
		"integrity/capture/http", "integrity/no-drop-under-load/http",
		"integrity/capture/ftp", "integrity/no-drop-under-load/ftp",
	} {
		if !ids[want] {
			t.Errorf("expected integrity case %q; got %v", want, ids)
		}
	}
	if ids["integrity/capture/ssh"] {
		t.Error("ssh has no capture vector; should not get an integrity case")
	}
}

func TestIntegritySkipsWithoutAPI(t *testing.T) {
	cfg := &Config{Mode: "module", Quiet: true,
		Endpoints:  []Endpoint{{Label: "http", Proto: "tcp", Handler: "http"}},
		Categories: []string{"integrity"}}
	cfg.ApplyDefaults()
	rr, err := mustRunnerRun(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for id, res := range resultsByID(rr) {
		if res.Status != StatusSkip {
			t.Errorf("%s should skip without verify.url; got %s", id, res.Status)
		}
	}
}

func TestMatchMetaContains(t *testing.T) {
	ev := apiEvent{
		Handler: "http",
		Meta: map[string]any{
			"http_path": "/?q=TPHIabc123",
			"nested":    map[string]any{"list": []any{"x", "TPHIdeep"}},
		},
	}
	if !MatchMetaContains("TPHIabc123")(ev) {
		t.Error("should find a marker in a top-level meta string")
	}
	if !MatchMetaContains("TPHIdeep")(ev) {
		t.Error("should find a marker nested in a map/slice")
	}
	if MatchMetaContains("TPHInope")(ev) {
		t.Error("should not match an absent marker")
	}
}

func TestFreshMarkerUnique(t *testing.T) {
	a, b := freshMarker(), freshMarker()
	if a == b {
		t.Error("freshMarker must differ each call (ephemeral correlation token)")
	}
	if !strings.HasPrefix(a, "TPHI") || len(a) < 12 {
		t.Errorf("marker shape unexpected: %q", a)
	}
}
