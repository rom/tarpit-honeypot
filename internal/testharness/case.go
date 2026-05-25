// Package testharness is a local QA / reliability harness that exercises the
// tarpit-honeypot sensor — either the complete tool over the network (a
// managed instance the harness spawns, or an external one) or individual
// protocol-handler modules in-process. Every test case has a stable id and is
// individually selectable; categories cover unit checks, dumb/smart fuzzing,
// protocol emulation/compatibility, deliberate mis-implementation, port/host
// sweeps, and client-fingerprint triggers. The runner tracks per-case state,
// retries (with target restart) on failure/crash, is rounds- and time-bounded,
// runs quiet or with progress, and writes reports + a results database.
package testharness

import (
	"context"
	"path"
	"sort"
	"strings"
	"time"
)

// Category groups related test cases.
type Category string

const (
	CatUnit        Category = "unit"        // is the port open / does the decoy answer plausibly
	CatFuzzDumb    Category = "fuzz-dumb"   // protocol-unaware random input
	CatFuzzSmart   Category = "fuzz-smart"  // protocol-aware malformed input
	CatEmulate     Category = "emulate"     // speak the protocol; is the emulation compatible
	CatMisimpl     Category = "misimpl"     // send wrong framing; is it detected
	CatScan        Category = "scan"        // port scans / host & ping sweeps
	CatFingerprint Category = "fingerprint" // trigger tool/scanner detection
	CatReliability Category = "reliability" // soak / liveness / resource checks
	CatResilience  Category = "resilience"  // abuse/overload: the sensor must not be the victim
	CatContainment Category = "containment" // do-no-harm: no egress / relay / traversal leak
	CatIntegrity   Category = "integrity"   // evidence integrity: did the sensor faithfully record it
)

// AllCategories is the canonical category order (for listing + reports).
func AllCategories() []Category {
	return []Category{CatUnit, CatEmulate, CatMisimpl, CatFuzzDumb, CatFuzzSmart, CatScan, CatFingerprint, CatReliability, CatResilience, CatContainment, CatIntegrity}
}

// Status is the outcome of one case execution attempt.
type Status string

const (
	StatusPass  Status = "pass"  // expected behavior
	StatusFail  Status = "fail"  // a target finding (bug / incompatibility / missed detection)
	StatusError Status = "error" // harness/setup problem, not a target defect
	StatusSkip  Status = "skip"  // not applicable (e.g. needs privileges)
	StatusCrash Status = "crash" // target stopped responding / process died
)

// Bad reports whether a status indicates a problem worth surfacing.
func (s Status) Bad() bool { return s == StatusFail || s == StatusCrash || s == StatusError }

// Result is the final outcome of one case for one round (after any retries).
type Result struct {
	CaseID   string        `json:"case_id"`
	Category Category      `json:"category"`
	Endpoint string        `json:"endpoint,omitempty"`
	Round    int           `json:"round"`
	Attempt  int           `json:"attempts"` // attempts taken (1 = first try)
	Status   Status        `json:"status"`
	Detail   string        `json:"detail,omitempty"`
	Err      string        `json:"error,omitempty"`
	Started  time.Time     `json:"started"`
	Duration time.Duration `json:"duration_ns"`
}

// Case is a single, individually-identified test.
type Case struct {
	// ID is unique and stable, e.g. "fuzz-dumb/ssh-22" or "scan/portscan-seq".
	ID       string
	Category Category
	Title    string
	// Endpoint is the configured endpoint label this case targets, or "" for
	// whole-target cases (scans). Used to report what was being exercised.
	Endpoint string
	// Fn runs the case. A non-pass Status with a nil error is a finding about
	// the target; a returned error is a harness error (StatusError). Fn must
	// honor ctx for the time bound and per-case timeout.
	Fn func(ctx context.Context, r *Run) (Status, string, error)
}

// Generator yields the concrete cases for a resolved config (e.g. one fuzz
// case per configured endpoint). Registered by each category file's init().
type Generator func(cfg *Config) []Case

var generators []genEntry

type genEntry struct {
	cat Category
	gen Generator
}

// RegisterGen registers a case generator for a category. Called from init().
func RegisterGen(cat Category, g Generator) {
	generators = append(generators, genEntry{cat: cat, gen: g})
}

// Build expands every registered generator into concrete cases for cfg, sorted
// by id. Duplicate ids are dropped (first wins) so the set is recallable.
func Build(cfg *Config) []Case {
	seen := map[string]bool{}
	var out []Case
	for _, ge := range generators {
		for _, c := range ge.gen(cfg) {
			if c.ID == "" || seen[c.ID] {
				continue
			}
			if c.Category == "" {
				c.Category = ge.cat
			}
			seen[c.ID] = true
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Select filters cases by id selectors (exact id, glob via path.Match against
// the id or — for a slash-free glob like "fuzz-*" — the category, an id prefix,
// or a bare category name) and an explicit category allow-list. Empty selectors
// / categories mean "no filter on that axis".
func Select(cases []Case, selectors []string, cats []string) []Case {
	catSet := map[string]bool{}
	for _, c := range cats {
		catSet[strings.ToLower(strings.TrimSpace(c))] = true
	}
	var out []Case
	for _, c := range cases {
		if len(catSet) > 0 && !catSet[string(c.Category)] {
			continue
		}
		if len(selectors) > 0 && !matchAny(c, selectors) {
			continue
		}
		out = append(out, c)
	}
	return out
}

func matchAny(c Case, selectors []string) bool {
	for _, sel := range selectors {
		sel = strings.TrimSpace(sel)
		if sel == "" {
			continue
		}
		if sel == c.ID || sel == string(c.Category) {
			return true
		}
		if ok, _ := path.Match(sel, c.ID); ok {
			return true
		}
		// A glob with no '/' (e.g. "fuzz-*") matches by category, since
		// path.Match's '*' does not cross the '/' in a case id.
		if !strings.Contains(sel, "/") {
			if ok, _ := path.Match(sel, string(c.Category)); ok {
				return true
			}
		}
		if strings.HasSuffix(sel, "/") && strings.HasPrefix(c.ID, sel) {
			return true
		}
		// "cat/*" style without the trailing-slash convenience
		if strings.HasPrefix(c.ID, sel+"/") {
			return true
		}
	}
	return false
}

// Run carries per-execution context handed to each Case.Fn.
type Run struct {
	Target  *Target
	Cfg     *Config
	API     *APIClient // optional detection-verification client (nil if unconfigured)
	Round   int
	Attempt int
	// now is overridable in tests; defaults to time.Now.
	now func() time.Time
}

// Now returns the run's clock.
func (r *Run) Now() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}
