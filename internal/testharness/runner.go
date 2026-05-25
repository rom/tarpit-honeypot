package testharness

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/version"
)

// RunResult is the full outcome of a harness run.
type RunResult struct {
	Started     time.Time
	Finished    time.Time
	Seed        int64
	ToolVersion string
	Target      string
	Rounds      int
	TimeBounded bool     // run stopped because the time bound was hit
	Results     []Result // the final result of every (case, round) that ran
	Info        RunInfo  // before/during/after context about the run + target
}

// Duration is the wall-clock run time.
func (rr *RunResult) Duration() time.Duration { return rr.Finished.Sub(rr.Started) }

// Counts tallies results by status.
func (rr *RunResult) Counts() map[Status]int {
	m := map[Status]int{}
	for _, r := range rr.Results {
		m[r.Status]++
	}
	return m
}

// Findings returns the results with a bad status (the actionable output).
func (rr *RunResult) Findings() []Result {
	var out []Result
	for _, r := range rr.Results {
		if r.Status.Bad() {
			out = append(out, r)
		}
	}
	return out
}

// OK reports whether the run had no findings.
func (rr *RunResult) OK() bool { return len(rr.Findings()) == 0 }

// Runner executes selected cases against a target.
type Runner struct {
	cfg    *Config
	target *Target
	api    *APIClient
	out    io.Writer
}

// NewRunner wires a runner (target + optional API verifier).
func NewRunner(cfg *Config, out io.Writer) (*Runner, error) {
	t, err := NewTarget(cfg)
	if err != nil {
		return nil, err
	}
	var api *APIClient
	if cfg.Verify.URL != "" {
		api = NewAPIClient(cfg.Verify.URL, cfg.Verify.Token)
	}
	return &Runner{cfg: cfg, target: t, api: api, out: out}, nil
}

// Cases returns the selected, expanded case list (for `list`).
func (r *Runner) Cases() []Case {
	return Select(Build(r.cfg), r.cfg.Cases, r.cfg.Categories)
}

// Run executes the selected cases for the configured rounds / time bound.
func (r *Runner) Run(ctx context.Context) (*RunResult, error) {
	cases := r.Cases()
	if len(cases) == 0 {
		return nil, fmt.Errorf("no test cases selected (check --cases / --categories / endpoints)")
	}
	rr := &RunResult{
		Started:     time.Now(),
		Seed:        r.cfg.Seed,
		ToolVersion: version.Version + " (" + version.Commit + ")",
		Rounds:      r.cfg.Rounds,
		Target:      r.describeTarget(),
	}
	if err := r.target.Start(ctx); err != nil {
		return nil, fmt.Errorf("start target: %w", err)
	}
	if r.target.Managed() {
		defer r.target.Stop()
	}
	r.logf("harness: %d case(s) × %d round(s) against %s (seed %d)", len(cases), r.cfg.Rounds, rr.Target, r.cfg.Seed)

	// before: provenance + environment + a baseline snapshot of each endpoint;
	// during: a resource sampler runs for the length of the run.
	rr.Info.Host = hostInfo()
	rr.Info.Config = configSummary(r.cfg)
	if r.target.Managed() {
		rr.Info.Binary = binaryInfo(r.cfg.Spawn.Binary)
	}
	rr.Info.Baseline = snapshotEndpoints(ctx, r.target, r.cfg)
	sampler := startSampler(r.target.PID)

	var deadline time.Time
	if r.cfg.Duration > 0 {
		deadline = rr.Started.Add(r.cfg.Duration.D())
	}
	total := len(cases) * r.cfg.Rounds
	var mu sync.Mutex
	done := 0
	stop := false

	for round := 1; round <= r.cfg.Rounds && !stop; round++ {
		sem := make(chan struct{}, r.cfg.Concurrency)
		var wg sync.WaitGroup
		for _, c := range cases {
			if !deadline.IsZero() && time.Now().After(deadline) {
				stop = true
				break
			}
			if ctx.Err() != nil {
				stop = true
				break
			}
			c, round := c, round
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				res := r.runCase(ctx, c, round, deadline)
				mu.Lock()
				rr.Results = append(rr.Results, res)
				done++
				r.progress(done, total, res)
				mu.Unlock()
			}()
		}
		wg.Wait()
	}
	rr.Finished = time.Now()
	rr.TimeBounded = stop && !deadline.IsZero()
	// after: close the resource envelope, snapshot the endpoints again (drift /
	// went-dark), and record how the run ended.
	rr.Info.Resources = sampler.Stop()
	rr.Info.Final = snapshotEndpoints(ctx, r.target, r.cfg)
	rr.Info.StoppedHow = r.stoppedHow(ctx, stop, deadline)
	return rr, nil
}

func (r *Runner) stoppedHow(ctx context.Context, stopped bool, deadline time.Time) string {
	switch {
	case ctx.Err() != nil:
		return "interrupted: " + ctx.Err().Error()
	case stopped && !deadline.IsZero():
		return "stopped at time bound"
	default:
		s := "completed all rounds"
		if r.target.Managed() {
			if exited, how := r.target.procExited(); exited {
				s += "; WARNING: target process had exited (" + how + ")"
			}
		}
		return s
	}
}

// runCase executes one case with retry+restart on a bad outcome.
func (r *Runner) runCase(ctx context.Context, c Case, round int, deadline time.Time) Result {
	retries := r.cfg.CaseRetries(c.ID)
	var res Result
	for attempt := 1; attempt <= retries+1; attempt++ {
		if (!deadline.IsZero() && time.Now().After(deadline)) || ctx.Err() != nil {
			return Result{CaseID: c.ID, Category: c.Category, Endpoint: c.Endpoint, Round: round, Attempt: attempt, Status: StatusSkip, Detail: "time bound reached", Started: time.Now()}
		}
		start := time.Now()
		cctx, cancel := context.WithTimeout(ctx, r.caseTimeout())
		st, detail, err := safeRun(cctx, c, &Run{Target: r.target, Cfg: r.cfg, API: r.api, Round: round, Attempt: attempt})
		cancel()
		res = Result{CaseID: c.ID, Category: c.Category, Endpoint: c.Endpoint, Round: round, Attempt: attempt, Started: start, Duration: time.Since(start), Status: st, Detail: detail}
		if err != nil {
			res.Status, res.Err = StatusError, err.Error()
		}
		// A bad outcome on a non-scan case may mean the target itself died:
		// re-check liveness and reclassify as a crash so the report is honest.
		if res.Status.Bad() && c.Category != CatScan && !r.target.Alive(ctx) {
			res.Status = StatusCrash
			if res.Detail == "" {
				res.Detail = "target unresponsive after this case"
			}
		}
		if !res.Status.Bad() {
			break
		}
		if attempt <= retries {
			if rerr := r.target.Restart(ctx); rerr != nil {
				r.logf("  ! restart failed before retry of %s: %v", c.ID, rerr)
			} else {
				r.logf("  ↻ restarted target; retrying %s (attempt %d/%d)", c.ID, attempt+1, retries+1)
			}
		}
	}
	return res
}

func safeRun(ctx context.Context, c Case, run *Run) (st Status, detail string, err error) {
	defer func() {
		if p := recover(); p != nil {
			st, err = StatusError, fmt.Errorf("case panic: %v", p)
		}
	}()
	return c.Fn(ctx, run)
}

// caseTimeout caps a single case so a hung target can't block the run; cases
// also enforce their own (shorter) per-exchange timeout.
func (r *Runner) caseTimeout() time.Duration {
	t := time.Duration(r.cfg.FuzzIterations+8) * r.cfg.Timeout.D() * 2
	if t < 2*time.Minute {
		t = 2 * time.Minute
	}
	return t
}

func (r *Runner) logf(format string, args ...any) {
	if r.cfg.Quiet || r.out == nil {
		return
	}
	fmt.Fprintf(r.out, format+"\n", args...)
}

func (r *Runner) progress(done, total int, res Result) {
	if r.cfg.Quiet || r.out == nil {
		return
	}
	mark := map[Status]string{StatusPass: "✓", StatusFail: "✗", StatusError: "‼", StatusSkip: "·", StatusCrash: "☠"}[res.Status]
	if r.cfg.Progress {
		extra := res.Detail
		if res.Err != "" {
			extra = res.Err
		}
		if res.Attempt > 1 {
			extra = fmt.Sprintf("(after %d attempts) %s", res.Attempt, extra)
		}
		fmt.Fprintf(r.out, "[%d/%d] %s %-6s %s %s\n", done, total, mark, res.Status, res.CaseID, extra)
		return
	}
	if res.Status.Bad() { // default mode: only surface problems
		d := res.Detail
		if res.Err != "" {
			d = res.Err
		}
		fmt.Fprintf(r.out, "%s %-6s %s — %s\n", mark, res.Status, res.CaseID, d)
	}
}

func (r *Runner) describeTarget() string {
	switch {
	case r.cfg.Mode == "module":
		return "module (in-process handlers)"
	case r.target.Managed():
		return fmt.Sprintf("managed %s (network)", r.cfg.Spawn.Binary)
	default:
		return fmt.Sprintf("external %s (network)", r.cfg.Host)
	}
}
