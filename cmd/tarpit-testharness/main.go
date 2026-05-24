// Command tarpit-testharness is a local QA / reliability harness for the
// tarpit-honeypot sensor. It exercises the complete tool over the network
// (a managed instance it spawns, or an external one) or individual protocol
// handlers in-process, across categorized, individually-selectable test cases:
// unit checks, dumb + smart fuzzing, protocol emulation/compatibility,
// deliberate mis-implementation, port/host/ping/ARP sweeps, and client
// fingerprint triggers. Run it fully automated, quiet, or with progress;
// bound it by rounds or wall-clock time; it retries (restarting the target)
// on failures/crashes, writes reports (text/json/junit/md), and records every
// run + result in a SQLite database keyed by tool version + time.
//
//	tarpit-testharness list   -c harness.yaml
//	tarpit-testharness run     -c harness.yaml --progress
//	tarpit-testharness run --target 127.0.0.1 --endpoint ssh=tcp:2222:ssh --case 'fuzz-*'
//	tarpit-testharness history -db harness-results.db
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rom/tarpit-honeypot/internal/testharness"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = runCmd(os.Args[2:])
	case "list":
		err = listCmd(os.Args[2:])
	case "history":
		err = historyCmd(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tarpit-testharness:", err)
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `tarpit-testharness — QA/reliability harness for tarpit-honeypot

commands:
  run       run selected cases against a target
  list      list the cases that would run for a config/selection
  history   show recent runs recorded in a results database

Run 'tarpit-testharness <command> -h' for flags. Exit code is 0 when there are
no findings, 1 when there are, 2 on a setup error.
`)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

// flags shared by run + list.
type commonFlags struct {
	config     string
	mode       string
	host       string
	endpoints  multiFlag
	cases      multiFlag
	categories multiFlag
}

func (cf *commonFlags) resolve() (*testharness.Config, error) {
	var cfg *testharness.Config
	if cf.config != "" {
		c, err := testharness.Load(cf.config)
		if err != nil {
			return nil, err
		}
		cfg = c
	} else {
		cfg = &testharness.Config{}
	}
	if cf.mode != "" {
		cfg.Mode = cf.mode
	}
	if cf.host != "" {
		cfg.Host = cf.host
	}
	if len(cf.endpoints) > 0 {
		eps, err := parseEndpoints(cf.endpoints)
		if err != nil {
			return nil, err
		}
		cfg.Endpoints = eps
	}
	if len(cf.cases) > 0 {
		cfg.Cases = splitCSV(cf.cases)
	}
	if len(cf.categories) > 0 {
		cfg.Categories = splitCSV(cf.categories)
	}
	cfg.ApplyDefaults()
	return cfg, cfg.Validate()
}

func listCmd(args []string) error {
	fs := newFlagSet("list")
	var cf commonFlags
	bindCommon(fs, &cf)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := cf.resolve()
	if err != nil {
		return err
	}
	r, err := testharness.NewRunner(cfg, nil)
	if err != nil {
		return err
	}
	cases := r.Cases()
	for _, c := range cases {
		fmt.Printf("%-34s %-12s %s\n", c.ID, c.Category, c.Title)
	}
	fmt.Printf("\n%d case(s) selected.\n", len(cases))
	return nil
}

func runCmd(args []string) error {
	fs := newFlagSet("run")
	var cf commonFlags
	bindCommon(fs, &cf)
	binary := fs.String("binary", "", "sensor binary to spawn + manage as the target")
	spawnConfig := fs.String("spawn-config", "", "config passed to the spawned sensor's `run`")
	healthURL := fs.String("health-url", "", "readiness probe URL for the spawned/external target")
	restartCmd := fs.String("restart-cmd", "", "shell command to restart an EXTERNAL target after a crash")
	rounds := fs.Int("rounds", 0, "number of full passes over the cases (0 = config/1)")
	duration := fs.Duration("duration", 0, "wall-clock time bound (0 = run to completion)")
	retries := fs.Int("retries", -1, "per-case retries on fail/crash (-1 = config)")
	timeout := fs.Duration("timeout", 0, "per-exchange I/O timeout")
	concurrency := fs.Int("concurrency", 0, "cases to run in parallel")
	fuzzIter := fs.Int("fuzz-iter", 0, "inputs per fuzz case")
	seed := fs.Int64("seed", 0, "fuzz seed (reproducible; recorded in the report)")
	sweepCIDR := fs.String("sweep-cidr", "", "CIDR for host/ping/ARP sweeps")
	verifyURL := fs.String("verify-url", "", "target web API base URL for detection verification")
	verifyToken := fs.String("verify-token", "", "API auth token")
	quiet := fs.Bool("quiet", false, "no output (run fully in the background)")
	progress := fs.Bool("progress", false, "print a line per case as it completes")
	var reports multiFlag
	fs.Var(&reports, "report", "report as format[=path], repeatable (text|json|junit|md; path '-'/empty = stdout)")
	dbPath := fs.String("db", "", "SQLite results database to append this run to")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := cf.resolve()
	if err != nil {
		return err
	}
	// CLI overrides.
	if *binary != "" {
		cfg.Spawn.Binary = *binary
	}
	if *spawnConfig != "" {
		cfg.Spawn.Config = *spawnConfig
	}
	if *healthURL != "" {
		cfg.Spawn.HealthURL = *healthURL
	}
	if *restartCmd != "" {
		cfg.RestartCmd = *restartCmd
	}
	if *rounds > 0 {
		cfg.Rounds = *rounds
	}
	if *duration > 0 {
		cfg.Duration = testharness.Duration(*duration)
	}
	if *retries >= 0 {
		cfg.Retries = *retries
	}
	if *timeout > 0 {
		cfg.Timeout = testharness.Duration(*timeout)
	}
	if *concurrency > 0 {
		cfg.Concurrency = *concurrency
	}
	if *fuzzIter > 0 {
		cfg.FuzzIterations = *fuzzIter
	}
	if *seed != 0 {
		cfg.Seed = *seed
	}
	if *sweepCIDR != "" {
		cfg.SweepCIDR = *sweepCIDR
	}
	if *verifyURL != "" {
		cfg.Verify.URL = *verifyURL
	}
	if *verifyToken != "" {
		cfg.Verify.Token = *verifyToken
	}
	cfg.Quiet = cfg.Quiet || *quiet
	cfg.Progress = cfg.Progress || *progress
	if len(reports) > 0 {
		cfg.Reports = parseReports(reports)
	}
	if *dbPath != "" {
		cfg.DBPath = *dbPath
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	var out *os.File = os.Stdout
	if cfg.Quiet {
		out = nil
	}
	runner, err := testharness.NewRunner(cfg, out)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rr, err := runner.Run(ctx)
	if err != nil {
		return err
	}

	// Reports: default to a text summary on stdout when none configured and not quiet.
	reps := cfg.Reports
	if len(reps) == 0 && !cfg.Quiet {
		reps = []testharness.ReportCfg{{Format: "text", Path: "-"}}
	}
	if err := testharness.WriteReports(rr, reps); err != nil {
		return err
	}
	if cfg.DBPath != "" {
		db, err := testharness.OpenDB(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("results db: %w", err)
		}
		defer db.Close()
		if _, err := db.Record(rr); err != nil {
			return fmt.Errorf("record run: %w", err)
		}
	}
	if !rr.OK() {
		os.Exit(1) // findings -> non-zero for CI gating
	}
	return nil
}

func historyCmd(args []string) error {
	fs := newFlagSet("history")
	dbPath := fs.String("db", "", "results SQLite database")
	limit := fs.Int("n", 20, "number of recent runs to show")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dbPath == "" {
		return fmt.Errorf("history needs -db <path>")
	}
	db, err := testharness.OpenDB(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.Recent(*limit)
	if err != nil {
		return err
	}
	fmt.Printf("%-5s %-20s %-22s %6s %5s %5s %6s\n", "RUN", "STARTED", "TOOL", "TOTAL", "PASS", "FAIL", "CRASH")
	for _, r := range rows {
		fmt.Printf("%-5d %-20s %-22s %6d %5d %5d %6d\n", r.ID, shortTime(r.Started), trunc(r.ToolVersion, 22), r.Total, r.Pass, r.Fail, r.Crash)
	}
	return nil
}

// shortTime renders a stored RFC3339(Nano) timestamp at second precision for
// the history table; on a parse failure it falls back to the raw value.
func shortTime(s string) string {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.Format("2006-01-02 15:04:05")
	}
	return trunc(s, 20)
}

// --- flag helpers ---

func newFlagSet(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ExitOnError) }

func bindCommon(fs *flag.FlagSet, cf *commonFlags) {
	fs.StringVar(&cf.config, "c", "", "harness YAML config")
	fs.StringVar(&cf.config, "config", "", "harness YAML config")
	fs.StringVar(&cf.mode, "mode", "", "backend: network | module")
	fs.StringVar(&cf.host, "target", "", "target host (network mode)")
	fs.Var(&cf.endpoints, "endpoint", "endpoint label=proto:port[:handler] (repeatable)")
	fs.Var(&cf.cases, "case", "case id / glob / category to run (repeatable, csv ok)")
	fs.Var(&cf.categories, "category", "category filter (repeatable, csv ok)")
}

func parseEndpoints(specs []string) ([]testharness.Endpoint, error) {
	var out []testharness.Endpoint
	for _, raw := range splitCSV(specs) {
		// label=proto:port[:handler]
		eq := strings.IndexByte(raw, '=')
		if eq < 0 {
			return nil, fmt.Errorf("endpoint %q: want label=proto:port[:handler]", raw)
		}
		label, rest := raw[:eq], raw[eq+1:]
		parts := strings.Split(rest, ":")
		if len(parts) < 2 {
			return nil, fmt.Errorf("endpoint %q: want label=proto:port[:handler]", raw)
		}
		ep := testharness.Endpoint{Label: label, Proto: parts[0]}
		p, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("endpoint %q: bad port", raw)
		}
		ep.Port = p
		if len(parts) >= 3 {
			ep.Handler = parts[2]
		}
		out = append(out, ep)
	}
	return out, nil
}

func parseReports(specs []string) []testharness.ReportCfg {
	var out []testharness.ReportCfg
	for _, raw := range splitCSV(specs) {
		format, path := raw, "-"
		if i := strings.IndexByte(raw, '='); i >= 0 {
			format, path = raw[:i], raw[i+1:]
		}
		out = append(out, testharness.ReportCfg{Format: format, Path: path})
	}
	return out
}

func splitCSV(in []string) []string {
	var out []string
	for _, s := range in {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
