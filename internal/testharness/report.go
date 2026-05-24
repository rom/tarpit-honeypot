package testharness

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Report is the JSON/structured form of a run.
type Report struct {
	ToolVersion string         `json:"tool_version"`
	Target      string         `json:"target"`
	Seed        int64          `json:"seed"`
	Started     time.Time      `json:"started"`
	Finished    time.Time      `json:"finished"`
	DurationMs  int64          `json:"duration_ms"`
	Rounds      int            `json:"rounds"`
	TimeBounded bool           `json:"time_bounded"`
	Total       int            `json:"total"`
	Counts      map[string]int `json:"counts"`
	Results     []Result       `json:"results"`
}

func toReport(rr *RunResult) Report {
	counts := map[string]int{}
	for s, n := range rr.Counts() {
		counts[string(s)] = n
	}
	return Report{
		ToolVersion: rr.ToolVersion, Target: rr.Target, Seed: rr.Seed,
		Started: rr.Started, Finished: rr.Finished, DurationMs: rr.Duration().Milliseconds(),
		Rounds: rr.Rounds, TimeBounded: rr.TimeBounded, Total: len(rr.Results),
		Counts: counts, Results: rr.Results,
	}
}

// WriteReports writes every configured report.
func WriteReports(rr *RunResult, reps []ReportCfg) error {
	for _, rep := range reps {
		if err := writeReport(rr, rep); err != nil {
			return fmt.Errorf("report %s -> %s: %w", rep.Format, rep.Path, err)
		}
	}
	return nil
}

func writeReport(rr *RunResult, rep ReportCfg) error {
	var w io.Writer
	if rep.Path == "" || rep.Path == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(rep.Path)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	switch rep.Format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(toReport(rr))
	case "junit":
		return writeJUnit(w, rr)
	case "md":
		return writeMarkdown(w, rr)
	default:
		return writeText(w, rr)
	}
}

func statusOrder() []Status {
	return []Status{StatusPass, StatusFail, StatusCrash, StatusError, StatusSkip}
}

func writeText(w io.Writer, rr *RunResult) error {
	counts := rr.Counts()
	fmt.Fprintf(w, "tarpit-honeypot test harness report\n")
	fmt.Fprintf(w, "  tool      %s\n  target    %s\n  seed      %d\n  started   %s\n  duration  %s\n  rounds    %d%s\n",
		rr.ToolVersion, rr.Target, rr.Seed, rr.Started.Format(time.RFC3339), rr.Duration().Round(time.Millisecond), rr.Rounds, boundedNote(rr))
	fmt.Fprintf(w, "  results   %d total", len(rr.Results))
	for _, s := range statusOrder() {
		if counts[s] > 0 {
			fmt.Fprintf(w, " · %s %d", s, counts[s])
		}
	}
	fmt.Fprintln(w)
	// per-category tally
	fmt.Fprintln(w, "\nby category:")
	for _, cat := range AllCategories() {
		var tot, bad int
		for _, r := range rr.Results {
			if r.Category == cat {
				tot++
				if r.Status.Bad() {
					bad++
				}
			}
		}
		if tot > 0 {
			fmt.Fprintf(w, "  %-12s %d run, %d finding(s)\n", cat, tot, bad)
		}
	}
	findings := rr.Findings()
	if len(findings) == 0 {
		fmt.Fprintln(w, "\nNo findings. ✓")
		return nil
	}
	fmt.Fprintf(w, "\nFINDINGS (%d):\n", len(findings))
	sort.Slice(findings, func(i, j int) bool { return findings[i].CaseID < findings[j].CaseID })
	for _, f := range findings {
		d := f.Detail
		if f.Err != "" {
			d = f.Err
		}
		fmt.Fprintf(w, "  [%s] %s (round %d, %d attempt(s)) — %s\n", f.Status, f.CaseID, f.Round, f.Attempt, d)
	}
	return nil
}

func boundedNote(rr *RunResult) string {
	if rr.TimeBounded {
		return " (stopped at time bound)"
	}
	return ""
}

func writeMarkdown(w io.Writer, rr *RunResult) error {
	counts := rr.Counts()
	fmt.Fprintf(w, "# tarpit-honeypot test harness report\n\n")
	fmt.Fprintf(w, "| | |\n|---|---|\n")
	fmt.Fprintf(w, "| Tool | %s |\n| Target | %s |\n| Seed | %d |\n| Started | %s |\n| Duration | %s |\n| Rounds | %d%s |\n| Total | %d |\n",
		rr.ToolVersion, rr.Target, rr.Seed, rr.Started.Format(time.RFC3339), rr.Duration().Round(time.Millisecond), rr.Rounds, boundedNote(rr), len(rr.Results))
	fmt.Fprintf(w, "\n## Results\n\n| Status | Count |\n|---|---|\n")
	for _, s := range statusOrder() {
		if counts[s] > 0 {
			fmt.Fprintf(w, "| %s | %d |\n", s, counts[s])
		}
	}
	findings := rr.Findings()
	fmt.Fprintf(w, "\n## Findings (%d)\n\n", len(findings))
	if len(findings) == 0 {
		fmt.Fprintln(w, "None. ✓")
		return nil
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].CaseID < findings[j].CaseID })
	fmt.Fprintf(w, "| Status | Case | Round | Attempts | Detail |\n|---|---|---|---|---|\n")
	for _, f := range findings {
		d := f.Detail
		if f.Err != "" {
			d = f.Err
		}
		fmt.Fprintf(w, "| %s | `%s` | %d | %d | %s |\n", f.Status, f.CaseID, f.Round, f.Attempt, strings.ReplaceAll(d, "|", "\\|"))
	}
	return nil
}

// --- JUnit XML (for CI) ---

type junitSuites struct {
	XMLName xml.Name     `xml:"testsuites"`
	Suites  []junitSuite `xml:"testsuite"`
}
type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Time     float64     `xml:"time,attr"`
	Cases    []junitCase `xml:"testcase"`
}
type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *junitMsg     `xml:"failure,omitempty"`
	Error     *junitMsg     `xml:"error,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}
type junitMsg struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}
type junitSkipped struct {
	Message string `xml:"message,attr"`
}

func writeJUnit(w io.Writer, rr *RunResult) error {
	suite := junitSuite{Name: "tarpit-honeypot", Tests: len(rr.Results), Time: rr.Duration().Seconds()}
	for _, r := range rr.Results {
		jc := junitCase{Name: r.CaseID, Classname: string(r.Category), Time: r.Duration.Seconds()}
		msg := r.Detail
		if r.Err != "" {
			msg = r.Err
		}
		switch r.Status {
		case StatusFail, StatusCrash:
			suite.Failures++
			jc.Failure = &junitMsg{Message: string(r.Status), Body: msg}
		case StatusError:
			suite.Errors++
			jc.Error = &junitMsg{Message: "error", Body: msg}
		case StatusSkip:
			suite.Skipped++
			jc.Skipped = &junitSkipped{Message: msg}
		}
		suite.Cases = append(suite.Cases, jc)
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(junitSuites{Suites: []junitSuite{suite}}); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
