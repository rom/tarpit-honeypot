package testharness

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
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
	Info        RunInfo        `json:"info"`
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
		Counts: counts, Info: rr.Info, Results: rr.Results,
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
	case "csv":
		return writeCSV(w, rr)
	case "rtf":
		return writeRTF(w, rr)
	case "pdf":
		return writePDF(w, rr)
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
	if rr.Info.present() {
		fmt.Fprintln(w)
		for _, ln := range infoLines(rr) {
			fmt.Fprintln(w, ln)
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
	if rr.Info.present() {
		fmt.Fprintf(w, "\n## Environment & target\n\n```\n")
		for _, ln := range infoLines(rr) {
			fmt.Fprintln(w, ln)
		}
		fmt.Fprintf(w, "```\n")
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

// --- CSV (spreadsheet-friendly: one row per result) ---

func writeCSV(w io.Writer, rr *RunResult) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"case_id", "category", "endpoint", "round", "attempt", "status", "duration_ms", "started", "detail"}); err != nil {
		return err
	}
	rows := append([]Result(nil), rr.Results...)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CaseID != rows[j].CaseID {
			return rows[i].CaseID < rows[j].CaseID
		}
		return rows[i].Round < rows[j].Round
	})
	for _, r := range rows {
		d := r.Detail
		if r.Err != "" {
			d = r.Err
		}
		if err := cw.Write([]string{
			r.CaseID, string(r.Category), r.Endpoint,
			strconv.Itoa(r.Round), strconv.Itoa(r.Attempt), string(r.Status),
			strconv.FormatInt(r.Duration.Milliseconds(), 10),
			r.Started.Format(time.RFC3339), oneLine(d),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// reportLines renders the human-readable report as plain ASCII lines, shared by
// the RTF and PDF writers so the three stay consistent.
func reportLines(rr *RunResult) []string {
	counts := rr.Counts()
	var ls []string
	add := func(format string, a ...interface{}) { ls = append(ls, fmt.Sprintf(format, a...)) }
	add("tarpit-honeypot test harness report")
	add("  tool      %s", rr.ToolVersion)
	add("  target    %s", rr.Target)
	add("  seed      %d", rr.Seed)
	add("  started   %s", rr.Started.Format(time.RFC3339))
	add("  duration  %s", rr.Duration().Round(time.Millisecond))
	add("  rounds    %d%s", rr.Rounds, boundedNote(rr))
	res := fmt.Sprintf("  results   %d total", len(rr.Results))
	for _, s := range statusOrder() {
		if counts[s] > 0 {
			res += fmt.Sprintf(" | %s %d", s, counts[s])
		}
	}
	ls = append(ls, res, "", "by category:")
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
			add("  %-12s %d run, %d finding(s)", cat, tot, bad)
		}
	}
	if rr.Info.present() {
		ls = append(ls, "")
		ls = append(ls, infoLines(rr)...)
	}
	findings := rr.Findings()
	if len(findings) == 0 {
		return append(ls, "", "No findings.")
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].CaseID < findings[j].CaseID })
	ls = append(ls, "", fmt.Sprintf("FINDINGS (%d):", len(findings)))
	for _, f := range findings {
		d := f.Detail
		if f.Err != "" {
			d = f.Err
		}
		add("  [%s] %s (round %d, %d attempt(s)) - %s", f.Status, f.CaseID, f.Round, f.Attempt, oneLine(d))
	}
	return ls
}

func oneLine(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(s)
}

// --- RTF (opens in Word/Pages/WordPad) ---

func writeRTF(w io.Writer, rr *RunResult) error {
	var b strings.Builder
	// Courier (monospace) so the space-aligned columns line up.
	b.WriteString(`{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0\fmodern Courier New;}}\fs20`)
	b.WriteString("\n")
	for _, ln := range reportLines(rr) {
		b.WriteString(rtfEscape(ln))
		b.WriteString("\\par\n")
	}
	b.WriteString("}")
	_, err := io.WriteString(w, b.String())
	return err
}

func rtfEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\\' || r == '{' || r == '}':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20:
			b.WriteByte(' ')
		case r < 0x80:
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, `\u%d?`, int(r))
		}
	}
	return b.String()
}

// --- PDF (self-contained, no external dependency) ---
//
// A minimal but valid PDF 1.4: a Catalog, a Pages tree, one standard-14 font
// (Courier, no embedding needed), and one Page+Contents object pair per page.
// The cross-reference table carries byte-exact offsets, so the file opens in any
// conformant viewer. Text is laid out with a fixed leading; lines that overflow
// a page roll onto the next.
func writePDF(w io.Writer, rr *RunResult) error {
	const (
		pageW, pageH = 612, 792 // US Letter, in points
		margin       = 50
		fontSize     = 10
		leading      = 12
		topY         = pageH - margin
	)
	maxLines := (topY - margin) / leading

	lines := reportLines(rr)
	var pages [][]string
	for i := 0; i < len(lines); i += maxLines {
		end := i + maxLines
		if end > len(lines) {
			end = len(lines)
		}
		pages = append(pages, lines[i:end])
	}
	if len(pages) == 0 {
		pages = [][]string{{}}
	}

	// Object plan: 1 Catalog, 2 Pages, 3 Font, then for page i: Page=4+2i,
	// Contents=5+2i.
	nPages := len(pages)
	pageObj := func(i int) int { return 4 + 2*i }
	contentObj := func(i int) int { return 5 + 2*i }
	totalObjs := 3 + 2*nPages

	var buf bytes.Buffer
	offsets := make([]int, totalObjs+1) // 1-indexed; [0] is the free object
	writeObj := func(num int, body string) {
		offsets[num] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", num, body)
	}

	buf.WriteString("%PDF-1.4\n")
	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	var kids strings.Builder
	for i := 0; i < nPages; i++ {
		if i > 0 {
			kids.WriteByte(' ')
		}
		fmt.Fprintf(&kids, "%d 0 R", pageObj(i))
	}
	writeObj(2, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kids.String(), nPages))
	writeObj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
	for i, pg := range pages {
		writeObj(pageObj(i), fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>",
			pageW, pageH, contentObj(i)))
		stream := pdfContent(pg, margin, topY, fontSize, leading)
		writeObj(contentObj(i), fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream))
	}

	xrefOff := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", totalObjs+1)
	buf.WriteString("0000000000 65535 f \n")
	for n := 1; n <= totalObjs; n++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[n])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", totalObjs+1, xrefOff)

	_, err := w.Write(buf.Bytes())
	return err
}

func pdfContent(lines []string, x, y, size, leading int) string {
	var b strings.Builder
	b.WriteString("BT\n")
	fmt.Fprintf(&b, "/F1 %d Tf\n", size)
	fmt.Fprintf(&b, "%d %d Td\n", x, y)
	fmt.Fprintf(&b, "%d TL\n", leading)
	for i, ln := range lines {
		if i > 0 {
			b.WriteString("T* ")
		}
		fmt.Fprintf(&b, "(%s) Tj\n", pdfEscape(ln))
	}
	b.WriteString("ET")
	return b.String()
}

func pdfEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' || c == '(' || c == ')':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c > 0x7e:
			b.WriteByte('?')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
