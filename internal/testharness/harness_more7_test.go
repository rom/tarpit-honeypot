package testharness

// A seventh batch, focused on the CSV / RTF / PDF report writers added so the
// run report can be consumed in spreadsheets, word processors, and as a
// self-contained printable document — plus the config/validation and
// multi-format plumbing that exposes them.

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sampleRR() *RunResult {
	start := time.Now().Add(-2 * time.Second)
	return &RunResult{
		Started: start, Finished: start.Add(2 * time.Second), Seed: 99, Rounds: 2,
		ToolVersion: "v1.2.3 (abc1234)", Target: "external 127.0.0.1",
		Results: []Result{
			{CaseID: "unit/banner/ssh", Category: CatUnit, Endpoint: "ssh", Round: 1, Attempt: 1, Status: StatusPass, Duration: 5 * time.Millisecond, Started: start},
			{CaseID: "fuzz-dumb/http", Category: CatFuzzDumb, Endpoint: "http", Round: 1, Attempt: 2, Status: StatusFail, Detail: "boom, with \"quotes\", a comma, and\na newline", Duration: 12 * time.Millisecond, Started: start},
			{CaseID: "scan/portscan", Category: CatScan, Round: 2, Attempt: 1, Status: StatusCrash, Err: "target died: (oops) \\ {brace}", Duration: time.Second, Started: start},
		},
	}
}

// --- CSV ---------------------------------------------------------------------

func TestWriteCSVParseable(t *testing.T) {
	var b bytes.Buffer
	if err := writeCSV(&b, sampleRR()); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(bytes.NewReader(b.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("CSV is not parseable: %v", err)
	}
	if len(recs) != 4 { // header + 3 rows
		t.Fatalf("CSV rows = %d; want 4 (header + 3 results)", len(recs))
	}
	wantHdr := []string{"case_id", "category", "endpoint", "round", "attempt", "status", "duration_ms", "started", "detail"}
	if strings.Join(recs[0], ",") != strings.Join(wantHdr, ",") {
		t.Errorf("CSV header = %v; want %v", recs[0], wantHdr)
	}
	// rows are sorted by case id; fuzz-dumb/http comes first and carries the
	// finding detail with embedded comma/quote/newline that csv must round-trip.
	if recs[1][0] != "fuzz-dumb/http" {
		t.Errorf("CSV first data row case = %q; want fuzz-dumb/http", recs[1][0])
	}
	detail := recs[1][8]
	if !strings.Contains(detail, "boom") || !strings.Contains(detail, "quotes") || !strings.Contains(detail, "comma") {
		t.Errorf("CSV detail lost content through quoting: %q", detail)
	}
	if strings.ContainsAny(detail, "\n\r") {
		t.Errorf("CSV detail should be collapsed to one line: %q", detail)
	}
	if recs[1][6] != "12" { // duration_ms
		t.Errorf("CSV duration_ms = %q; want 12", recs[1][6])
	}
}

func TestWriteCSVEmpty(t *testing.T) {
	var b bytes.Buffer
	rr := &RunResult{Started: time.Now(), Finished: time.Now(), Rounds: 1}
	if err := writeCSV(&b, rr); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&b).ReadAll()
	if err != nil || len(recs) != 1 {
		t.Errorf("an empty run should still emit a header row only: %d recs, err=%v", len(recs), err)
	}
}

// --- RTF ---------------------------------------------------------------------

func TestWriteRTFWellFormed(t *testing.T) {
	var b bytes.Buffer
	if err := writeRTF(&b, sampleRR()); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.HasPrefix(s, `{\rtf1`) {
		t.Errorf("RTF must start with the {\\rtf1 header; got %.16q", s)
	}
	if !strings.HasSuffix(s, "}") {
		t.Error("RTF must end with a closing brace")
	}
	if strings.Count(s, "{") != strings.Count(s, "}") {
		t.Errorf("RTF braces unbalanced: %d open vs %d close", strings.Count(s, "{"), strings.Count(s, "}"))
	}
	if !strings.Contains(s, "FINDINGS") || !strings.Contains(s, "fuzz-dumb/http") {
		t.Error("RTF should carry the findings section")
	}
	// the crash Err carries a literal backslash and braces — they must be escaped
	// so they don't corrupt the control stream.
	if !strings.Contains(s, `\\`) || !strings.Contains(s, `\{brace\}`) {
		t.Errorf("RTF did not escape backslash/brace in detail:\n%s", s)
	}
}

func TestRTFEscape(t *testing.T) {
	got := rtfEscape("a\\b{c}d\te" + string(rune(0x2014)) + "f") // em dash
	if strings.Contains(got, "\t") {
		t.Error("control chars should be replaced")
	}
	if !strings.Contains(got, `a\\b\{c\}d`) {
		t.Errorf("specials not escaped: %q", got)
	}
	want := "\\u" + strconv.Itoa(0x2014) + "?" // em dash -> \uNNNN?
	if !strings.Contains(got, want) {
		t.Errorf("non-ASCII rune not unicode-escaped: %q", got)
	}
}

// --- PDF ---------------------------------------------------------------------

func TestWritePDFStructure(t *testing.T) {
	var b bytes.Buffer
	if err := writePDF(&b, sampleRR()); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.HasPrefix(s, "%PDF-") {
		t.Errorf("PDF must start with %%PDF-; got %.8q", s)
	}
	if !strings.HasSuffix(s, "%%EOF\n") {
		t.Error("PDF must end with the EOF marker")
	}
	for _, want := range []string{"/Catalog", "/Pages", "/Font", "/BaseFont /Courier", "xref", "trailer", "startxref", "/Root 1 0 R"} {
		if !strings.Contains(s, want) {
			t.Errorf("PDF missing %q", want)
		}
	}
	if !strings.Contains(s, "tarpit-honeypot test harness report") {
		t.Error("PDF body text missing")
	}
	// parens and backslash in detail must be escaped for a literal string; braces
	// are legal inside one and are kept verbatim.
	if !strings.Contains(s, `\(oops\)`) || !strings.Contains(s, `\\ {brace}`) {
		t.Errorf("PDF did not escape parens / backslash in detail:\n%s", s)
	}
}

// TestWritePDFXrefOffsets checks that the cross-reference table points at real
// object headers — the part most likely to silently corrupt a hand-rolled PDF.
func TestWritePDFXrefOffsets(t *testing.T) {
	var b bytes.Buffer
	if err := writePDF(&b, sampleRR()); err != nil {
		t.Fatal(err)
	}
	data := b.Bytes()
	s := string(data)

	// startxref offset must point at the "xref" keyword.
	i := strings.LastIndex(s, "startxref")
	if i < 0 {
		t.Fatal("no startxref")
	}
	after := strings.TrimLeft(s[i+len("startxref"):], "\r\n")
	numStr := after[:strings.IndexAny(after, "\r\n")]
	xrefAt, err := strconv.Atoi(strings.TrimSpace(numStr))
	if err != nil {
		t.Fatalf("startxref value unparseable: %v", err)
	}
	if xrefAt < 0 || xrefAt >= len(data) || !bytes.HasPrefix(data[xrefAt:], []byte("xref")) {
		t.Fatalf("startxref %d does not point at the xref table", xrefAt)
	}

	// each "NNNNNNNNNN ..... n" entry must point at "<obj> 0 obj".
	objNum := 0
	for _, ln := range strings.Split(s[xrefAt:], "\n") {
		trimmed := strings.TrimRight(ln, " ")
		if len(ln) < 18 || !strings.HasSuffix(trimmed, "n") {
			continue
		}
		off, err := strconv.Atoi(ln[:10])
		if err != nil {
			continue
		}
		objNum++
		if off <= 0 || off >= len(data) {
			continue
		}
		prefix := []byte(strconv.Itoa(objNum) + " 0 obj")
		if !bytes.HasPrefix(data[off:], prefix) {
			t.Errorf("xref entry for obj %d -> offset %d does not begin %q", objNum, off, prefix)
		}
	}
	if objNum == 0 {
		t.Error("no in-use xref entries parsed")
	}
}

func TestWritePDFPaginates(t *testing.T) {
	// enough findings to force more than one page.
	rr := &RunResult{Started: time.Now(), Finished: time.Now(), Rounds: 1, ToolVersion: "v", Target: "t"}
	for i := 0; i < 300; i++ {
		rr.Results = append(rr.Results, Result{CaseID: "fuzz-dumb/case-" + strconv.Itoa(i), Category: CatFuzzDumb, Round: 1, Attempt: 1, Status: StatusFail, Detail: "finding"})
	}
	var b bytes.Buffer
	if err := writePDF(&b, rr); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if n := strings.Count(s, "/Type /Page "); n < 2 {
		t.Errorf("a 300-finding report should span multiple pages; got %d Page object(s)", n)
	}
	if !strings.Contains(s, "/Count ") {
		t.Error("missing /Count on the Pages node")
	}
}

// --- config + multi-format plumbing -----------------------------------------

func TestConfigValidateNewFormats(t *testing.T) {
	for _, f := range []string{"csv", "rtf", "pdf"} {
		c := &Config{Mode: "network", Host: "127.0.0.1",
			Endpoints: []Endpoint{{Label: "a", Proto: "tcp", Port: 22, Handler: "ssh"}},
			Reports:   []ReportCfg{{Format: f, Path: "x"}}}
		c.ApplyDefaults()
		if err := c.Validate(); err != nil {
			t.Errorf("format %q should be accepted, got %v", f, err)
		}
	}
}

func TestWriteReportsAllFormats(t *testing.T) {
	dir := t.TempDir()
	reps := []ReportCfg{
		{Format: "text", Path: filepath.Join(dir, "r.txt")},
		{Format: "json", Path: filepath.Join(dir, "r.json")},
		{Format: "junit", Path: filepath.Join(dir, "r.xml")},
		{Format: "md", Path: filepath.Join(dir, "r.md")},
		{Format: "csv", Path: filepath.Join(dir, "r.csv")},
		{Format: "rtf", Path: filepath.Join(dir, "r.rtf")},
		{Format: "pdf", Path: filepath.Join(dir, "r.pdf")},
	}
	if err := WriteReports(sampleRR(), reps); err != nil {
		t.Fatalf("WriteReports: %v", err)
	}
	for _, rep := range reps {
		fi, err := os.Stat(rep.Path)
		if err != nil || fi.Size() == 0 {
			t.Errorf("%s report missing/empty: %v", rep.Format, err)
		}
	}
}

func TestReportLinesShared(t *testing.T) {
	ls := reportLines(sampleRR())
	joined := strings.Join(ls, "\n")
	for _, want := range []string{"tarpit-honeypot test harness report", "seed      99", "FINDINGS (2)", "fuzz-dumb/http"} {
		if !strings.Contains(joined, want) {
			t.Errorf("reportLines missing %q:\n%s", want, joined)
		}
	}
	for _, ln := range ls {
		if strings.ContainsAny(ln, "\n\r") {
			t.Errorf("a report line must not contain embedded newlines: %q", ln)
		}
	}
}
