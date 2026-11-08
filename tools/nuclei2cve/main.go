// Command nuclei2cve converts Nuclei vulnerability templates into tarpit-honeypot
// CVE catalog records.
//
// The honeypot's internal/cve catalog matches attacker payloads against a
// per-CVE set of high-signal exploit substrings (see internal/cve/cve.go). Nuclei
// templates already encode, per CVE, exactly the request an exploitation attempt
// sends — its distinctive URL path / query. This tool extracts that static,
// high-signal portion and emits ready-to-compile Go Record literals (or JSON),
// so future catalog expansions are a repeatable data-conversion step rather than
// hand transcription.
//
// Typical use:
//
//	# All CVE templates under a Nuclei checkout, skipping ones already catalogued:
//	nuclei2cve -templates ~/nuclei-templates/http/cves -have have.txt \
//	    -var cveKEVAuto2026 > internal/cve/cve_kev_auto.go
//
//	# Only CISA-KEV ("actually exploited") CVEs, as JSON:
//	nuclei2cve -templates ~/nuclei-templates -kev kev.json -format json
//
// It is intentionally dependency-light (only gopkg.in/yaml.v3, already a project
// dependency) and reads templates as untrusted data: no template is executed,
// only parsed for its declared request path.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Record mirrors the exported fields of internal/cve.Record that this tool
// populates. (Enrichment fields — CWE/CPE/EPSS — are left to the catalog's
// separate cveExtra cross-reference and are not emitted here.)
type Record struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	CVSS        float64  `json:"cvss"`
	Service     string   `json:"service"`
	Signatures  []string `json:"signatures"`
	Technique   string   `json:"technique"`
	Tactic      string   `json:"tactic"`
	Description string   `json:"description"`
}

// options controls a conversion run.
type options struct {
	templates   string
	kev         string
	have        string
	service     string
	varName     string
	format      string
	maxSigs     int
	minSevCVSS  float64
	keepGeneric bool
}

func main() {
	var o options
	flag.StringVar(&o.templates, "templates", "", "directory of Nuclei templates to scan recursively for CVE-*.yaml (required)")
	flag.StringVar(&o.kev, "kev", "", "optional CISA KEV JSON feed; when set, only CVEs present in it are emitted (and names/descriptions prefer CISA's wording)")
	flag.StringVar(&o.have, "have", "", "optional file of CVE IDs already in the catalog (one per line); these are skipped")
	flag.StringVar(&o.service, "service", "http", "Service field for every emitted record")
	flag.StringVar(&o.varName, "var", "cveGenerated", "Go slice variable name (-format go)")
	flag.StringVar(&o.format, "format", "go", "output format: go | json")
	flag.IntVar(&o.maxSigs, "max-sigs", 3, "maximum signatures kept per CVE")
	flag.Float64Var(&o.minSevCVSS, "min-cvss", 0, "drop records whose derived CVSS is below this")
	flag.BoolVar(&o.keepGeneric, "keep-generic", false, "keep over-generic paths (/login, /api, …) that normally hurt match precision")
	out := flag.String("out", "", "output file (default: stdout)")
	flag.Parse()

	if o.templates == "" {
		fmt.Fprintln(os.Stderr, "nuclei2cve: -templates is required")
		flag.Usage()
		os.Exit(2)
	}
	if o.format != "go" && o.format != "json" {
		fmt.Fprintf(os.Stderr, "nuclei2cve: unknown -format %q (want go|json)\n", o.format)
		os.Exit(2)
	}

	recs, err := Convert(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nuclei2cve:", err)
		os.Exit(1)
	}

	var rendered string
	if o.format == "json" {
		b, err := json.MarshalIndent(recs, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "nuclei2cve:", err)
			os.Exit(1)
		}
		rendered = string(b) + "\n"
	} else {
		rendered = RenderGo(recs, o.varName)
	}

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "nuclei2cve:", err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}
	fmt.Fprint(w, rendered)
	fmt.Fprintf(os.Stderr, "nuclei2cve: emitted %d record(s)\n", len(recs))
}

// Convert walks the template tree and returns the derived records, sorted by ID.
func Convert(o options) ([]Record, error) {
	have, err := loadIDSet(o.have)
	if err != nil {
		return nil, fmt.Errorf("reading -have: %w", err)
	}
	kev, err := loadKEV(o.kev)
	if err != nil {
		return nil, fmt.Errorf("reading -kev: %w", err)
	}

	// Index the newest template per CVE id (templates can appear under multiple
	// directories; first-seen in a sorted walk wins, deterministically).
	paths, err := findTemplates(o.templates)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var recs []Record
	for _, p := range paths {
		id := cveIDFromName(filepath.Base(p))
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		if have[id] {
			continue
		}
		if kev != nil {
			if _, ok := kev[id]; !ok {
				continue // KEV-only mode: skip CVEs CISA hasn't confirmed exploited
			}
		}
		rec, ok := recordFromTemplate(p, id, o, kev)
		if !ok {
			continue
		}
		if rec.CVSS < o.minSevCVSS {
			continue
		}
		recs = append(recs, rec)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].ID < recs[j].ID })
	return recs, nil
}

var cveNameRe = regexp.MustCompile(`(?i)^(CVE-\d{4}-\d{3,})\.ya?ml$`)

func cveIDFromName(base string) string {
	m := cveNameRe.FindStringSubmatch(base)
	if m == nil {
		return ""
	}
	return strings.ToUpper(m[1])
}

func findTemplates(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if cveIDFromName(filepath.Base(p)) != "" {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// --- Nuclei template parsing -------------------------------------------------

type nucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string    `yaml:"name"`
		Severity    string    `yaml:"severity"`
		Description string    `yaml:"description"`
		Tags        multiWord `yaml:"tags"`
	} `yaml:"info"`
	HTTP     []nucleiReq `yaml:"http"`
	Requests []nucleiReq `yaml:"requests"`
}

type nucleiReq struct {
	Path multiWord `yaml:"path"`
	Raw  multiWord `yaml:"raw"`
}

// multiWord accepts a YAML scalar, a comma string, or a sequence, and flattens
// it to a string slice — Nuclei uses all three for `tags`, `path`, and `raw`.
type multiWord []string

func (m *multiWord) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		parts := strings.Split(n.Value, ",")
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				*m = append(*m, s)
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			*m = append(*m, c.Value)
		}
	}
	return nil
}

func recordFromTemplate(path, id string, o options, kev map[string]kevEntry) (Record, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Record{}, false
	}
	var t nucleiTemplate
	if err := yaml.Unmarshal(b, &t); err != nil {
		return Record{}, false
	}
	reqs := t.HTTP
	if len(reqs) == 0 {
		reqs = t.Requests
	}
	sigs := extractSigs(reqs, o.maxSigs, o.keepGeneric)
	if len(sigs) == 0 {
		return Record{}, false
	}

	name := t.Info.Name
	desc := t.Info.Description
	if ke, ok := kev[id]; ok {
		if ke.Name != "" {
			name = ke.Name
		}
		if ke.Desc != "" {
			desc = ke.Desc
		}
	}
	tech, tac := techTactic(t.Info.Tags, name)
	return Record{
		ID:          id,
		Name:        cleanName(firstNonEmpty(name, id)),
		CVSS:        sevToCVSS(t.Info.Severity),
		Service:     o.service,
		Signatures:  sigs,
		Technique:   tech,
		Tactic:      tac,
		Description: cleanDesc(desc),
	}, true
}

func extractSigs(reqs []nucleiReq, maxSigs int, keepGeneric bool) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = stripVars(s)
		if !goodSig(s, keepGeneric) {
			return
		}
		low := strings.ToLower(s)
		if seen[low] {
			return
		}
		seen[low] = true
		out = append(out, low)
	}
	for _, r := range reqs {
		for _, p := range r.Path {
			add(p)
		}
		for _, raw := range r.Raw {
			if p := pathFromRaw(raw); p != "" {
				add(p)
			}
		}
	}
	if len(out) > maxSigs {
		out = out[:maxSigs]
	}
	return out
}

var (
	tmplVarRe = regexp.MustCompile(`(?i)\{\{\s*(BaseURL|RootURL|Hostname|Host|interactsh-url|BaseDNS)\s*\}\}`)
	rawLineRe = regexp.MustCompile(`(?m)^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP`)
)

func stripVars(p string) string {
	p = tmplVarRe.ReplaceAllString(p, "")
	if i := strings.Index(p, "{{"); i >= 0 {
		p = p[:i]
	}
	return strings.TrimSpace(p)
}

func pathFromRaw(raw string) string {
	if m := rawLineRe.FindStringSubmatch(raw); m != nil {
		return m[2]
	}
	return ""
}

// genericPaths are endpoints too common to attribute to one CVE by substring
// match; dropping them keeps catalog false positives near zero.
var genericPaths = map[string]bool{
	"/": true, "/login": true, "/index.php": true, "/index.html": true,
	"/admin": true, "/api": true, "/api/": true, "/wp-login.php": true,
	"/favicon.ico": true, "/robots.txt": true, "/.env": true, "/index.jsp": true,
	"/index.action": true, "/console": true, "/login.php": true, "/user/login": true,
	"/wp-admin/": true, "/cgi-bin/": true, "/admin/": true, "/portal/": true,
	"/web/": true, "/status": true, "/health": true, "/version": true, "/info": true,
	"/debug": true, "/test": true, "/manager/html": true, "/login.htm": true,
	"/login.do": true, "/setup.php": true, "/login/index.php": true,
	"/api/v3/": true, "/api/content/": true, "/api/upload": true, "/api/jobs/": true,
	"/api/v1/login": true, "/api/v1/version": true, "/v1/chat/completions": true,
	"/rest/login": true, "/rest/version": true, "/login/": true,
}

func goodSig(s string, keepGeneric bool) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) < 8 || !strings.HasPrefix(s, "/") {
		return false
	}
	if !keepGeneric {
		if genericPaths[s] || genericPaths[strings.TrimRight(s, "/")] {
			return false
		}
	}
	depth := strings.Count(strings.Trim(s, "/"), "/")
	if depth < 1 && !strings.Contains(s, "?") && !strings.Contains(s[1:], ".") {
		return false
	}
	return true
}

func techTactic(tags multiWord, name string) (string, string) {
	t := strings.ToLower(strings.Join(tags, " ") + " " + name)
	for _, k := range []string{"lfi", "traversal", "fileread", "file read", "file inclusion", "disclosure", "arbitrary file"} {
		if strings.Contains(t, k) {
			return "T1083", "discovery"
		}
	}
	return "T1190", "initial-access"
}

func sevToCVSS(sev string) float64 {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 9.8
	case "high":
		return 8.1
	case "medium":
		return 6.1
	case "low":
		return 4.0
	case "info":
		return 0.0
	}
	return 8.1
}

var wsRe = regexp.MustCompile(`\s+`)

func cleanName(s string) string {
	s = strings.TrimSpace(wsRe.ReplaceAllString(s, " "))
	if len(s) <= 120 {
		return s
	}
	cut := s[:120]
	if sp := strings.LastIndex(strings.TrimRight(cut, " "), " "); sp > 0 {
		cut = cut[:sp]
	}
	return strings.TrimRight(cut, " ,(-")
}

func cleanDesc(s string) string {
	s = strings.TrimSpace(wsRe.ReplaceAllString(s, " "))
	if s == "" {
		return ""
	}
	if len(s) > 240 {
		window := s[:240]
		if dot := strings.LastIndex(window, ". "); dot >= 80 {
			s = window[:dot+1]
		} else if sp := strings.LastIndex(strings.TrimRight(window, " "), " "); sp > 0 {
			s = strings.TrimRight(window[:sp], " ,(-") + "..."
		}
	}
	if !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, "...") {
		s += "."
	}
	return s
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

// --- inputs ------------------------------------------------------------------

func loadIDSet(path string) (map[string]bool, error) {
	set := map[string]bool{}
	if path == "" {
		return set, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if s := strings.ToUpper(strings.TrimSpace(line)); s != "" {
			set[s] = true
		}
	}
	return set, nil
}

type kevEntry struct {
	Name string
	Desc string
}

func loadKEV(path string) (map[string]kevEntry, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var feed struct {
		Vulnerabilities []struct {
			CveID             string `json:"cveID"`
			VulnerabilityName string `json:"vulnerabilityName"`
			ShortDescription  string `json:"shortDescription"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &feed); err != nil {
		return nil, err
	}
	m := make(map[string]kevEntry, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		m[strings.ToUpper(v.CveID)] = kevEntry{Name: v.VulnerabilityName, Desc: v.ShortDescription}
	}
	return m, nil
}

// --- Go rendering ------------------------------------------------------------

// RenderGo emits a compilable Go source file declaring recs as a []Record slice
// named varName. Signatures are already lowercased; the catalog lowercases again
// in init(), so this is idempotent.
func RenderGo(recs []Record, varName string) string {
	var b strings.Builder
	b.WriteString("package cve\n\n")
	fmt.Fprintf(&b, "// %s was generated by tools/nuclei2cve from Nuclei templates.\n", varName)
	b.WriteString("// Each record pairs a CVE with the static, high-signal portion of its Nuclei\n")
	b.WriteString("// exploit path. Detection + ATT&CK tagging only; nothing is executed. Fold it\n")
	b.WriteString("// into the catalog in init() (see cve.go).\n")
	fmt.Fprintf(&b, "var %s = []Record{\n", varName)
	for _, r := range recs {
		fmt.Fprintf(&b, "\t{ID: %q, Name: %q, CVSS: %.1f, Service: %q,\n", r.ID, r.Name, r.CVSS, r.Service)
		b.WriteString("\t\tSignatures: []string{")
		for i, s := range r.Signatures {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", s)
		}
		b.WriteString("},\n")
		fmt.Fprintf(&b, "\t\tTechnique:  %q, Tactic: %q,\n", r.Technique, r.Tactic)
		fmt.Fprintf(&b, "\t\tDescription: %q},\n", r.Description)
	}
	b.WriteString("}\n")
	return b.String()
}
