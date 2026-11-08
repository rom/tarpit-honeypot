package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStripVars(t *testing.T) {
	cases := map[string]string{
		"{{BaseURL}}/boardDataWW.php":               "/boardDataWW.php",
		"{{RootURL}}/cgi-bin/x?a={{rand}}":          "/cgi-bin/x?a=",
		"{{Hostname}}/a/b":                          "/a/b",
		"/plain/path":                               "/plain/path",
		"{{BaseURL}}/path?u={{interactsh-url}}&v=1": "/path?u=&v=1",
	}
	for in, want := range cases {
		if got := stripVars(in); got != want {
			t.Errorf("stripVars(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestPathFromRaw(t *testing.T) {
	raw := "POST /upload.action HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\nx=1"
	if got := pathFromRaw(raw); got != "/upload.action" {
		t.Errorf("pathFromRaw=%q, want /upload.action", got)
	}
	if got := pathFromRaw("not a request line"); got != "" {
		t.Errorf("pathFromRaw(non-request)=%q, want empty", got)
	}
}

func TestGoodSig(t *testing.T) {
	good := []string{"/cgi-bin/mainfunction.cgi/cvmcfgupload", "/web-console/serverinfo.jsp", "/search?q=12345"}
	for _, s := range good {
		if !goodSig(s, false) {
			t.Errorf("goodSig(%q)=false, want true", s)
		}
	}
	bad := []string{"/login", "/api/", "short", "nopath", "/setup.php", "/"}
	for _, s := range bad {
		if goodSig(s, false) {
			t.Errorf("goodSig(%q)=true, want false", s)
		}
	}
	// keepGeneric re-admits the generic ones (still needs a leading slash + length).
	if !goodSig("/login.php", true) {
		t.Error("goodSig with keepGeneric should admit /login.php")
	}
}

func TestTechTactic(t *testing.T) {
	if tech, tac := techTactic(multiWord{"lfi", "traversal"}, "x"); tech != "T1083" || tac != "discovery" {
		t.Errorf("traversal => %s/%s, want T1083/discovery", tech, tac)
	}
	if tech, _ := techTactic(nil, "ColdFusion Directory Traversal"); tech != "T1083" {
		t.Errorf("name-based traversal => %s, want T1083", tech)
	}
	if tech, tac := techTactic(multiWord{"rce"}, "Some RCE"); tech != "T1190" || tac != "initial-access" {
		t.Errorf("rce => %s/%s, want T1190/initial-access", tech, tac)
	}
}

func TestSevToCVSS(t *testing.T) {
	for sev, want := range map[string]float64{"critical": 9.8, "high": 8.1, "medium": 6.1, "low": 4.0, "info": 0.0, "": 8.1} {
		if got := sevToCVSS(sev); got != want {
			t.Errorf("sevToCVSS(%q)=%v, want %v", sev, got, want)
		}
	}
}

func TestCleanNameAndDesc(t *testing.T) {
	if got := cleanName("  Foo   Bar  "); got != "Foo Bar" {
		t.Errorf("cleanName collapse ws: %q", got)
	}
	long := strings.Repeat("word ", 40)
	if got := cleanName(long); len(got) > 120 {
		t.Errorf("cleanName did not cap length: %d", len(got))
	}
	if got := cleanDesc("A short note"); got != "A short note." {
		t.Errorf("cleanDesc should add period: %q", got)
	}
	if got := cleanDesc(""); got != "" {
		t.Errorf("cleanDesc(empty)=%q", got)
	}
}

func TestConvertEndToEnd(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("CVE-2020-15415.yaml", `
id: CVE-2020-15415
info:
  name: DrayTek Vigor Command Injection
  severity: critical
  description: DrayTek routers contain an OS command injection vulnerability.
  tags: cve,rce,draytek
http:
  - method: POST
    path:
      - "{{BaseURL}}/cgi-bin/mainfunction.cgi/cvmcfgupload?1=2"
`)
	write("CVE-2010-2861.yaml", `
id: CVE-2010-2861
info:
  name: Adobe ColdFusion Directory Traversal
  severity: high
  description: A directory traversal vulnerability in ColdFusion.
  tags: [cve, lfi, coldfusion]
http:
  - raw:
      - |
        GET /CFIDE/administrator/enter.cfm?locale=../../../../etc/passwd HTTP/1.1
        Host: {{Hostname}}
`)
	// Advisory-only template (no usable path) must be dropped.
	write("CVE-2099-0001.yaml", `
id: CVE-2099-0001
info:
  name: Generic Login
  severity: low
http:
  - path:
      - "{{BaseURL}}/login"
`)
	// A non-CVE template file must be ignored entirely.
	write("exposed-panel.yaml", `id: exposed-panel`)

	recs, err := Convert(options{templates: dir, service: "http", maxSigs: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(recs), recs)
	}
	// Sorted by ID: 2010 first.
	if recs[0].ID != "CVE-2010-2861" || recs[1].ID != "CVE-2020-15415" {
		t.Fatalf("unexpected order: %s, %s", recs[0].ID, recs[1].ID)
	}
	if recs[0].Technique != "T1083" || recs[0].Tactic != "discovery" {
		t.Errorf("traversal CVE mapped to %s/%s", recs[0].Technique, recs[0].Tactic)
	}
	if recs[0].Signatures[0] != "/cfide/administrator/enter.cfm?locale=../../../../etc/passwd" {
		t.Errorf("raw path not extracted/lowercased: %v", recs[0].Signatures)
	}
	if recs[1].CVSS != 9.8 || recs[1].Signatures[0] != "/cgi-bin/mainfunction.cgi/cvmcfgupload?1=2" {
		t.Errorf("draytek record wrong: %+v", recs[1])
	}

	// have.txt skips a CVE.
	havePath := filepath.Join(dir, "have.txt")
	if err := os.WriteFile(havePath, []byte("CVE-2020-15415\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	recs2, err := Convert(options{templates: dir, service: "http", maxSigs: 3, have: havePath})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs2) != 1 || recs2[0].ID != "CVE-2010-2861" {
		t.Fatalf("-have did not skip: %+v", recs2)
	}
}

func TestConvertKEVFilter(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "CVE-2021-0001.yaml"), []byte(`
id: CVE-2021-0001
info: {name: In KEV, severity: high}
http: [{path: ["{{BaseURL}}/distinct/kev/path.php"]}]
`), 0o644)
	os.WriteFile(filepath.Join(dir, "CVE-2021-0002.yaml"), []byte(`
id: CVE-2021-0002
info: {name: Not In KEV, severity: high}
http: [{path: ["{{BaseURL}}/distinct/other/path.php"]}]
`), 0o644)
	kevPath := filepath.Join(dir, "kev.json")
	os.WriteFile(kevPath, []byte(`{"vulnerabilities":[{"cveID":"CVE-2021-0001","vulnerabilityName":"KEV Name","shortDescription":"From CISA."}]}`), 0o644)

	recs, err := Convert(options{templates: dir, service: "http", maxSigs: 3, kev: kevPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].ID != "CVE-2021-0001" {
		t.Fatalf("KEV filter wrong: %+v", recs)
	}
	if recs[0].Name != "KEV Name" || recs[0].Description != "From CISA." {
		t.Errorf("KEV name/desc not preferred: %+v", recs[0])
	}
}

func TestRenderGoCompilableShape(t *testing.T) {
	out := RenderGo([]Record{{
		ID: "CVE-2020-15415", Name: `DrayTek "Vigor"`, CVSS: 9.8, Service: "http",
		Signatures: []string{"/a/b", "/c?d=1"}, Technique: "T1190", Tactic: "initial-access",
		Description: "x",
	}}, "cveTest")
	for _, want := range []string{"package cve", "var cveTest = []Record{", `ID: "CVE-2020-15415"`,
		`Name: "DrayTek \"Vigor\""`, `[]string{"/a/b", "/c?d=1"}`, `Technique:  "T1190"`} {
		if !strings.Contains(out, want) {
			t.Errorf("RenderGo output missing %q\n%s", want, out)
		}
	}
}
