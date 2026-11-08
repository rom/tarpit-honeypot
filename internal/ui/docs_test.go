package ui

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"
)

// docsTmpl parses the template set with a non-zero refresh interval so we can
// assert the docs reader stays static even when the rest of the UI live-updates.
func docsTmpl(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("").Funcs(tmplFuncs(func() int { return 10 }, "nvd", "", true, navFuncs{has: func(string) bool { return true }, enabled: func(string) bool { return true }})).Parse(tmpls)
	if err != nil {
		t.Fatal(err)
	}
	return tmpl
}

// The docs index and a single doc must render via the static head/foot so they
// never carry a <meta http-equiv="refresh"> even when refreshSeconds > 0.
func TestDocsPagesDoNotAutoRefresh(t *testing.T) {
	tmpl := docsTmpl(t)

	var idx strings.Builder
	if err := tmpl.ExecuteTemplate(&idx, "docs", docsPage{UIBind: "127.0.0.1:8080", Docs: docLibrary()}); err != nil {
		t.Fatalf("render docs index: %v", err)
	}
	if strings.Contains(idx.String(), "http-equiv=\"refresh\"") {
		t.Error("docs index must not emit a <meta refresh> tag")
	}
	if strings.Contains(idx.String(), "auto-refreshes") {
		t.Error("docs index footer must not advertise auto-refresh")
	}

	var one strings.Builder
	body := template.HTML("<h1>Hello</h1>")
	if err := tmpl.ExecuteTemplate(&one, "doc", docPage{Name: "lua", Body: body}); err != nil {
		t.Fatalf("render doc: %v", err)
	}
	if strings.Contains(one.String(), "http-equiv=\"refresh\"") {
		t.Error("doc page must not emit a <meta refresh> tag")
	}
	if !strings.Contains(one.String(), "Hello") {
		t.Error("doc page must render the markdown body")
	}
}

// A normal (live) page must still carry the refresh meta when refreshSeconds>0,
// confirming the split didn't disable auto-refresh everywhere.
func TestLivePageStillRefreshes(t *testing.T) {
	tmpl := docsTmpl(t)
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "errors", errorsPage{}); err != nil {
		t.Skipf("errors template render unavailable: %v", err)
	}
	if !strings.Contains(b.String(), "http-equiv=\"refresh\"") {
		t.Error("live pages must still emit <meta refresh> when refreshSeconds>0")
	}
}

// lua and attack-tools must appear in the curated catalog (with real titles),
// not just be auto-appended with their bare slugs.
func TestNewDocsInCatalog(t *testing.T) {
	want := map[string]bool{"lua": false, "attack-tools": false}
	for _, d := range docCatalog {
		if _, ok := want[d.Name]; ok {
			if d.Title == "" || d.Title == d.Name {
				t.Errorf("doc %q needs a curated title, got %q", d.Name, d.Title)
			}
			want[d.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("doc %q missing from docCatalog", name)
		}
	}
}

// The generated CVE catalog must be reachable from the GUI docs page: listed in
// the library (from docCatalog, since CVE.md is embedded) and renderable at
// /docs/CVE with its content.
func TestCVEDocInLibraryAndRenders(t *testing.T) {
	var found bool
	for _, d := range docLibrary() {
		if d.Name == "CVE" {
			found = true
			if d.Title == "" {
				t.Error("CVE doc has no title")
			}
		}
	}
	if !found {
		t.Fatal("CVE doc not listed in docLibrary()")
	}
	if !availableDocs()["CVE"] {
		t.Error("CVE.md not embedded in docs.FS")
	}

	s := &Server{tmpl: docsTmpl(t)}
	w := httptest.NewRecorder()
	s.handleDoc(w, httptest.NewRequest("GET", "/docs/CVE", nil))
	if w.Code != 200 {
		t.Fatalf("/docs/CVE status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"CVE catalog", "severity distribution", "nvd.nist.gov"} {
		if !strings.Contains(body, want) {
			t.Errorf("/docs/CVE missing %q", want)
		}
	}
}
