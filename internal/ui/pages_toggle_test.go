package ui

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// pageRoute must 404 a disabled page and pass an enabled one through.
func TestPageRouteGating(t *testing.T) {
	s := &Server{cfg: config.UI{Pages: map[string]bool{"charts": false}}}
	mux := http.NewServeMux()
	chartsHit, credsHit := false, false
	s.pageRoute(mux, "/charts", "charts", func(w http.ResponseWriter, r *http.Request) { chartsHit = true })
	s.pageRoute(mux, "/credentials", "credentials", func(w http.ResponseWriter, r *http.Request) { credsHit = true; w.WriteHeader(200) })

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/charts", nil))
	if rec.Code != http.StatusNotFound || chartsHit {
		t.Errorf("disabled /charts: code=%d hit=%v, want 404 + not hit", rec.Code, chartsHit)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/credentials", nil))
	if rec.Code != http.StatusOK || !credsHit {
		t.Errorf("enabled /credentials: code=%d hit=%v, want 200 + hit", rec.Code, credsHit)
	}
}

// The pageEnabled / hasPage template funcs must reflect the wired predicates,
// and the nav must drop a disabled page's link.
func TestNavRespectsPageToggle(t *testing.T) {
	render := func(enabled func(string) bool, has func(string) bool) string {
		fns := tmplFuncs(func() int { return 0 }, "nvd", "", true, navFuncs{has: has, enabled: enabled})
		tmpl := template.Must(template.New("").Funcs(fns).Parse(tmpls))
		var b strings.Builder
		// "events" is the smallest page that just renders head+foot.
		if err := tmpl.ExecuteTemplate(&b, "head", map[string]any{}); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	// charts disabled, dns listener present + enabled.
	out := render(
		func(slug string) bool { return slug != "charts" },
		func(cat string) bool { return cat == "dns" },
	)
	if strings.Contains(out, `href="/charts"`) {
		t.Error("disabled charts page must not appear in the nav")
	}
	if !strings.Contains(out, `href="/dns"`) {
		t.Error("dns page (listener present, enabled) should appear in the nav")
	}
	if strings.Contains(out, `href="/web"`) {
		t.Error("web has no listener here; must not appear")
	}
	// credentials stays (not disabled).
	if !strings.Contains(out, `href="/credentials"`) {
		t.Error("credentials should appear when enabled")
	}
	// playbooks is a first-class, togglable nav entry — present when enabled.
	if !strings.Contains(out, `href="/playbooks"`) {
		t.Error("playbooks should appear in the nav when enabled")
	}
	if out2 := render(func(slug string) bool { return slug != "playbooks" }, func(string) bool { return false }); strings.Contains(out2, `href="/playbooks"`) {
		t.Error("disabled playbooks page must not appear in the nav")
	}
}
