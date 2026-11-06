package ui

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func TestHandleCoverageRenders(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv, err := New(config.UI{Enabled: true, Bind: "127.0.0.1:0"}, st)
	if err != nil {
		t.Fatal(err)
	}

	// nil provider → the page is hidden (404) and not advertised in the nav.
	w := httptest.NewRecorder()
	srv.handleCoverage(w, httptest.NewRequest("GET", "/coverage", nil))
	if w.Code != 404 {
		t.Errorf("nil coverage provider: code=%d want 404", w.Code)
	}
	if srv.hasServicePage("coverage") {
		t.Error("coverage nav should be absent with no provider")
	}

	srv.SetCoverageProvider(func() CoverageView {
		return CoverageView{
			Counts: CoverageCounts{
				TCPHandlers: 184, UDPHandlers: 118,
				CVETotal: 719, CVEDetectable: 364, CVEAdvisory: 355,
				KEVActive: true, KEVEntries: 1300, KEVModeled: 42,
				KEVUpdated:  time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC),
				RulesLoaded: 11, Techniques: 200, Tactics: 14, Archetypes: 259,
			},
			Services: []CoverageServiceRow{
				{Service: "http", Detectable: 200, Advisory: 100, KEV: 9,
					TopCVE: "CVE-2021-44228", TopName: "Log4Shell", TopCVSS: 10.0},
			},
		}
	})
	if !srv.hasServicePage("coverage") {
		t.Error("coverage nav should appear once a provider is wired")
	}

	w = httptest.NewRecorder()
	srv.handleCoverage(w, httptest.NewRequest("GET", "/coverage", nil))
	if w.Code != 200 {
		t.Fatalf("coverage render: code=%d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"detection &amp; emulation coverage", // h1
		"719",                                // CVE total
		"CISA KEV overlay",
		"active",         // overlay status
		"CVE-2021-44228", // top CVE for http
		"Log4Shell",
		"spoofed_ptr",       // a recognition label from the ui-side catalog
		"threat_confidence", // another
	} {
		if !strings.Contains(body, want) {
			t.Errorf("coverage page missing %q", want)
		}
	}
	// The ui-side label catalog filled in because the provider left it empty.
	if n := len(recognitionLabelCatalog()); n < 10 {
		t.Errorf("recognition label catalog too small: %d", n)
	}
}
