package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStaticChartsJSServed(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest(http.MethodGet, "/static/charts.js", nil)
	w := httptest.NewRecorder()
	s.handleStatic(w, r)
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("content-type = %q; want a javascript MIME", ct)
	}
	body := w.Body.String()
	// Every documented chart type must be present in the library.
	for _, typ := range []string{"bar", "hbar", "pie", "histogram", "scatter",
		"line", "area", "heatmap", "topology", "network", "sankey", "timeline",
		"sourcemap", "sessionreplay", "creds"} {
		if !strings.Contains(body, "charts."+typ+" =") {
			t.Errorf("charts.js missing renderer for %q", typ)
		}
	}
	if !strings.Contains(body, "window.TarpitCharts") {
		t.Errorf("charts.js does not expose TarpitCharts")
	}
}

func TestHeadIncludesChartsJS(t *testing.T) {
	if !strings.Contains(tmpls, "/static/charts.js") {
		t.Error("head template does not load charts.js")
	}
}
