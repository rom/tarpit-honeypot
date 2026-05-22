package ui

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStaticAppJSServed(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	w := httptest.NewRecorder()
	s.handleStatic(w, r)
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", res.StatusCode)
	}
	ct := res.Header.Get("Content-Type")
	if !strings.Contains(ct, "javascript") {
		t.Errorf("content-type = %q; want a javascript MIME (required under nosniff)", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "tarpit-honeypot UI") {
		t.Errorf("app.js body not served (got %d bytes)", len(body))
	}
}

func TestStaticMissing404(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest(http.MethodGet, "/static/nope.js", nil)
	w := httptest.NewRecorder()
	s.handleStatic(w, r)
	if w.Result().StatusCode != http.StatusNotFound {
		t.Errorf("missing asset should 404, got %d", w.Result().StatusCode)
	}
}

func TestCSPAllowsPackagedScripts(t *testing.T) {
	s := &Server{} // no auth token → loopback gate
	h := s.withAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	csp := w.Result().Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("CSP should allow same-origin scripts: %q", csp)
	}
	if strings.Contains(csp, "'unsafe-eval'") || strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Errorf("CSP must not allow eval / inline scripts: %q", csp)
	}
	if !strings.Contains(csp, "connect-src 'self'") {
		t.Errorf("CSP should allow same-origin fetch: %q", csp)
	}
}

func TestBuildCorrGraph(t *testing.T) {
	sources := []corrSource{
		{IP: "9.9.9.9", FPs: []fpChip{{Kind: "ja4", Value: "t13d1516"}}, ASN: "AS64500 EvilNet", Tools: []string{"sqlmap"}, Domains: []string{"exfil.example"}},
	}
	b64 := buildCorrGraph(sources)
	if b64 == "" {
		t.Fatal("expected a graph")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("graph not valid base64: %v", err)
	}
	var g struct {
		Nodes []graphNode `json:"nodes"`
		Edges []graphEdge `json:"edges"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("graph not valid JSON: %v", err)
	}
	// IP node + fp + asn + tool + domain = 5 nodes, 4 edges from the IP.
	if len(g.Nodes) != 5 || len(g.Edges) != 4 {
		t.Errorf("graph shape: %d nodes / %d edges; want 5/4", len(g.Nodes), len(g.Edges))
	}
	var hasIP bool
	for _, n := range g.Nodes {
		if n.Group == "ip" && n.Label == "9.9.9.9" {
			hasIP = true
		}
	}
	if !hasIP {
		t.Errorf("IP node missing: %+v", g.Nodes)
	}
}
