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

// The shared-infrastructure graph is bipartite: only pivots shared by 2+ IPs
// become hubs, and only the IPs that touch a shared hub appear.
func TestBuildSharedGraph(t *testing.T) {
	sources := []corrSource{
		{IP: "9.9.9.9", MaxSev: "high", Count: 10},
		{IP: "8.8.8.8", MaxSev: "critical", Count: 5},
		{IP: "7.7.7.7", MaxSev: "low", Count: 2}, // shares nothing → excluded
	}
	pivotIPs := map[string]map[string]bool{
		"fp\x00ja4/t13d":    {"9.9.9.9": true, "8.8.8.8": true}, // shared → a hub
		"cred\x00root:toor": {"9.9.9.9": true},                  // only one IP → not a hub
	}
	pivotInfo := map[string]sharedPivot{
		"fp\x00ja4/t13d":    {Kind: "fp", Label: "ja4:t13d"},
		"cred\x00root:toor": {Kind: "cred", Label: "root:toor"},
	}
	// Mimic the builder: drop non-shared pivots before graphing.
	for k, ips := range pivotIPs {
		if len(ips) < 2 {
			delete(pivotIPs, k)
			delete(pivotInfo, k)
		}
	}
	b64 := buildSharedGraph(sources, pivotIPs, pivotInfo)
	if b64 == "" {
		t.Fatal("expected a shared-infrastructure graph")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("graph not valid base64: %v", err)
	}
	var g struct {
		Sources []sharedNode `json:"sources"`
		Hubs    []sharedNode `json:"hubs"`
		Edges   []graphEdge  `json:"edges"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("graph not valid JSON: %v", err)
	}
	// 2 IPs (the sharers) + 1 hub + 2 edges; 7.7.7.7 excluded.
	if len(g.Sources) != 2 || len(g.Hubs) != 1 || len(g.Edges) != 2 {
		t.Errorf("graph shape: %d sources / %d hubs / %d edges; want 2/1/2", len(g.Sources), len(g.Hubs), len(g.Edges))
	}
	if len(g.Hubs) == 1 && (g.Hubs[0].Kind != "fp" || g.Hubs[0].Count != 2) {
		t.Errorf("hub wrong: %+v", g.Hubs[0])
	}
}

// Two IPs sharing a fingerprint are grouped into one correlation cluster.
func TestBuildCorrClusters(t *testing.T) {
	order := []string{"9.9.9.9", "8.8.8.8", "7.7.7.7"}
	sources := []corrSource{
		{IP: "9.9.9.9", MaxSev: "high", Count: 10},
		{IP: "8.8.8.8", MaxSev: "critical", Count: 5},
		{IP: "7.7.7.7", MaxSev: "low", Count: 2},
	}
	pivotIPs := map[string]map[string]bool{
		"fp\x00ja4/t13d": {"9.9.9.9": true, "8.8.8.8": true},
	}
	pivotInfo := map[string]sharedPivot{"fp\x00ja4/t13d": {Kind: "fp", Label: "ja4:t13d"}}
	cl := buildCorrClusters(order, sources, pivotIPs, pivotInfo)
	if len(cl) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(cl))
	}
	c := cl[0]
	if len(c.Members) != 2 || c.MaxSev != "critical" || c.Events != 15 {
		t.Errorf("cluster wrong: %+v", c)
	}
	if len(c.Shared) != 1 || c.Shared[0].IPs != 2 {
		t.Errorf("cluster shared wrong: %+v", c.Shared)
	}
}
