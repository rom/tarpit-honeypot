package ui

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func hasStr(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func hasInt(list []int, n int) bool {
	for _, e := range list {
		if e == n {
			return true
		}
	}
	return false
}

func TestBuildProfile(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{
			ID: "1", Time: now, RuleID: "cve:CVE-2021-41773", Severity: event.SeverityCritical,
			Handler: "http", Dest: event.Endpoint{Port: 80}, Source: event.Endpoint{IP: "5.6.7.8"},
			Sensor:          "edge-1",
			MitreTechniques: []string{"T1190"}, MitreTactics: []string{"initial-access"},
			Anomalies: []string{"uri-path-traversal"},
			Meta: map[string]any{
				"tools": []any{"nmap", "sqlmap"}, "automation": true,
				"ja4h": "ge11nn0000", "http_login_user": "admin", "http_login_pass": "admin",
			},
		},
		{
			ID: "2", Time: now.Add(-time.Hour), RuleID: "listener:ssh", Severity: event.SeverityMedium,
			Handler: "ssh", Dest: event.Endpoint{Port: 22}, Source: event.Endpoint{IP: "5.6.7.8"},
			Sensor: "edge-1",
			Meta: map[string]any{
				"tools": []any{"hydra"}, "hassh": "abc123",
				"user_attempt": "root", "pass_attempt": "toor",
			},
		},
	}
	p := buildProfile("5.6.7.8", evs)

	if p.Count != 2 {
		t.Errorf("count = %d; want 2", p.Count)
	}
	if p.ThreatScore != 20 { // 4^2 + 2^2
		t.Errorf("threat score = %d; want 20", p.ThreatScore)
	}
	if p.ThreatLevel != "elevated" {
		t.Errorf("threat level = %q; want elevated", p.ThreatLevel)
	}
	if p.MaxSeverity != "critical" {
		t.Errorf("max severity = %q; want critical", p.MaxSeverity)
	}
	if !p.Automation {
		t.Error("automation should be true")
	}
	for _, want := range []string{"nmap", "sqlmap", "hydra"} {
		if !hasStr(p.Tools, want) {
			t.Errorf("tools missing %q: %v", want, p.Tools)
		}
	}
	if p.Fingerprints["ja4h"] == "" || p.Fingerprints["hassh"] == "" {
		t.Errorf("fingerprints incomplete: %v", p.Fingerprints)
	}
	if len(p.Credentials) != 2 {
		t.Errorf("credentials = %v; want 2 pairs", p.Credentials)
	}
	if !hasStr(p.CVEs, "CVE-2021-41773") {
		t.Errorf("CVEs missing: %v", p.CVEs)
	}
	if !hasStr(p.Mitre, "T1190") || !hasStr(p.Tactics, "initial-access") {
		t.Errorf("mitre/tactics missing: %v / %v", p.Mitre, p.Tactics)
	}
	if !hasStr(p.Handlers, "http") || !hasStr(p.Handlers, "ssh") {
		t.Errorf("handlers missing: %v", p.Handlers)
	}
	if !hasInt(p.Ports, 80) || !hasInt(p.Ports, 22) {
		t.Errorf("ports missing: %v", p.Ports)
	}
	if p.BySeverity["critical"] != 1 || p.BySeverity["medium"] != 1 {
		t.Errorf("by-severity wrong: %v", p.BySeverity)
	}
}

func TestProfilesHandlersEndToEnd(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.Insert(ctx, &event.Event{
		ID: "1", Time: now, Sensor: "s", RuleID: "webapp:sqli", Severity: event.SeverityHigh,
		Source: event.Endpoint{IP: "5.6.7.8"}, Handler: "http", Dest: event.Endpoint{Port: 80},
		Meta: map[string]any{"tools": []any{"sqlmap"}, "http_login_user": "admin", "http_login_pass": "admin"},
	})
	srv, err := New(config.UI{Enabled: true, Bind: "127.0.0.1:0"}, st)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	srv.handleProfiles(w, httptest.NewRequest("GET", "/profiles", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "/profiles/5.6.7.8") {
		t.Errorf("profiles list: code=%d body=%q", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	srv.handleProfile(w, httptest.NewRequest("GET", "/profiles/5.6.7.8", nil))
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "attacker profile") || !strings.Contains(body, "sqlmap") {
		t.Errorf("profile detail: code=%d body=%q", w.Code, body)
	}

	w = httptest.NewRecorder()
	srv.handleAPIProfile(w, httptest.NewRequest("GET", "/api/profiles/5.6.7.8", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"threat_score"`) {
		t.Errorf("profile JSON: code=%d body=%q", w.Code, w.Body.String())
	}
}

// In the attacker profile the recent-events rule column and the anomalies are
// rendered as links; a "cve:CVE-..." rule also gets a CVE-reference link.
func TestProfileClickableLabels(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	_ = st.Insert(ctx, &event.Event{
		ID: "c1", Time: time.Now().UTC(), Sensor: "s", RuleID: "cve:CVE-2017-9841", Severity: event.SeverityCritical,
		Source: event.Endpoint{IP: "9.9.9.9"}, Handler: "http", Dest: event.Endpoint{Port: 80},
		Anomalies:    []string{"webapp-secret-file-probe", "webapp:sqli"},
		MitreTactics: []string{"initial-access"},
		Meta: map[string]any{
			"tools": []any{"sqlmap"}, "cloud_provider": "aws", "net_class": "hosting",
			"tls_version": "TLS 1.3", "sni": "evil.example",
			"harvested_urls": []any{"http://evil.example/x.sh"},
		},
	})
	srv, err := New(config.UI{Enabled: true, Bind: "127.0.0.1:0"}, st)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	srv.handleProfile(w, httptest.NewRequest("GET", "/profiles/9.9.9.9", nil))
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	if !strings.Contains(body, `href="/events?source=9.9.9.9&amp;rule=cve%3aCVE-2017-9841"`) {
		t.Errorf("recent-events rule not linked: %q", body)
	}
	if !strings.Contains(body, "nvd.nist.gov/vuln/detail/CVE-2017-9841") {
		t.Errorf("CVE rule missing CVE-reference link: %q", body)
	}
	if !strings.Contains(body, `href="/search?source=9.9.9.9&amp;tag=webapp-secret-file-probe"`) {
		t.Errorf("anomaly not linked: %q", body)
	}
	// tools / scanners and ATT&CK tactics are links too.
	if !strings.Contains(body, `href="/events?source=9.9.9.9&amp;tool=sqlmap"`) {
		t.Errorf("tool not linked: %q", body)
	}
	if !strings.Contains(body, `href="/events?source=9.9.9.9&amp;tactic=initial-access"`) {
		t.Errorf("tactic not linked: %q", body)
	}
	// origin/infrastructure "network", protocol intelligence, domains/SNIs,
	// harvested URLs and web-attack classes are clickable too.
	for _, want := range []string{
		`href="/events?cloud=aws"`,                          // network: cloud provider
		`href="/events?source=9.9.9.9&amp;q=hosting"`,       // network: net_class
		`href="/events?source=9.9.9.9&amp;q=evil.example"`,  // domains / SNIs
		`href="/events?source=9.9.9.9&amp;q=webapp%3asqli"`, // web-attack class
		`>http://evil.example/x.sh</a>`,                     // harvested URL is a link
	} {
		if !strings.Contains(body, want) {
			t.Errorf("profile missing clickable label %q\nbody: %q", want, body)
		}
	}
}

func TestThreatLevel(t *testing.T) {
	cases := map[int]string{0: "low", 5: "low", 15: "elevated", 60: "high", 200: "critical", 999: "critical"}
	for score, want := range cases {
		if got := threatLevel(score); got != want {
			t.Errorf("threatLevel(%d) = %q; want %q", score, got, want)
		}
	}
}

func TestProfileTemplatesRender(t *testing.T) {
	tmpl := uiTmpl(t)

	var b strings.Builder
	pp := profilesPage{Profiles: []store.SourceAggregate{
		{IP: "9.9.9.9", Count: 12, MaxSeverity: event.SeverityHigh, DistinctRules: 4, Weight: 80, FirstSeen: time.Now(), LastSeen: time.Now()},
	}}
	if err := tmpl.ExecuteTemplate(&b, "profiles", pp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "attacker profiles") || !strings.Contains(b.String(), "/profiles/9.9.9.9") {
		t.Errorf("profiles list missing content: %q", b.String())
	}

	b.Reset()
	prof := buildProfile("9.9.9.9", []*event.Event{
		{ID: "1", Time: time.Now(), RuleID: "webapp:sqli", Severity: event.SeverityHigh, Handler: "http",
			Meta: map[string]any{"tools": []any{"sqlmap"}, "tool_confidence": 90, "http_login_user": "admin", "http_login_pass": "x"}},
	})
	if prof.Confidence != 90 {
		t.Errorf("profile confidence = %d; want 90", prof.Confidence)
	}
	if err := tmpl.ExecuteTemplate(&b, "profile", profileView{Profile: prof}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "attacker profile") || !strings.Contains(out, "sqlmap") || !strings.Contains(out, "secrets captured") {
		t.Errorf("profile detail missing content: %q", out)
	}
	// The synthesized assessment + identification confidence are surfaced.
	if !strings.Contains(out, "assessment:") || !strings.Contains(out, "id confidence") || !strings.Contains(out, "high (90)") {
		t.Errorf("profile missing synthesized assessment / confidence: %q", out)
	}
}
