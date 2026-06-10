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

func TestBuildCrossTarget(t *testing.T) {
	base := time.Now().UTC()
	mk := func(dst string, port int, h string, dt time.Duration) *event.Event {
		return &event.Event{
			ID: dst, Time: base.Add(dt), RuleID: "listener:" + h, Severity: event.SeverityMedium,
			Handler: h, Source: event.Endpoint{IP: "203.0.113.9"},
			Dest: event.Endpoint{IP: dst, Port: port},
		}
	}
	// One source hits three target IPs; port 22 on all three (fleet sweep) + 445 on one.
	evs := []*event.Event{
		mk("10.0.0.10", 22, "ssh", 0),
		mk("10.0.0.11", 22, "ssh", 30*time.Second),
		mk("10.0.0.11", 445, "smb", 31*time.Second),
		mk("10.0.0.12", 22, "ssh", 60*time.Second),
	}
	p := buildProfile("203.0.113.9", evs)
	ct := p.CrossTarget
	if ct == nil {
		t.Fatal("CrossTarget nil for a 3-target source")
	}
	if ct.DistinctTargets != 3 {
		t.Errorf("distinct targets = %d; want 3", ct.DistinctTargets)
	}
	want := []string{"10.0.0.10", "10.0.0.11", "10.0.0.12"}
	for i, tr := range ct.Targets {
		if tr.IP != want[i] {
			t.Fatalf("targets order = %v; want %v", ct.Targets, want)
		}
	}
	if ct.Targets[0].FirstOffset != 0 || ct.Targets[2].FirstOffset != 60 {
		t.Errorf("offsets wrong: %d / %d", ct.Targets[0].FirstOffset, ct.Targets[2].FirstOffset)
	}
	if len(ct.SharedPorts) != 1 || ct.SharedPorts[0] != 22 {
		t.Errorf("shared_ports = %v; want [22]", ct.SharedPorts)
	}
	if ct.Targets[2].BarPct != 100 {
		t.Errorf("last target BarPct = %d; want 100", ct.Targets[2].BarPct)
	}
	// A single-target source gets no cross-target section.
	single := buildProfile("198.51.100.1", []*event.Event{mk("10.0.0.10", 22, "ssh", 0)})
	if single.CrossTarget != nil {
		t.Error("CrossTarget should be nil for a single-target source")
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

// TestProfileNewSectionsRender renders the profile template for a rich actor
// and asserts the new dossier sections show: the aggregated intent, the
// consolidated attacks/misuse catalog, the per-protocol summary, the requested
// URLs, the HTTP headers seen, the files downloaded, and the honeytokens — and
// that the now-folded standalone CVE / web-attack / anomalies sections are gone.
func TestProfileNewSectionsRender(t *testing.T) {
	tmpl := uiTmpl(t)
	now := time.Now()
	prof := buildProfile("6.6.6.6", []*event.Event{
		{ID: "1", Time: now, RuleID: "cve:CVE-2021-41773", Severity: event.SeverityCritical, Handler: "http",
			Dest:      event.Endpoint{Port: 80},
			Anomalies: []string{"webapp:sqli", "uri-path-traversal"},
			Meta: map[string]any{
				"intent": "path traversal to read /etc/passwd", "http_uri": "/cgi-bin/.%2e/etc/passwd",
				"http_headers": map[string]string{"user-agent": "curl/8.1"}, "honeytoken": "AKIA_HONEY_KEY",
				"tls_version": "TLS 1.3",
			}},
		{ID: "2", Time: now.Add(time.Minute), RuleID: "listener:ftp", Severity: event.SeverityHigh, Handler: "ftp",
			Meta: map[string]any{"retrieved": []any{"/home/admin/.ssh/id_rsa"}}},
	})
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "profile", profileView{Profile: prof}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"intent:", "path traversal to read /etc/passwd", // aggregated intent
		"attacks, misuse &amp; manipulation",  // consolidated catalog
		"vulnerabilities / exploit attempts:", // CVEs folded in
		"web-application attacks:",            // attack classes folded in
		"protocol misuse / manipulation:",     // non-webapp anomalies folded in
		"per-protocol summary",                // protocol intel beyond TLS
		"URLs requested", "/cgi-bin/",         // requested URLs
		"HTTP headers seen", "user-agent", // headers
		"files downloaded / exfiltrated", "id_rsa", // files taken
		"honeytokens served / stolen", "AKIA_HONEY_KEY", // honeytokens
	} {
		if !strings.Contains(out, want) {
			t.Errorf("profile detail missing %q\nbody: %q", want, out)
		}
	}
	// The folded-in standalone sections should no longer render their own headers.
	for _, gone := range []string{"<h2>CVE exploit attempts</h2>", "<h2>web-attack classes</h2>", "<h2>anomalies</h2>"} {
		if strings.Contains(out, gone) {
			t.Errorf("standalone section %q should be folded into the consolidated catalog", gone)
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
