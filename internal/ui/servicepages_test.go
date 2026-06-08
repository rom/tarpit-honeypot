package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestServiceCategory(t *testing.T) {
	cases := map[string]string{
		"dns": "dns", "http": "web", "https": "web",
		"mysql": "database", "postgres": "database", "redis": "database",
		"mongodb": "database",
		"ssh": "remote", "ssh_interactive": "remote", "telnet": "remote",
		"rdp": "remote", "vnc": "remote",
		"smtp_recv": "mail", "smtps": "mail", "pop3": "mail", "imaps": "mail",
		"ntp": "ntp",
		"ftp_files": "",
	}
	for h, want := range cases {
		if got := serviceCategory(h); got != want {
			t.Errorf("serviceCategory(%q) = %q, want %q", h, got, want)
		}
	}
}

func TestHasServicePage(t *testing.T) {
	s := &Server{fullConfig: &config.Config{Listeners: []config.Listener{
		{Handler: "dns"}, {Handler: "mysql"},
	}}}
	if !s.hasServicePage("dns") || !s.hasServicePage("database") {
		t.Error("expected dns + database pages available")
	}
	if s.hasServicePage("web") {
		t.Error("no web listener configured; web page must not be available")
	}
	// honeynet host services also count.
	s2 := &Server{fullConfig: &config.Config{Honeynets: []config.Honeynet{{
		Hosts: []config.HoneynetHost{{Services: []config.HoneynetService{{Port: 80, Handler: "http"}}}},
	}}}}
	if !s2.hasServicePage("web") {
		t.Error("honeynet http service should make the web page available")
	}
	if (&Server{}).hasServicePage("dns") {
		t.Error("nil config must report no pages")
	}
}

func TestBuildDNSAndRender(t *testing.T) {
	now := time.Now()
	mk := func(ip, qname, qtype, intent string, anoms ...string) *event.Event {
		m := map[string]any{"qname": qname, "qtype_name": qtype}
		if intent != "" {
			m["intent"] = intent
		}
		return &event.Event{Time: now, Source: event.Endpoint{IP: ip}, Handler: "dns",
			BannerSent: "dns answer (" + qtype + ")", Anomalies: anoms, Meta: m}
	}
	evs := []*event.Event{
		mk("1.1.1.1", "www.example.com", "A", ""),
		mk("1.1.1.1", "mail.example.com", "MX", ""),
		mk("2.2.2.2", "x.evil.test", "TXT", "DNS tunneling / data exfiltration over DNS", "dns-tunneling-qtype"),
		mk("2.2.2.2", "internal.corp", "AXFR", "DNS zone transfer (AXFR/IXFR) — full-zone reconnaissance", "dns-zone-transfer"),
	}
	v := buildDNS(evs)
	if len(v.Intents) == 0 {
		t.Error("expected aggregated attacker-intent rows")
	}
	if v.Empty || v.Total != 4 {
		t.Fatalf("Total = %d, empty=%v", v.Total, v.Empty)
	}
	if v.Sources != 2 {
		t.Errorf("Sources = %d, want 2", v.Sources)
	}
	if len(v.Figs) == 0 || len(v.Queries) != 4 {
		t.Errorf("figs=%d queries=%d", len(v.Figs), len(v.Queries))
	}
	// example.com should be a top domain (2 of the qnames reduce to it).
	var sawTunnel bool
	for _, a := range v.Attacks {
		if a.Name == "dns-tunneling-qtype" {
			sawTunnel = true
		}
	}
	if !sawTunnel {
		t.Errorf("dns-tunneling-qtype not in attack table: %+v", v.Attacks)
	}
	if len(v.TopDomains) == 0 || len(v.Attackers) == 0 {
		t.Errorf("expected TopDomains + Attackers drill-down tables; got %d / %d", len(v.TopDomains), len(v.Attackers))
	}
	var b strings.Builder
	v.RangeLabel = "last 24h"
	if err := uiTmpl(t).ExecuteTemplate(&b, "dns", v); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"DNS analytics", "Query log", "dns-zone-transfer", "www.example.com",
		`href="#domains"`, `href="#sources"`, `id="domains"`, `id="sources"`, "Top domains", "Top sources",
		"Attacker intent", "full-zone reconnaissance"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("dns page missing %q", want)
		}
	}
}

func TestBuildWebAndRender(t *testing.T) {
	now := time.Now()
	mk := func(ip, uri, status string, hdrs map[string]string, attacks []string) *event.Event {
		// The real handler flags each webapp_attacks class as an anomaly too.
		var anoms []string
		for _, a := range attacks {
			anoms = append(anoms, "webapp:"+a)
		}
		return &event.Event{Time: now, Source: event.Endpoint{IP: ip}, Handler: "http", Anomalies: anoms,
			BannerSent: "HTTP/1.1 " + status + "\r\nServer: nginx\r\n",
			Meta:       map[string]any{"http_uri": uri, "http_headers": hdrs, "webapp_attacks": attacks}}
	}
	evs := []*event.Event{
		mk("9.9.9.9", "/index.php", "200 OK", map[string]string{"User-Agent": "curl", "Host": "x"}, nil),
		mk("9.9.9.9", "/admin.php", "404 Not Found", map[string]string{"User-Agent": "curl"}, nil),
		mk("8.8.8.8", "/search.php?q=1' OR '1'='1", "200 OK", map[string]string{"User-Agent": "sqlmap"}, []string{"sqli"}),
		mk("8.8.8.8", "/.env", "200 OK", nil, nil),
	}
	v := buildWeb(evs)
	if v.Empty || v.Total != 4 {
		t.Fatalf("Total=%d empty=%v", v.Total, v.Empty)
	}
	if v.URLs != 4 {
		t.Errorf("URLs = %d, want 4", v.URLs)
	}
	// admin.php / index.php / .env are "files"; /search.php has a file segment too.
	var sawFile bool
	for _, f := range v.Files {
		if f == "admin.php" {
			sawFile = true
		}
	}
	if !sawFile {
		t.Errorf("expected admin.php in files: %v", v.Files)
	}
	if len(v.Attackers) == 0 {
		t.Error("expected top attackers")
	}
	var b strings.Builder
	v.RangeLabel = "last 24h"
	if err := uiTmpl(t).ExecuteTemplate(&b, "web", v); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"web analytics", "Top attackers", "Unique URLs", "webapp:sqli"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("web page missing %q", want)
		}
	}
}

func TestBuildDatabasesAndRender(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{Time: now, Source: event.Endpoint{IP: "7.7.7.7"}, Handler: "mysql", BannerSent: "5.7.30",
			Anomalies: []string{"mysql-login-attempt"}, Meta: map[string]any{"username": "root", "database": "intranet"}},
		{Time: now, Source: event.Endpoint{IP: "7.7.7.7"}, Handler: "redis",
			Anomalies: []string{"redis-config-set"}, Meta: map[string]any{"commands": []string{"AUTH", "CONFIG SET"}}},
		{Time: now, Source: event.Endpoint{IP: "6.6.6.6"}, Handler: "mongodb",
			Meta: map[string]any{"mongo_command": "listDatabases"}},
	}
	v := buildDatabases(evs)
	if v.Empty || v.Total != 3 {
		t.Fatalf("Total=%d empty=%v", v.Total, v.Empty)
	}
	var sawLogin bool
	for _, a := range v.Attacks {
		if a.Name == "mysql-login-attempt" {
			sawLogin = true
		}
	}
	if !sawLogin {
		t.Errorf("mysql-login-attempt missing from attacks: %+v", v.Attacks)
	}
	var b strings.Builder
	v.RangeLabel = "last 24h"
	if err := uiTmpl(t).ExecuteTemplate(&b, "databases", v); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"database analytics", "redis-config-set", "Top databases", "mysql-login-attempt"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("databases page missing %q", want)
		}
	}
}

func TestAttackTableCVEAndCWE(t *testing.T) {
	ev := &event.Event{Handler: "http", Anomalies: []string{"cve:CVE-2021-44228", "webapp:sqli"}}
	rows := attackTable([]*event.Event{ev})
	var cveRow, sqliRow *attackRow
	for i := range rows {
		if rows[i].CVE == "CVE-2021-44228" {
			cveRow = &rows[i]
		}
		if rows[i].Name == "webapp:sqli" {
			sqliRow = &rows[i]
		}
	}
	if cveRow == nil {
		t.Fatalf("CVE row missing: %+v", rows)
	}
	if sqliRow == nil {
		t.Errorf("sqli anomaly row missing")
	}
	// The CVE must not also be double-counted as a plain anomaly row.
	for _, r := range rows {
		if r.Name == "cve:CVE-2021-44228" && r.CVE == "" {
			t.Error("cve: anomaly should be folded into the CVE row, not a separate anomaly")
		}
	}
}
