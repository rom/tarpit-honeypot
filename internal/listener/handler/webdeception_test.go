package handler

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestWebDeceptionDefaultsAndContent(t *testing.T) {
	var wd config.WebDeception // all-zero → defaults, enabled
	if !wd.On() {
		t.Fatal("web deception should default ON")
	}
	if len(wd.Disallow()) == 0 || len(wd.Contacts()) == 0 || len(wd.Pages()) == 0 {
		t.Fatal("defaults must be non-empty")
	}
	// Honeytoken accounts must include both full address and local-part.
	accts := map[string]bool{}
	for _, a := range wd.HoneytokenAccounts() {
		accts[a] = true
	}
	if !accts["security"] || !accts["security@example.com"] {
		t.Errorf("honeytoken accounts missing local-part/full: %v", wd.HoneytokenAccounts())
	}

	robots := robotsTxt(wd.Disallow())
	if !strings.Contains(robots, "User-agent: *") || !strings.Contains(robots, "Disallow: /admin/") || !strings.Contains(robots, "Sitemap: /sitemap.xml") {
		t.Errorf("robots.txt malformed: %q", robots)
	}
	sec := securityTxt(wd.Contacts(), "", "")
	if !strings.Contains(sec, "Contact: mailto:security@example.com") || !strings.Contains(sec, "Expires:") || !strings.Contains(sec, "Policy:") {
		t.Errorf("security.txt malformed: %q", sec)
	}
	sm := sitemapXML(wd.Pages())
	if !strings.Contains(sm, "<urlset") || !strings.Contains(sm, "<loc>/admin/login</loc>") {
		t.Errorf("sitemap.xml malformed: %q", sm)
	}
}

func TestServeWebDeceptionRoutes(t *testing.T) {
	var wd config.WebDeception

	// robots.txt served.
	res := &Result{Meta: map[string]any{}}
	out := serveWebDeception(nil, wd, "GET", "/robots.txt", "nginx", res)
	if !strings.Contains(out, "200 OK") || !strings.Contains(out, "Disallow:") || res.Meta["web_deception"] != "robots.txt" {
		t.Errorf("robots.txt route wrong: %q meta=%v", out, res.Meta["web_deception"])
	}

	// security.txt served with honeytoken contacts.
	res = &Result{Meta: map[string]any{}}
	out = serveWebDeception(nil, wd, "GET", "/.well-known/security.txt", "nginx", res)
	if !strings.Contains(out, "security@example.com") || res.Meta["web_deception"] != "security.txt" {
		t.Errorf("security.txt route wrong: %q", out)
	}

	// A Disallow bait path is flagged and 403'd.
	res = &Result{Meta: map[string]any{}}
	out = serveWebDeception(nil, wd, "GET", "/admin/", "nginx", res)
	if !strings.Contains(out, "403 Forbidden") || !hasAnom(*res, "robots-honeypot-access") {
		t.Errorf("bait path not flagged: %q anoms=%v", out, metaAnoms(*res))
	}

	// A sitemap page (tarpit OFF for the test) is flagged and served.
	off := false
	wd.SitemapTarpit = &off
	res = &Result{Meta: map[string]any{}}
	out = serveWebDeception(nil, wd, "GET", "/hr/payroll.xlsx", "nginx", res)
	if !strings.Contains(out, "200 OK") || !hasAnom(*res, "sitemap-honeypot-access") {
		t.Errorf("sitemap page not flagged: %q anoms=%v", out, metaAnoms(*res))
	}

	// A non-decoy path falls through (empty return).
	res = &Result{Meta: map[string]any{}}
	if out = serveWebDeception(nil, wd, "GET", "/normal-page", "nginx", res); out != "" {
		t.Errorf("normal path should fall through, got %q", out)
	}

	// Disabled → no handling.
	dis := false
	wd2 := config.WebDeception{Enabled: &dis}
	res = &Result{Meta: map[string]any{}}
	if out = serveWebDeception(nil, wd2, "GET", "/robots.txt", "nginx", res); out != "" {
		t.Errorf("disabled web deception should not serve, got %q", out)
	}
}
