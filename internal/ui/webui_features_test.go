package ui

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func TestCVEURL(t *testing.T) {
	if got := cveURL("", "CVE-2024-4577"); got != "https://nvd.nist.gov/vuln/detail/CVE-2024-4577" {
		t.Errorf("nvd default: %q", got)
	}
	if got := cveURL("cve.org", "CVE-2024-4577"); got != "https://www.cve.org/CVERecord?id=CVE-2024-4577" {
		t.Errorf("cve.org: %q", got)
	}
	for _, bad := range []string{"", "not-a-cve", "CVE-x", "CVE-2024", "cve-2024-1; rm -rf"} {
		if got := cveURL("nvd", bad); got != "" {
			t.Errorf("cveURL(%q) should be empty, got %q", bad, got)
		}
	}
}

func TestExternalOrigin(t *testing.T) {
	cases := map[string]string{
		"":                                "",
		"/static/world.png":               "",
		"https://tiles.example.com/w.png": "https://tiles.example.com",
		"http://10.0.0.5:8080/m.png":      "http://10.0.0.5:8080",
		"ftp://x/y":                       "",
		"javascript:alert(1)":             "",
	}
	for in, want := range cases {
		if got := externalOrigin(in); got != want {
			t.Errorf("externalOrigin(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestIPMatcher(t *testing.T) {
	m := newIPMatcher([]string{"10.0.0.1", "192.168.0.0/16", "2001:db8::/32"})
	for _, ip := range []string{"10.0.0.1", "192.168.5.5", "2001:db8::dead"} {
		if !m.match(ip) {
			t.Errorf("expected %s hidden", ip)
		}
	}
	for _, ip := range []string{"10.0.0.2", "8.8.8.8", "2001:dead::1", ""} {
		if m.match(ip) {
			t.Errorf("expected %s visible", ip)
		}
	}
	if newIPMatcher(nil) != nil || newIPMatcher([]string{"garbage"}) != nil {
		t.Error("empty/garbage matcher should be nil")
	}
}

func TestHiddenIPsFilteredFromViews(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.Insert(ctx, &event.Event{ID: "1", Time: now, Sensor: "s", RuleID: "listener:ssh",
		Severity: event.SeverityHigh, Source: event.Endpoint{IP: "9.9.9.9"}, Handler: "ssh"})
	_ = st.Insert(ctx, &event.Event{ID: "2", Time: now, Sensor: "s", RuleID: "listener:ssh",
		Severity: event.SeverityHigh, Source: event.Endpoint{IP: "1.2.3.4"}, Handler: "ssh"})

	srv, err := New(config.UI{Enabled: true, Bind: "127.0.0.1:0", HiddenIPs: []string{"9.9.9.9"}}, st)
	if err != nil {
		t.Fatal(err)
	}
	// query() drops hidden-source events.
	evs, _ := srv.query(ctx, store.Filter{Since: now.Add(-time.Hour), Limit: 100})
	for _, ev := range evs {
		if ev.Source.IP == "9.9.9.9" {
			t.Errorf("hidden IP leaked through query(): %+v", ev)
		}
	}
	if len(evs) != 1 {
		t.Errorf("expected 1 visible event, got %d", len(evs))
	}
	// The hidden IP's profile is not found.
	w := httptest.NewRecorder()
	srv.handleProfile(w, httptest.NewRequest("GET", "/profiles/9.9.9.9", nil))
	if w.Code != 404 {
		t.Errorf("hidden profile should 404, got %d", w.Code)
	}
	// The visible IP's profile still works.
	w = httptest.NewRecorder()
	srv.handleProfile(w, httptest.NewRequest("GET", "/profiles/1.2.3.4", nil))
	if w.Code != 200 {
		t.Errorf("visible profile should 200, got %d", w.Code)
	}
}

func TestAttackURL(t *testing.T) {
	cases := map[string]string{
		"T1190":     "https://attack.mitre.org/techniques/T1190/",
		"T1059.001": "https://attack.mitre.org/techniques/T1059/001/",
		"T0814":     "https://attack.mitre.org/techniques/T0814/",
		"":          "",
		"X1190":     "",
		"T1190; rm": "",
	}
	for in, want := range cases {
		if got := attackURL(in); got != want {
			t.Errorf("attackURL(%q) = %q; want %q", in, got, want)
		}
	}
	if attackType("T0814") != "ics" || attackType("T1190") != "enterprise" {
		t.Errorf("attackType wrong")
	}
}

func TestAttackLinkURLToggle(t *testing.T) {
	on := true
	off := false
	linkFunc := func(linkPtr *bool) func(string) string {
		funcs := tmplFuncs(func() int { return 0 }, "nvd", "", config.UI{AttackLinks: linkPtr}.AttackLinksEnabled(), navFuncs{has: func(string) bool { return true }, enabled: func(string) bool { return true }})
		return funcs["attackLinkURL"].(func(string) string)
	}
	// Enabled (default) -> external link; disabled -> "" so templates fall back
	// to the internal drill-down.
	if got := linkFunc(&on)("T1190"); got != "https://attack.mitre.org/techniques/T1190/" {
		t.Errorf("enabled attackLinkURL = %q", got)
	}
	if got := linkFunc(nil)("T1190"); got == "" { // omitted = on
		t.Error("omitted attack_links should default to enabled")
	}
	if got := linkFunc(&off)("T1190"); got != "" {
		t.Errorf("disabled attackLinkURL = %q; want empty", got)
	}
	// attackURL (the always-on canonical builder) is unaffected by the toggle.
	if attackURL("T1190") == "" {
		t.Error("attackURL should always build the canonical URL")
	}
}
