package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// ipv6Tag must badge only genuine IPv6 literals — never IPv4, hostnames, or junk.
func TestIPv6Tag(t *testing.T) {
	cases := []struct {
		in   string
		want bool // expect the IPv6 badge
	}{
		{"1.2.3.4", false},
		{"203.0.113.9", false},
		{"2001:db8::1", true},
		{"fe80::1", true},
		{"::1", true},
		{"2606:4700:4700::1111", true},
		{"", false},
		{"not-an-ip", false},
		{"example.com", false},
		{"::ffff:1.2.3.4", false}, // IPv4-mapped — To4() != nil, so IPv4
	}
	for _, c := range cases {
		got := strings.Contains(string(ipv6Tag(c.in)), "IPv6")
		if got != c.want {
			t.Errorf("ipv6Tag(%q) badged=%v want %v", c.in, got, c.want)
		}
	}
}

func TestBuildCredentialsAndRender(t *testing.T) {
	now := time.Now()
	mk := func(ip, user, pass string) *event.Event {
		return &event.Event{Time: now, Source: event.Endpoint{IP: ip}, Handler: "ssh",
			Meta: map[string]any{"username": user, "password": pass}}
	}
	evs := []*event.Event{
		// 10.0.0.1 sprays one password across many users.
		mk("10.0.0.1", "root", "123456"),
		mk("10.0.0.1", "admin", "123456"),
		mk("10.0.0.1", "user", "123456"),
		mk("10.0.0.1", "test", "123456"),
		mk("10.0.0.1", "oracle", "123456"),
		// 10.0.0.2 brute-forces one user with many passwords.
		mk("10.0.0.2", "root", "p1"),
		mk("10.0.0.2", "root", "p2"),
		mk("10.0.0.2", "root", "p3"),
		mk("10.0.0.2", "root", "p4"),
		mk("10.0.0.2", "root", "p5"),
		// reuse: "123456" also seen from a second source.
		mk("2001:db8::9", "guest", "123456"),
	}
	v := buildCredentials(evs)
	if v.Empty {
		t.Fatal("expected non-empty credential view")
	}
	if v.Total != len(evs) {
		t.Errorf("Total = %d want %d", v.Total, len(evs))
	}
	if v.Sources != 3 {
		t.Errorf("Sources = %d want 3", v.Sources)
	}
	if len(v.Figs) == 0 {
		t.Error("expected credential figures")
	}
	// spray classification present.
	var sawSpray, sawBrute bool
	for _, r := range v.Spray {
		if r.Source == "10.0.0.1" && r.Verdict == "password spray" {
			sawSpray = true
		}
		if r.Source == "10.0.0.2" && r.Verdict == "brute force" {
			sawBrute = true
		}
	}
	if !sawSpray || !sawBrute {
		t.Errorf("spray verdicts wrong: %+v", v.Spray)
	}
	// reuse: 123456 from 2 distinct sources.
	var reuse123 *reuseRow
	for i := range v.Reuse {
		if v.Reuse[i].Secret == "123456" {
			reuse123 = &v.Reuse[i]
		}
	}
	if reuse123 == nil || reuse123.Sources < 2 {
		t.Errorf("expected 123456 reuse across >=2 sources: %+v", v.Reuse)
	}

	// Full template render, including the IPv6 badge on the v6 spray source.
	var b strings.Builder
	v.RangeLabel = "last 24h"
	if err := uiTmpl(t).ExecuteTemplate(&b, "credentials", v); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"password spray", "brute force", "IPv6"} {
		if !strings.Contains(html, want) {
			t.Errorf("credentials page missing %q", want)
		}
	}
}

func TestPassClassAndSprayVerdict(t *testing.T) {
	classes := map[string]string{
		"123456":   "digits only",
		"password": "lowercase only",
		"P@ssw0rd": "has symbol",
		"Abc123":   "mixed-case + digits",
		"abc123":   "letters + digits",
		"ABCDEF":   "letters only",
	}
	for in, want := range classes {
		if got := passClass(in); got != want {
			t.Errorf("passClass(%q) = %q want %q", in, got, want)
		}
	}
	verdicts := []struct {
		u, p, a int
		want    string
	}{
		{6, 1, 6, "password spray"},
		{1, 6, 6, "brute force"},
		{6, 6, 12, "credential stuffing"},
		{1, 1, 6, "repeated"},
		{1, 1, 1, "probe"},
	}
	for _, c := range verdicts {
		if got := sprayVerdict(c.u, c.p, c.a); got != c.want {
			t.Errorf("sprayVerdict(%d,%d,%d) = %q want %q", c.u, c.p, c.a, got, c.want)
		}
	}
}

func TestChartsAnalyticsBuilders(t *testing.T) {
	now := time.Date(2026, 6, 5, 13, 0, 0, 0, time.UTC)
	mk := func(ip string, dport int) *event.Event {
		return &event.Event{Time: now, Source: event.Endpoint{IP: ip}, Dest: event.Endpoint{Port: dport},
			Meta: map[string]any{"asn": "64500", "asn_org": "EvilNet", "geo_country": "CN"}}
	}
	evs := []*event.Event{
		mk("1.1.1.1", 23),
		mk("1.1.1.2", 23),
		mk("1.1.1.3", 23),
		mk("2.2.2.1", 445),
		mk("2.2.2.2", 445),
		mk("3.3.3.3", 8080),
	}

	if _, ok := portHourHeatmap(evs); !ok {
		t.Error("portHourHeatmap should produce a figure")
	}
	if _, ok := destPortLeaderboard(evs); !ok {
		t.Error("destPortLeaderboard should produce a figure")
	}
	if _, ok := entitySparklines("ASN trend", evs, func(e *event.Event) string { return asnLabel(e.Meta) }, 6, time.Hour); !ok {
		t.Error("entitySparklines should produce a figure")
	}
	if _, ok := actorGraph(evs); !ok {
		t.Error("actorGraph should produce a figure (>=2 sources)")
	}

	// Coverage gap: ports 23/445/8080 are probed; only 23 is configured.
	cfg := &config.Config{
		Listeners: []config.Listener{{Bind: "0.0.0.0:23"}},
	}
	fig, rows, ok := coverageGap(cfg, evs)
	if !ok {
		t.Fatal("coverageGap should report gaps")
	}
	_ = fig
	gapPorts := map[int]bool{}
	for _, r := range rows {
		gapPorts[r.Port] = true
	}
	if gapPorts[23] {
		t.Error("port 23 is configured and must not be a gap")
	}
	if !gapPorts[445] || !gapPorts[8080] {
		t.Errorf("expected 445 and 8080 as coverage gaps: %+v", rows)
	}
}
