package ui

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestSortEventsBySeverityAndTime(t *testing.T) {
	mk := func(sev event.Severity, sec int64) *event.Event {
		return &event.Event{Severity: sev, Time: time.Unix(sec, 0)}
	}
	evs := []*event.Event{mk(event.SeverityLow, 30), mk(event.SeverityCritical, 10), mk(event.SeverityMedium, 20)}

	sortEvents(evs, "severity", "asc")
	if evs[0].Severity != event.SeverityLow || evs[2].Severity != event.SeverityCritical {
		t.Errorf("severity asc wrong: %v %v %v", evs[0].Severity, evs[1].Severity, evs[2].Severity)
	}
	sortEvents(evs, "severity", "desc")
	if evs[0].Severity != event.SeverityCritical {
		t.Errorf("severity desc should lead with critical; got %v", evs[0].Severity)
	}
	sortEvents(evs, "time", "asc")
	if !evs[0].Time.Before(evs[2].Time) {
		t.Error("time asc not chronological")
	}
	sortEvents(evs, "time", "desc")
	if evs[0].Time.Before(evs[2].Time) {
		t.Error("time desc not reverse-chronological")
	}
}

func TestBuildSortHeadersTogglesAndCarriesFilters(t *testing.T) {
	q := url.Values{"source": {"1.2.3.4"}, "severity": {"high"}}
	h := buildSortHeaders("/events", q, "time", "desc")
	timeH := h["time"]
	// active column shows the descending arrow and toggles to asc.
	if !strings.Contains(timeH.Arrow, "▼") {
		t.Errorf("active time column arrow = %q", timeH.Arrow)
	}
	if !strings.Contains(timeH.Href, "order=asc") || !strings.Contains(timeH.Href, "sort=time") {
		t.Errorf("time header should toggle to asc: %q", timeH.Href)
	}
	// filters are preserved in every header link.
	if !strings.Contains(timeH.Href, "source=1.2.3.4") || !strings.Contains(timeH.Href, "severity=high") {
		t.Errorf("filters not carried in sort link: %q", timeH.Href)
	}
	// inactive column has no arrow and defaults to asc.
	if h["rule"].Arrow != "" || !strings.Contains(h["rule"].Href, "order=asc") {
		t.Errorf("inactive rule header wrong: %+v", h["rule"])
	}
}

func TestFilterHosts(t *testing.T) {
	hosts := []HostView{
		{IP: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "ws-1", Vendor: "Dell", Source: "dhcp", Allowed: false},
		{IP: "10.0.0.6", Hostname: "printer", Vendor: "HP", Source: "arp", Allowed: true},
	}
	if got := filterHosts(hosts, "dell", ""); len(got) != 1 || got[0].IP != "10.0.0.5" {
		t.Errorf("vendor substring filter: %+v", got)
	}
	if got := filterHosts(hosts, "", "allow"); len(got) != 1 || !got[0].Allowed {
		t.Errorf("allow status filter: %+v", got)
	}
	if got := filterHosts(hosts, "", "seen"); len(got) != 1 || got[0].Allowed {
		t.Errorf("seen status filter: %+v", got)
	}
	if got := filterHosts(hosts, "10.0.0.", ""); len(got) != 2 {
		t.Errorf("ip substring should match both: %+v", got)
	}
	if got := filterHosts(hosts, "", ""); len(got) != 2 {
		t.Errorf("empty filter should return all: %+v", got)
	}
}

func TestIsOperationalEvent(t *testing.T) {
	cases := map[string]bool{
		"sensor:listener_stopped": true,
		"sensor:canary_stopped":   true,
		"sensor:listener_error":   true,
		"listener:ssh:accept_cap": true,
		"sensor:panic":            true,
		"sensor:reload":           false, // audit, not an error
		"listener:ssh-bait":       false,
		"correlate:port_scan":     false,
	}
	for rule, want := range cases {
		if got := isOperationalEvent(rule); got != want {
			t.Errorf("isOperationalEvent(%q) = %v; want %v", rule, got, want)
		}
	}
}

func TestEventsAndErrorsTemplatesRender(t *testing.T) {
	tmpl := uiTmpl(t)
	// events page with sort headers.
	ep := eventsPage{
		Events:  []*event.Event{{ID: "x", RuleID: "listener:ssh", Severity: event.SeverityHigh, Time: time.Now()}},
		Headers: buildSortHeaders("/events", url.Values{}, "time", "desc"),
	}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "events", ep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "sort=severity") || !strings.Contains(b.String(), `href="/errors"`) {
		t.Errorf("events page missing sortable header / errors nav: %q", b.String())
	}

	// errors page.
	b.Reset()
	xp := errorsPage{Events: []*event.Event{{ID: "y", RuleID: "sensor:listener_stopped", Severity: event.SeverityMedium, Time: time.Now()}}}
	if err := tmpl.ExecuteTemplate(&b, "errors", xp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "operational errors") || !strings.Contains(b.String(), "sensor:listener_stopped") {
		t.Errorf("errors page missing content: %q", b.String())
	}
}
