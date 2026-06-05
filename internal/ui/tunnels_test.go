package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestTunnelKindURL(t *testing.T) {
	cases := map[string]string{
		"dns-tunnel":    "/events?q=dns-tunnel",
		"icmp-tunnel":   "/events?q=icmp_tunnel",
		"dga-domain":    "/events?q=dga",
		"encapsulation": "/events?q=encapsulation",
	}
	for kind, want := range cases {
		if got := tunnelKindURL(kind, ""); got != want {
			t.Errorf("tunnelKindURL(%q,'') = %q, want %q", kind, got, want)
		}
	}
	if got := tunnelKindURL("dns-tunnel", "1.2.3.4"); got != "/events?q=dns-tunnel&source=1.2.3.4" {
		t.Errorf("source-scoped = %q", got)
	}
}

// The tunnels page renders the "kind" labels (by-type bars + the by-source and
// recent table chips) as links to the events that produced each detection.
func TestTunnelsPageKindLinks(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{RuleID: "listener:dns", Handler: "dns", Time: now, Source: event.Endpoint{IP: "9.9.9.9"},
			Meta: map[string]any{"anomalies": []any{"dns-tunnel-suspected"}, "qname": "x.evil"}},
		{RuleID: "sniffer:encapsulation", Handler: "raw", Time: now.Add(-time.Minute), Source: event.Endpoint{IP: "8.8.8.8"},
			Meta: map[string]any{"encap_type": "gre"}},
	}
	v := buildTunnelsView(now.Add(-time.Hour), evs)

	// by-type bars carry an Href.
	var dnsBar bool
	for _, b := range v.Types {
		if b.Label == "dns-tunnel" && b.Href == "/events?q=dns-tunnel" {
			dnsBar = true
		}
	}
	if !dnsBar {
		t.Errorf("dns-tunnel by-type bar not linked: %+v", v.Types)
	}

	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "tunnels", v); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{
		`href="/events?q=dns-tunnel"`,                    // by-type bar
		`href="/events?q=encapsulation"`,                 // by-type bar (rule-id token)
		`href="/events?q=dns-tunnel&amp;source=9.9.9.9"`, // by-source / recent chip (scoped)
	} {
		if !strings.Contains(html, want) {
			t.Errorf("tunnels page missing kind link %q", want)
		}
	}
}
