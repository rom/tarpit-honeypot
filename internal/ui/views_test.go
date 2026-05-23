package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestDevicesTemplateRenders(t *testing.T) {
	p := hostsPage{Enabled: true, Hosts: []HostView{
		{Key: "aa:bb:cc:dd:ee:ff", IP: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "ws-1", Vendor: "Dell", Source: "dhcp", Allowed: false, FirstSeen: time.Now(), LastSeen: time.Now(), Count: 3, Services: []string{"ssh"}, Ports: []int{22}, Attrs: map[string]string{"ja3": "abc"}},
		{Key: "2001:db8::1", IP: "2001:db8::1", Source: "conn", Allowed: true, Count: 1},
	}}
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "devices", p); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"known / seen devices", "10.0.0.5", "aa:bb:cc:dd:ee:ff", "2001:db8::1", "allow", `href="/devices"`, "ssh", "ja3=abc"} {
		if !strings.Contains(html, want) {
			t.Errorf("devices page missing %q", want)
		}
	}
	// Read-only by default: no action forms.
	if strings.Contains(html, `action="/devices/action"`) {
		t.Errorf("read-only devices page should not render action forms")
	}
}

func TestDevicesSummaryPanelRenders(t *testing.T) {
	p := hostsPage{
		Enabled: true,
		Hosts:   []HostView{{Key: "10.0.0.9", IP: "10.0.0.9", Source: "conn", Count: 1}},
		Summary: &HostsSummary{
			Total: 5, Allowed: 3, Rogue: 2,
			BySource: []LabeledCount{{"arp", 3}, {"conn", 2}},
			ByClass:  []LabeledCount{{"ics-endpoint", 1}, {"scanner", 1}},
			Conflicts: []HostConflict{
				{IP: "10.0.0.50", MACs: []string{"00:90:e8:01:02:03", "aa:bb:cc:dd:ee:ff"}},
			},
		},
	}
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "devices", p); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{
		"inventory:", "allow-listed", "rogue", "arp=3", "ics-endpoint=1",
		"IP/MAC conflicts", "10.0.0.50", "00:90:e8:01:02:03", "aa:bb:cc:dd:ee:ff",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("devices summary panel missing %q", want)
		}
	}
	// With no conflicts, the conflict warning must not render.
	p.Summary.Conflicts = nil
	b.Reset()
	if err := uiTmpl(t).ExecuteTemplate(&b, "devices", p); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "IP/MAC conflicts") {
		t.Error("conflict panel should not render when there are no conflicts")
	}
}

func TestDevicesTemplateActionsEnabled(t *testing.T) {
	p := hostsPage{Enabled: true, ActionsEnabled: true, Token: "secret-tok", Hosts: []HostView{
		{Key: "10.0.0.9", IP: "10.0.0.9", Source: "conn", Count: 1},
	}}
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "devices", p); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{`action="/devices/action"`, `name="action" value="delete"`, `name="action" value="allow"`, "secret-tok"} {
		if !strings.Contains(html, want) {
			t.Errorf("actions-enabled devices page missing %q", want)
		}
	}
}

func TestDevicesEmptyPlaceholder(t *testing.T) {
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "devices", hostsPage{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "No devices learned") || !strings.Contains(out, "disabled") {
		t.Errorf("empty devices page should note disabled + empty: %q", out)
	}
}

func TestAlertingViewDetectsChannels(t *testing.T) {
	s := &Server{fullConfig: &config.Config{
		Channels: []config.Channel{
			{ID: "soc-mail", Type: "smtp", Host: "mail.x", Port: 587, From: "a@x", To: []string{"soc@x"}, MinSeverity: "high"},
			{ID: "siem", Type: "syslog", Network: "tcp", Address: "siem:514", Format: "cef"},
			{ID: "log", Type: "jsonlog"},
		},
		Routes: []config.Route{
			{Match: config.Match{Severity: ">=critical", Honeynet: "ot"}, Channels: []string{"soc-mail"}},
		},
		Allowlist: []string{"10.0.0.0/8"},
	}}
	v := s.alertingView()
	if !v.HasEmail || !v.HasSyslog {
		t.Errorf("expected email + syslog detected; got %+v", v)
	}
	if v.HasSMS || v.HasWebhook {
		t.Error("sms/webhook should be off")
	}
	// local channel flagged.
	var logLocal bool
	for _, c := range v.Channels {
		if c.ID == "log" {
			logLocal = c.Local
		}
		if c.ID == "siem" && c.Destination != "tcp siem:514" {
			t.Errorf("syslog destination = %q", c.Destination)
		}
	}
	if !logLocal {
		t.Error("jsonlog should be marked local")
	}
	if len(v.Routes) != 1 || !strings.Contains(v.Routes[0].Match, "honeynet=ot") {
		t.Errorf("route match summary wrong: %+v", v.Routes)
	}

	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "alerting", v); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	if !strings.Contains(html, "alerting") || !strings.Contains(html, "soc-mail") || !strings.Contains(html, "configured") {
		t.Errorf("alerting page missing expected content: %q", html)
	}
}
