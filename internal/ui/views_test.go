package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestHostsTemplateRenders(t *testing.T) {
	p := hostsPage{Enabled: true, Hosts: []HostView{
		{IP: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "ws-1", Vendor: "Dell", Source: "dhcp", Allowed: false, FirstSeen: time.Now(), LastSeen: time.Now(), Count: 3},
		{IP: "2001:db8::1", Source: "conn", Allowed: true, Count: 1},
	}}
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "hosts", p); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"known / seen hosts", "10.0.0.5", "aa:bb:cc:dd:ee:ff", "2001:db8::1", "allow", `href="/hosts"`, `href="/alerting"`} {
		if !strings.Contains(html, want) {
			t.Errorf("hosts page missing %q", want)
		}
	}
}

func TestHostsEmptyPlaceholder(t *testing.T) {
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "hosts", hostsPage{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "No hosts learned") || !strings.Contains(out, "disabled") {
		t.Errorf("empty hosts page should note disabled + empty: %q", out)
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
