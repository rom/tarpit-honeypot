package ui

import (
	"html/template"
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// configYAML marshals the wired config; with a secret referenced via an
// *_env field, the env var NAME (not its value) appears.
func TestConfigYAMLRedactsSecrets(t *testing.T) {
	s := &Server{fullConfig: &config.Config{
		Sensor: config.Sensor{Name: "test-sensor", DataDir: "/var/lib/tp"},
		Channels: []config.Channel{
			{ID: "hook", Type: "webhook", URL: "https://x/y", HMACSecretEnv: "TARPIT_HOOK_SECRET"},
		},
	}}
	out := s.configYAML()
	if !strings.Contains(out, "test-sensor") {
		t.Errorf("config YAML missing sensor name: %q", out)
	}
	// The env-var name appears; no actual secret value does (the model
	// never stores one).
	if !strings.Contains(out, "TARPIT_HOOK_SECRET") {
		t.Errorf("hmac_secret_env name should appear: %q", out)
	}
}

func TestConfigYAMLNilConfig(t *testing.T) {
	s := &Server{}
	if !strings.Contains(s.configYAML(), "not available") {
		t.Errorf("nil config should render a placeholder")
	}
}

// The config template renders the YAML inside the page.
func TestConfigTemplateRenders(t *testing.T) {
	tmpl, err := template.New("").Funcs(tmplFuncs(func() int { return 0 }, "nvd", "", true, navFuncs{has: func(string) bool { return true }, enabled: func(string) bool { return true }})).Parse(tmpls)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	err = tmpl.ExecuteTemplate(&b, "config", configPage{YAML: "sensor:\n  name: demo\n"})
	if err != nil {
		t.Fatal(err)
	}
	html := b.String()
	if !strings.Contains(html, "effective configuration") {
		t.Errorf("config page title missing")
	}
	if !strings.Contains(html, "name: demo") {
		t.Errorf("config YAML not embedded in page: %q", html)
	}
	// The nav should link to /config.
	if !strings.Contains(html, `href="/config"`) {
		t.Errorf("nav missing config link")
	}
}

// TestConfigStoragePanelRenders: the /config page surfaces the event-store size
// cap, current usage, percent-of-cap, and (when over cap) an "evicting" tag, so
// operators can see retention limits without reading logs.
func TestConfigStoragePanelRenders(t *testing.T) {
	page := configPage{
		YAML:         "sensor: {}\n",
		DBStatsKnown: true,
		DBBackend:    "sqlite",
		DBCapMB:      500,
		DBFileMB:     599,
		DBUsedMB:     599,
		DBUsedPct:    119,
	}
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "config", page); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"event store retention", "size cap", "500 MB", "599 MB", "119%", "evicting", "sqlite_mb"} {
		if !strings.Contains(html, want) {
			t.Errorf("storage panel missing %q", want)
		}
	}
}

func TestConfigFilesPanelRenders(t *testing.T) {
	page := configPage{
		YAML: "sensor: {}\n",
		Files: []fileRow{
			{Category: "enrichment", Key: "oui_file", Path: "/etc/thp/oui.csv", Access: "read", Exists: true},
			{Category: "enrichment", Key: "tor.exit_file", Path: "/etc/thp/tor.txt", Access: "read", Exists: false},
			{Category: "state", Key: "events_db", Path: "/var/lib/thp/events.db", Access: "write", Exists: false},
		},
	}
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "config", page); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"files in use", "oui_file", "/etc/thp/oui.csv", "tor.exit_file", "MISSING", "pending"} {
		if !strings.Contains(html, want) {
			t.Errorf("config files panel missing %q", want)
		}
	}
}
