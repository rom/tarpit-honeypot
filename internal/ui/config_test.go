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
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"fmtTime": func(any) string { return "" },
		"join":    func([]int) string { return "" },
	}).Parse(tmpls)
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
