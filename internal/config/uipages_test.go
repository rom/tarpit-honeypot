package config

import (
	"strings"
	"testing"
)

func TestUIPageEnabled(t *testing.T) {
	// No overrides: everything enabled.
	var u UI
	for _, slug := range []string{"charts", "dns", "web", "databases", "docs", "summary"} {
		if !u.PageEnabled(slug) {
			t.Errorf("default PageEnabled(%q) = false, want true", slug)
		}
	}
	// Core pages can never be disabled, even if listed.
	u = UI{Pages: map[string]bool{"events": false, "summary": false, "charts": false}}
	if !u.PageEnabled("events") || !u.PageEnabled("summary") {
		t.Error("core pages must stay enabled")
	}
	if u.PageEnabled("charts") {
		t.Error("charts was disabled and must report false")
	}
	// A togglable page explicitly true stays on; unlisted stays on.
	u = UI{Pages: map[string]bool{"charts": true}}
	if !u.PageEnabled("charts") || !u.PageEnabled("fleet") {
		t.Error("explicit-true and unlisted togglable pages should be enabled")
	}
}

func TestUIServiceActivityEnabled(t *testing.T) {
	if !(UI{}).ServiceActivityEnabled() {
		t.Error("default service-activity should be on")
	}
	off := false
	if (UI{ServiceActivity: &off}).ServiceActivityEnabled() {
		t.Error("service_activity:false must disable")
	}
	on := true
	if !(UI{ServiceActivity: &on}).ServiceActivityEnabled() {
		t.Error("service_activity:true must enable")
	}
}

func TestValidateRejectsUnknownPage(t *testing.T) {
	base := func(pages map[string]bool) *Config {
		c := &Config{UI: UI{Enabled: true, Bind: "127.0.0.1:8088", Pages: pages}}
		c.applyDefaults()
		return c
	}
	err := base(map[string]bool{"chrats": false}).Validate()
	if err == nil || !strings.Contains(err.Error(), "ui.pages") {
		t.Fatalf("expected a ui.pages validation error for a typo'd slug, got %v", err)
	}
	// A correct slug must not trip the ui.pages check.
	if err := base(map[string]bool{"charts": false}).Validate(); err != nil && strings.Contains(err.Error(), "ui.pages") {
		t.Errorf("valid slug should not trip the ui.pages check: %v", err)
	}
}
