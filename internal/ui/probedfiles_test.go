package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// buildProfile must aggregate the specific sensitive files a source probed
// (recorded by the web decoy as meta.probed_file) into ProbedFiles, so the
// secret-file-probe anomaly can be drilled into the actual filenames.
func TestProfileAggregatesProbedFiles(t *testing.T) {
	now := time.Now()
	mk := func(file string) *event.Event {
		return &event.Event{
			Time:      now,
			Source:    event.Endpoint{IP: "9.9.9.9"},
			RuleID:    "listener:http",
			Severity:  event.SeverityHigh,
			Handler:   "http",
			Anomalies: []string{"webapp:secret-file-probe"},
			Meta:      map[string]any{"probed_file": file},
		}
	}
	evs := []*event.Event{mk("/.env"), mk("/config.php.bak"), mk("/.env"), mk("/etc/passwd")}
	p := buildProfile("9.9.9.9", evs)

	want := map[string]bool{"/.env": true, "/config.php.bak": true, "/etc/passwd": true}
	if len(p.ProbedFiles) != len(want) {
		t.Fatalf("ProbedFiles = %v, want the 3 distinct files", p.ProbedFiles)
	}
	for _, f := range p.ProbedFiles {
		if !want[f] {
			t.Errorf("unexpected probed file %q", f)
		}
	}

	// And the profile page renders them under a "sensitive files probed" heading.
	var b strings.Builder
	view := profileView{Profile: p, RuleHeaders: ruleHeaders{
		Rule:  sortLink{Href: "#"},
		Count: sortLink{Href: "#"},
	}}
	if err := uiTmpl(t).ExecuteTemplate(&b, "profile", view); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	if !strings.Contains(html, "sensitive files probed") || !strings.Contains(html, "/config.php.bak") {
		t.Errorf("profile page missing the probed-files section")
	}
}

func TestMatchesFamily(t *testing.T) {
	cases := []struct {
		ip, fam string
		want    bool
	}{
		{"2001:db8::1", "ipv6", true},
		{"2001:db8::1", "ipv4", false},
		{"1.2.3.4", "ipv4", true},
		{"1.2.3.4", "ipv6", false},
		{"1.2.3.4", "v4", true},
		{"2001:db8::1", "6", true},
		{"1.2.3.4", "", true},        // empty family is a no-op (matches all)
		{"2001:db8::1", "", true},    // empty family is a no-op
		{"1.2.3.4", "garbage", true}, // unknown family is a no-op
	}
	for _, c := range cases {
		if got := matchesFamily(c.ip, c.fam); got != c.want {
			t.Errorf("matchesFamily(%q,%q) = %v want %v", c.ip, c.fam, got, c.want)
		}
	}
}
