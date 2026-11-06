package enrich

import (
	"reflect"
	"sort"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestSourceClassPriority(t *testing.T) {
	cases := []struct {
		name string
		rule string
		meta map[string]any
		want string
	}{
		{"malware-rule", "malware:capture", map[string]any{}, "malicious"},
		{"high-threat", "listener:x", map[string]any{"threat_confidence": "high"}, "malicious"},
		{"spoofed", "listener:x", map[string]any{"spoofed_ptr": true}, "spoofed"},
		{"scanner", "listener:x", map[string]any{"known_scanner": "censys"}, "scanner"},
		{"tor", "listener:x", map[string]any{"tor_exit": true}, "anonymizer"},
		{"cloud", "listener:x", map[string]any{"cloud_provider": "aws"}, "hosting"},
		{"residential", "listener:x", map[string]any{"conn_type": "residential"}, "residential"},
		{"suspect", "listener:x", map[string]any{"threat_intel_hit": true}, "suspect"},
		{"nothing", "listener:x", map[string]any{"geo_country": "US"}, ""},
		// Priority: malware beats a spoofed-PTR tag on the same event.
		{"priority", "cve:CVE-2024-1", map[string]any{"spoofed_ptr": true, "known_scanner": "shodan"}, "malicious"},
	}
	for _, c := range cases {
		ev := &event.Event{RuleID: c.rule, Meta: c.meta}
		if got := sourceClass(ev); got != c.want {
			t.Errorf("%s: sourceClass = %q; want %q", c.name, got, c.want)
		}
	}
}

func TestDecorateRecognitionLabels(t *testing.T) {
	ev := &event.Event{
		RuleID: "listener:x",
		Meta: map[string]any{
			"geo_country": "RU", "geo_risk": true, "asn": uint32(64500),
			"tor_exit": true, "anonymized": true, "cloud_provider": "aws",
			"known_scanner": "censys",
			"conn_type":     "hosting", "threat_confidence": "medium",
			"spoofed_ptr": true, "targeting": "web-cms", "novel_asn": true,
		},
	}
	decorateRecognition(ev)

	// source_class set (spoofed wins over scanner/hosting here; not malicious).
	if ev.Meta["source_class"] != "spoofed" {
		t.Errorf("source_class = %v; want spoofed", ev.Meta["source_class"])
	}
	labels, ok := ev.Meta["labels"].([]string)
	if !ok {
		t.Fatalf("labels not a []string: %T", ev.Meta["labels"])
	}
	want := []string{
		"anonymized", "as64500", "class:spoofed", "cloud:aws", "conn:hosting",
		"geo-risk", "geo:RU", "novel-asn", "scanner:censys", "spoofed-ptr",
		"target:web-cms", "threat:medium", "tor",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(labels, want) {
		t.Errorf("labels =\n  %v\nwant\n  %v", labels, want)
	}
}

func TestDecorateRecognitionEmpty(t *testing.T) {
	ev := &event.Event{RuleID: "listener:x", Meta: map[string]any{}}
	decorateRecognition(ev)
	if _, ok := ev.Meta["labels"]; ok {
		t.Error("no signals -> no labels")
	}
	if _, ok := ev.Meta["source_class"]; ok {
		t.Error("no signals -> no source_class")
	}
}
