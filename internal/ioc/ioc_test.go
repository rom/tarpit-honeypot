package ioc

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func has(inds []Indicator, typ, val string) bool {
	for _, i := range inds {
		if i.Type == typ && i.Value == val {
			return true
		}
	}
	return false
}

func TestExtract(t *testing.T) {
	ev := &event.Event{
		RuleID: "cve:CVE-2021-44228",
		Source: event.Endpoint{IP: "203.0.113.7"},
		Meta: map[string]any{
			"asn": "AS64500", "ja3": "abc", "qname": "evil.example.com",
			"payload_artifacts": []string{"elf:deadbeef -> x.bin"},
			"harvested_urls":    []string{"http://evil.test/x.sh"},
			"username":          "admin", "password": "s3cr3t",
			"client_mac": "02:42:ac:11:00:01",
		},
	}
	inds := Extract(ev)
	for _, want := range [][2]string{
		{"ip", "203.0.113.7"}, {"asn", "AS64500"}, {"ja3", "abc"},
		{"domain", "evil.example.com"}, {"cve", "CVE-2021-44228"},
		{"sha256", "deadbeef"}, {"url", "http://evil.test/x.sh"},
		{"credential", "admin:s3cr3t"}, {"mac", "02:42:ac:11:00:01"},
	} {
		if !has(inds, want[0], want[1]) {
			t.Errorf("missing indicator %s=%s in %v", want[0], want[1], inds)
		}
	}
}

func TestExtractIOCEventPropagates(t *testing.T) {
	ev := &event.Event{RuleID: "ioc:sha256", Meta: map[string]any{"ioc_type": "sha256", "ioc_value": "cafef00d"}}
	inds := Extract(ev)
	if len(inds) != 1 || !has(inds, "sha256", "cafef00d") {
		t.Errorf("ioc:* event did not re-yield its indicator: %v", inds)
	}
}

func TestExtractSkipsOperational(t *testing.T) {
	for _, rule := range []string{"fleet:rollup", "fleet:sensor-untrusted"} {
		if inds := Extract(&event.Event{RuleID: rule, Source: event.Endpoint{IP: "1.2.3.4"}}); len(inds) != 0 {
			t.Errorf("%s yielded indicators: %v", rule, inds)
		}
	}
}
