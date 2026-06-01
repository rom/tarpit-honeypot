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
			"ja4h": "ge11nn", "ja4t": "64240_2-4-8", "user_agent": "sqlmap/1.7",
			"sni":               "intranet.corp",
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
		{"ja4h", "ge11nn"}, {"ja4t", "64240_2-4-8"},
		{"user-agent", "sqlmap/1.7"}, {"domain", "intranet.corp"},
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

// TestExtractForwardedIOCValidation guards L4: a forwarded ioc:* event from a
// misbehaving child must not be able to poison the upstream store with an
// unknown indicator kind or a bloated value.
func TestExtractForwardedIOCValidation(t *testing.T) {
	mk := func(typ, val string) *event.Event {
		return &event.Event{RuleID: "ioc:" + typ, Meta: map[string]any{"ioc_type": typ, "ioc_value": val}}
	}
	// Known type + sane value: accepted.
	if inds := Extract(mk("sha256", "deadbeef")); len(inds) != 1 || inds[0].Type != "sha256" {
		t.Errorf("known type rejected: %v", inds)
	}
	// Unknown type: rejected.
	if inds := Extract(mk("bogus", "anything")); len(inds) != 0 {
		t.Errorf("unknown type %q yielded indicators: %v", "bogus", inds)
	}
	// Oversized value: rejected.
	huge := make([]byte, maxIOCValueLen+1)
	for i := range huge {
		huge[i] = 'a'
	}
	if inds := Extract(mk("url", string(huge))); len(inds) != 0 {
		t.Errorf("oversized value yielded indicators: %v", inds)
	}
	// Empty type/value: rejected (existing behavior preserved).
	if inds := Extract(mk("", "x")); len(inds) != 0 {
		t.Errorf("empty type yielded indicators: %v", inds)
	}
	if inds := Extract(mk("sha256", "")); len(inds) != 0 {
		t.Errorf("empty value yielded indicators: %v", inds)
	}
}
