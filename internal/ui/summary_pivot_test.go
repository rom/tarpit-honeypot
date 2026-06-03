package ui

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestAsnNumber(t *testing.T) {
	for in, want := range map[string]string{
		"AS13335 Cloudflare, Inc.": "13335",
		"AS9009":                   "9009",
		"Some Org Without ASN":     "",
		"AS":                       "",
	} {
		if got := asnNumber(in); got != want {
			t.Errorf("asnNumber(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFilterByMeta(t *testing.T) {
	mk := func(tools []string, asn int) *event.Event {
		m := map[string]any{}
		if len(tools) > 0 {
			anys := make([]any, len(tools))
			for i, s := range tools {
				anys[i] = s
			}
			m["tools"] = anys
		}
		if asn > 0 {
			m["asn"] = asn
		}
		return &event.Event{Meta: m}
	}
	evs := []*event.Event{
		mk([]string{"sqlmap"}, 13335),
		mk([]string{"nmap"}, 9009),
		mk(nil, 13335),
	}

	// tool pivot (case-insensitive)
	if got := filterByMeta(evs, "SQLMAP", "", ""); len(got) != 1 {
		t.Errorf("tool filter returned %d, want 1", len(got))
	}
	// asn pivot, accepts "AS"-prefixed and bare
	if got := filterByMeta(evs, "", "", "AS13335"); len(got) != 2 {
		t.Errorf("asn filter returned %d, want 2", len(got))
	}
	if got := filterByMeta(evs, "", "", "9009"); len(got) != 1 {
		t.Errorf("asn filter returned %d, want 1", len(got))
	}
	// empty pivots are a no-op
	if got := filterByMeta(evs, "", "", ""); len(got) != 3 {
		t.Errorf("no-op filter returned %d, want 3", len(got))
	}
}
