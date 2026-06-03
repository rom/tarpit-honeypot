package ui

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseFilterASNAndRange(t *testing.T) {
	// ?asn=14618 → numeric ASN filter (also tolerate an "AS" prefix).
	for _, raw := range []string{"asn=14618", "asn=AS14618"} {
		f := parseFilter(httptest.NewRequest("GET", "/events?"+raw, nil))
		if f.ASN != 14618 {
			t.Errorf("%s → ASN %d, want 14618", raw, f.ASN)
		}
	}

	// ?range=7d → Since ~7 days ago (the summary window propagated to /events).
	f := parseFilter(httptest.NewRequest("GET", "/events?range=7d", nil))
	age := time.Since(f.Since)
	if age < 6*24*time.Hour || age > 8*24*time.Hour {
		t.Errorf("range=7d → Since age %v, want ~7d", age)
	}

	// Default window stays 24h.
	d := parseFilter(httptest.NewRequest("GET", "/events", nil))
	if a := time.Since(d.Since); a < 23*time.Hour || a > 25*time.Hour {
		t.Errorf("default Since age %v, want ~24h", a)
	}
}

func TestScopeEventLinks(t *testing.T) {
	d := &dashboard{
		Counters: []counter{{Href: "/events?proto=tcp"}, {Href: "/profiles/1.2.3.4"}},
		ASNs:     []barRow{{Href: "/events?asn=14618"}},
		Tools:    []barRow{{Href: "/events?tool=nmap"}},
	}
	scopeEventLinks(d, "7d")
	if d.Counters[0].Href != "/events?proto=tcp&range=7d" {
		t.Errorf("counter href = %q", d.Counters[0].Href)
	}
	if d.Counters[1].Href != "/profiles/1.2.3.4" {
		t.Errorf("profile link must be untouched, got %q", d.Counters[1].Href)
	}
	if d.ASNs[0].Href != "/events?asn=14618&range=7d" || d.Tools[0].Href != "/events?tool=nmap&range=7d" {
		t.Errorf("pivot links not scoped: %q / %q", d.ASNs[0].Href, d.Tools[0].Href)
	}

	// 24h (default) is a no-op so URLs stay clean.
	d2 := &dashboard{ASNs: []barRow{{Href: "/events?asn=1"}}}
	scopeEventLinks(d2, "24h")
	if d2.ASNs[0].Href != "/events?asn=1" {
		t.Errorf("24h must not append range: %q", d2.ASNs[0].Href)
	}
}
