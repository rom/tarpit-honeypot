package enrich

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestClassifyCred(t *testing.T) {
	breach := map[string]struct{}{"hunter2": {}}
	cases := []struct {
		user, pass, want string
	}{
		{"root", "root", "default"}, // user==pass
		{"x", "admin", "default"},   // builtin default
		{"x", "P@ss", "weak"},       // short
		{"x", "24681012", "weak"},   // all digits (not in builtin)
		{"x", "hunter2", "breach"},  // breach list
		{"x", "Str0ng-Unique-Pw!", "unique"},
	}
	for _, c := range cases {
		if got := classifyCred(c.user, c.pass, breach); got != c.want {
			t.Errorf("classifyCred(%q,%q) = %q; want %q", c.user, c.pass, got, c.want)
		}
	}
}

func TestDecorateCreds(t *testing.T) {
	e, _ := New(Config{CredIntel: true})
	ev := &event.Event{Meta: map[string]any{"auth_user": "admin", "auth_pass": "admin"}}
	e.decorateCreds(ev)
	if ev.Meta["cred_class"] != "default" {
		t.Errorf("cred_class = %v; want default", ev.Meta["cred_class"])
	}
	// No credential on the event -> no tag.
	ev2 := &event.Event{Meta: map[string]any{"geo_country": "US"}}
	e.decorateCreds(ev2)
	if _, ok := ev2.Meta["cred_class"]; ok {
		t.Error("no credential should yield no cred_class")
	}
}

func TestLooksDGA(t *testing.T) {
	dga := []string{"x7fjq2kz9plmq.com", "kqwzrtbvxhdlmn.net", "a1b2c3d4e5f6g7h8.info"}
	for _, d := range dga {
		if !looksDGA(d) {
			t.Errorf("looksDGA(%q) = false; want true", d)
		}
	}
	normal := []string{"google.com", "cloudflare.com", "my-cool-site.org", "en.wikipedia.org", "githubusercontent.com"}
	for _, d := range normal {
		if looksDGA(d) {
			t.Errorf("looksDGA(%q) = true; want false (false positive)", d)
		}
	}
}

func TestMatchDomain(t *testing.T) {
	set := map[string]struct{}{"evil.example": {}, "bad.co": {}}
	if !matchDomain(set, "evil.example") {
		t.Error("exact match failed")
	}
	if !matchDomain(set, "a.b.evil.example") {
		t.Error("subdomain match failed")
	}
	if matchDomain(set, "notevil.example") {
		t.Error("non-member wrongly matched")
	}
}

func TestDecorateDomains(t *testing.T) {
	bad := writeList(t, "bad.txt", "evil.example\n")
	e, _ := New(Config{DomainIntel: true, BadDomainsFile: bad})
	ev := &event.Event{Meta: map[string]any{"qname": "login.evil.example"}}
	e.decorateDomains(ev)
	if ev.Meta["domain_bad"] != true {
		t.Errorf("domain_bad = %v; want true", ev.Meta["domain_bad"])
	}
	ev2 := &event.Event{Meta: map[string]any{"qname": "x7fjq2kz9plmq.com"}}
	e.decorateDomains(ev2)
	if ev2.Meta["dns_dga"] != true {
		t.Errorf("dns_dga = %v; want true", ev2.Meta["dns_dga"])
	}
}

func TestLoadASNInfoAndDecorate(t *testing.T) {
	f := writeList(t, "asninfo.csv", "# asn,country,category\n13335,US,cdn\nAS64500,RU,hosting\n")
	e, _ := New(Config{ASNInfoFile: f})
	// ASN registered RU but IP geolocates US -> mismatch.
	ev := &event.Event{Meta: map[string]any{"asn": uint32(64500), "geo_country": "US"}}
	e.decorateASNInfo(ev)
	if ev.Meta["asn_country"] != "RU" || ev.Meta["asn_type"] != "hosting" || ev.Meta["asn_geo_mismatch"] != true {
		t.Errorf("asn info = %+v; want country RU, type hosting, mismatch true", ev.Meta)
	}
	// Matching country -> no mismatch.
	ev2 := &event.Event{Meta: map[string]any{"asn": uint32(13335), "geo_country": "US"}}
	e.decorateASNInfo(ev2)
	if _, ok := ev2.Meta["asn_geo_mismatch"]; ok {
		t.Error("same country should not flag asn_geo_mismatch")
	}
}
