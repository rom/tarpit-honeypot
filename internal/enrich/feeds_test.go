package enrich

import (
	"reflect"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestExtractASN(t *testing.T) {
	cases := map[string]uint32{
		`{"asn":64500,"rir":"arin","cc":"US"}`: 64500,
		"AS13335":                              13335,
		"7922 some comment":                    7922,
		"# header":                             0,
		"not-an-asn":                           0,
	}
	for in, want := range cases {
		if got := extractASN(in); got != want {
			t.Errorf("extractASN(%q) = %d; want %d", in, got, want)
		}
	}
}

func TestLoadASNList(t *testing.T) {
	p := writeList(t, "asndrop.txt", "# Spamhaus ASN-DROP\n{\"asn\":64500,\"cc\":\"US\"}\nAS65001\n65002\n\n# comment\nbogus\n")
	asns, n, err := loadASNList(p)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("loaded %d ASNs; want 3 (%v)", n, asns)
	}
	for _, a := range []uint32{64500, 65001, 65002} {
		if _, ok := asns[a]; !ok {
			t.Errorf("AS%d not loaded", a)
		}
	}
}

// Anonymizer ranges tag the source anonymizer=<kind> (and so anonymized=true),
// and ASN-reputation tags asn_reputation; both surface in the recognition rollup.
func TestAnonymizerAndASNReputation(t *testing.T) {
	vpn := writeList(t, "vpn.txt", "203.0.113.0/24\n")
	asndrop := writeList(t, "asndrop.txt", "{\"asn\":64500}\n")
	e, err := New(Config{
		AnonymizerRanges: []CloudRangeList{{Provider: "vpn", File: vpn}},
		ASNLists:         []ASNList{{Label: "asndrop", File: asndrop}},
	})
	if err != nil {
		t.Fatal(err)
	}

	ev := &event.Event{
		RuleID: "listener:x",
		Source: event.Endpoint{IP: "203.0.113.9"},
		Meta:   map[string]any{"asn": uint32(64500)}, // no asnDB; pre-set survives
	}
	e.Decorate(ev)

	if ev.Meta["anonymizer"] != "vpn" {
		t.Errorf("anonymizer = %v; want vpn", ev.Meta["anonymizer"])
	}
	if ev.Meta["anonymized"] != true {
		t.Errorf("anonymized = %v; want true (rollup of anonymizer)", ev.Meta["anonymized"])
	}
	reps, ok := ev.Meta["asn_reputation"].([]string)
	if !ok || !reflect.DeepEqual(reps, []string{"asndrop"}) {
		t.Errorf("asn_reputation = %v; want [asndrop]", ev.Meta["asn_reputation"])
	}
	// Recognition: labels carry both; source_class is at least "anonymizer".
	labels, _ := ev.Meta["labels"].([]string)
	if !containsStr(labels, "anon:vpn") || !containsStr(labels, "asnrep:asndrop") {
		t.Errorf("labels missing anon:vpn / asnrep:asndrop: %v", labels)
	}
	if ev.Meta["source_class"] != "anonymizer" {
		t.Errorf("source_class = %v; want anonymizer", ev.Meta["source_class"])
	}
}

// asn_reputation alone (no anonymizer) classes the source as "suspect".
func TestASNReputationSourceClass(t *testing.T) {
	ev := &event.Event{RuleID: "listener:x", Meta: map[string]any{"asn_reputation": []string{"asndrop"}}}
	if got := sourceClass(ev); got != "suspect" {
		t.Errorf("sourceClass with asn_reputation = %q; want suspect", got)
	}
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
