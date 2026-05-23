package enrich

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func writeList(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func evt(ip string) *event.Event { return &event.Event{Source: event.Endpoint{IP: ip}} }

func TestThreatIntelTagging(t *testing.T) {
	list := writeList(t, "ti.txt", "# bad guys\n203.0.113.7\n45.66.0.0/16\n\n# trailing comment line\n8.8.8.8 some-note\n")
	e, err := New(Config{ThreatLists: []ThreatList{{Label: "abuse", File: list}}})
	if err != nil {
		t.Fatal(err)
	}
	// Exact IP hit.
	ev := evt("203.0.113.7")
	e.Decorate(ev)
	if ev.Meta["threat_intel_hit"] != true {
		t.Errorf("exact IP not tagged: %v", ev.Meta)
	}
	if got, _ := ev.Meta["threat_intel"].([]string); len(got) != 1 || got[0] != "abuse" {
		t.Errorf("threat_intel labels = %v; want [abuse]", ev.Meta["threat_intel"])
	}
	// CIDR hit.
	ev = evt("45.66.12.34")
	e.Decorate(ev)
	if ev.Meta["threat_intel_hit"] != true {
		t.Errorf("CIDR member not tagged: %v", ev.Meta)
	}
	// IP with a trailing column/comment still parsed.
	ev = evt("8.8.8.8")
	e.Decorate(ev)
	if ev.Meta["threat_intel_hit"] != true {
		t.Errorf("IP with trailing note not tagged: %v", ev.Meta)
	}
	// A clean IP gets no tag.
	ev = evt("1.1.1.1")
	e.Decorate(ev)
	if _, ok := ev.Meta["threat_intel_hit"]; ok {
		t.Errorf("clean IP wrongly tagged: %v", ev.Meta)
	}
}

func TestTorExitTagging(t *testing.T) {
	list := writeList(t, "tor.txt", "185.220.101.1\n198.96.155.3\n")
	e, err := New(Config{TorExitFile: list})
	if err != nil {
		t.Fatal(err)
	}
	ev := evt("185.220.101.1")
	e.Decorate(ev)
	if ev.Meta["tor_exit"] != true {
		t.Errorf("tor exit not tagged: %v", ev.Meta)
	}
	ev = evt("9.9.9.9")
	e.Decorate(ev)
	if _, ok := ev.Meta["tor_exit"]; ok {
		t.Errorf("non-exit wrongly tagged: %v", ev.Meta)
	}
}

func TestNetClassBogonAndHosting(t *testing.T) {
	e, err := New(Config{NetClass: true})
	if err != nil {
		t.Fatal(err)
	}
	// Bogon (TEST-NET-3) source.
	ev := evt("203.0.113.50")
	e.Decorate(ev)
	if ev.Meta["net_class"] != "bogon" {
		t.Errorf("net_class = %v; want bogon", ev.Meta["net_class"])
	}
	// CGNAT bogon.
	ev = evt("100.64.0.9")
	e.Decorate(ev)
	if ev.Meta["net_class"] != "bogon" {
		t.Errorf("net_class = %v; want bogon for CGNAT", ev.Meta["net_class"])
	}
	// Hosting derived from a pre-set asn_org (as the ASN enricher would set).
	ev = evt("3.5.6.7")
	ev.Meta = map[string]any{"asn_org": "AMAZON-02"}
	e.Decorate(ev)
	if ev.Meta["net_class"] != "hosting" {
		t.Errorf("net_class = %v; want hosting", ev.Meta["net_class"])
	}
	// Public IP, no hosting org -> no class.
	ev = evt("3.5.6.8")
	ev.Meta = map[string]any{"asn_org": "Comcast Cable Communications"}
	e.Decorate(ev)
	if _, ok := ev.Meta["net_class"]; ok {
		t.Errorf("residential ASN should not be classed: %v", ev.Meta)
	}
}

func TestDecorateSkipsPrivateAndLoopback(t *testing.T) {
	list := writeList(t, "ti.txt", "10.0.0.0/8\n")
	e, err := New(Config{NetClass: true, ThreatLists: []ThreatList{{Label: "x", File: list}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.0.0.5", "127.0.0.1", "169.254.1.1"} {
		ev := evt(ip)
		e.Decorate(ev)
		if len(ev.Meta) != 0 {
			t.Errorf("private/loopback %s should not be enriched: %v", ip, ev.Meta)
		}
	}
}

func TestNewMissingListErrors(t *testing.T) {
	if _, err := New(Config{ThreatLists: []ThreatList{{Label: "x", File: "/no/such/file"}}}); err == nil {
		t.Error("expected error for a missing threat list file")
	}
}

func TestLoadIPListParsing(t *testing.T) {
	p := writeList(t, "l.txt", "# header\n1.2.3.4\n  10.0.0.0/24  \n\nnot-an-ip\nfe80::1\n")
	ips, cidrs, n, err := loadIPList(p)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 { // 1.2.3.4, 10.0.0.0/24, fe80::1
		t.Errorf("parsed %d entries; want 3", n)
	}
	if _, ok := ips["1.2.3.4"]; !ok {
		t.Errorf("1.2.3.4 not loaded: %v", ips)
	}
	if len(cidrs) != 1 {
		t.Errorf("cidrs = %v; want one /24", cidrs)
	}
}

func TestMACVendorEnrichment(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	// A DHCP-shaped event: zeroed source IP, MAC in meta (built-in OUI table).
	ev := &event.Event{Source: event.Endpoint{IP: "0.0.0.0"}, Meta: map[string]any{"client_mac": "00:90:e8:11:22:33"}}
	e.Decorate(ev)
	if ev.Meta["mac_vendor"] != "Moxa" {
		t.Errorf("mac_vendor = %v; want Moxa", ev.Meta["mac_vendor"])
	}
	// sender_mac (ARP) is also recognized; runs even with no source IP.
	ev2 := &event.Event{Meta: map[string]any{"sender_mac": "00:0c:29:aa:bb:cc"}}
	e.Decorate(ev2)
	if ev2.Meta["mac_vendor"] != "VMware" {
		t.Errorf("mac_vendor = %v; want VMware", ev2.Meta["mac_vendor"])
	}
	// No MAC -> no tag.
	ev3 := &event.Event{Source: event.Endpoint{IP: "8.8.8.8"}, Meta: map[string]any{}}
	e.Decorate(ev3)
	if _, ok := ev3.Meta["mac_vendor"]; ok {
		t.Errorf("mac_vendor set on a MAC-less event: %v", ev3.Meta)
	}
}
