package main

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/cve"
)

func TestYearOf(t *testing.T) {
	for id, want := range map[string]string{
		"CVE-2021-44228": "2021", "CVE-2007-0882": "2007", "weird": "unknown",
	} {
		if got := yearOf(id); got != want {
			t.Errorf("yearOf(%q)=%q want %q", id, got, want)
		}
	}
}

func TestFromCPE(t *testing.T) {
	v, p, ok := fromCPE("cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*")
	if !ok || v != "BIND" || p != "" {
		// isc→"ISC" via acronyms, bind→"BIND"
		if v != "ISC" {
			t.Errorf("isc:bind => vendor %q product %q ok %v", v, p, ok)
		}
	}
	v, p, ok = fromCPE("cpe:2.3:o:abb:aspect-enterprise_firmware:*:*:*:*:*:*:*:*")
	if !ok || v != "ABB" || p != "ASPECT" {
		t.Errorf("abb aspect => vendor %q product %q (want ABB / ASPECT)", v, p)
	}
	if _, _, ok := fromCPE("cpe:2.3:a:*:*:*"); ok {
		t.Error("wildcard vendor should not resolve")
	}
	if _, _, ok := fromCPE(""); ok {
		t.Error("empty CPE should not resolve")
	}
}

func TestFromName(t *testing.T) {
	cases := []struct{ name, vendor, product string }{
		{"Adobe ColdFusion Directory Traversal Vulnerability", "Adobe", "Adobe ColdFusion"},
		{"Oracle WebLogic Server OS Command Injection Vulnerability", "Oracle", "Oracle WebLogic Server"},
		{"NETGEAR Multiple WAP Devices Command Injection Vulnerability", "NETGEAR", "NETGEAR Multiple WAP Devices"},
	}
	for _, c := range cases {
		v, p := fromName(c.name)
		if v != c.vendor || p != c.product {
			t.Errorf("fromName(%q) = %q / %q; want %q / %q", c.name, v, p, c.vendor, c.product)
		}
	}
}

func TestVendorProductPrefersCPE(t *testing.T) {
	r := cve.Record{ID: "CVE-2024-4872", Name: "Hitachi Energy MicroSCADA SYS600 query code injection",
		CPE: "cpe:2.3:a:hitachienergy:microscada_x_sys600:*:*:*:*:*:*:*:*"}
	v, p := vendorProduct(r)
	if v != "Hitachi Energy" || !strings.Contains(p, "MicroSCADA") {
		t.Errorf("vendorProduct from CPE = %q / %q", v, p)
	}
}

func TestRenderFromLiveCatalog(t *testing.T) {
	doc := Render(cve.All())
	for _, want := range []string{
		"# CVE catalog", "## Overview — top 10s", "Top 10 products by CVE count",
		"Top 10 vendors by CVE count", "Top 10 protocols / services by CVE count",
		"Top 10 years by CVE count", "## By protocol / service", "## By product / tool",
		"## All CVEs", "nvd.nist.gov/vuln/detail/CVE-",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("rendered doc missing %q", want)
		}
	}
	// Spot-check a known protocol subsection and a known CVE row.
	if !strings.Contains(doc, "CVE-2013-5211") {
		t.Error("expected the NTP monlist CVE in the doc")
	}
}
