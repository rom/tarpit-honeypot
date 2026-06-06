package toolfp

import (
	"slices"
	"testing"
)

func TestIdentifyDNSExtended(t *testing.T) {
	cases := map[string]string{
		"abc.oastify.com":            "burp-collaborator",
		"x.oast.pro":                 "interactsh",
		"y.requestrepo.com":          "requestrepo",
		"z.bxss.me":                  "xsshunter",
		"q.rbndr.us":                 "dns-rebind-service",
		"whoami.akamai.net":          "resolver-recon",
		"_kerberos._tcp.example.com": "ad-dns-recon",
		"data.iodined.attacker.net":  "iodine",
	}
	for qname, want := range cases {
		if got := IdentifyDNS(qname); !slices.Contains(got, want) {
			t.Errorf("IdentifyDNS(%q) = %v, want to contain %q", qname, got, want)
		}
	}
	if got := IdentifyDNS("www.legit-site.com"); len(got) != 0 {
		t.Errorf("benign qname matched: %v", got)
	}
}

func TestIdentifyNTP(t *testing.T) {
	// mode 7 (private) + reqCode 42 = monlist scanner.
	if got := IdentifyNTP(7, 2, 3, 42); !slices.Contains(got, "ntpdc-monlist") {
		t.Errorf("monlist not identified: %v", got)
	}
	// mode 7 other reqCode = ntpdc.
	if got := IdentifyNTP(7, 3, 3, 0); !slices.Contains(got, "ntpdc") {
		t.Errorf("ntpdc not identified: %v", got)
	}
	// mode 6 = ntpq.
	if got := IdentifyNTP(6, 3, 0, 0); !slices.Contains(got, "ntpq") {
		t.Errorf("ntpq not identified: %v", got)
	}
	// legacy version.
	if got := IdentifyNTP(3, 1, 0, 0); !slices.Contains(got, "legacy-ntp-client") {
		t.Errorf("legacy client not identified: %v", got)
	}
	// normal v4 client = nothing.
	if got := IdentifyNTP(3, 4, 0, 0); len(got) != 0 {
		t.Errorf("normal client matched: %v", got)
	}
}

func TestIdentifySNMP(t *testing.T) {
	for _, c := range []string{"public", "private", "cisco", "manager", "ILMI"} {
		if got := IdentifySNMP(c); !slices.Contains(got, "snmp-community-brute") {
			t.Errorf("weak community %q not flagged: %v", c, got)
		}
	}
	if got := IdentifySNMP("3f9c-rand-org-community"); len(got) != 0 {
		t.Errorf("strong community matched: %v", got)
	}
}
