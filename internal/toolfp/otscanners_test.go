package toolfp

import "testing"

// OT/ICS asset-discovery + research crawlers self-identify by product or
// study token in their HTTP User-Agent. Confirm each maps to its tool and
// the OT discovery platforms classify as vuln-scanners.
func TestOTScannerUASignatures(t *testing.T) {
	cases := map[string]string{
		"Claroty-CTD/4.5 asset-enrichment":                         "claroty",
		"Nozomi Guardian/22.6 active-query":                        "nozomi",
		"Tenable.ot/3.18 (Indegy)":                                 "tenable-ot",
		"Forescout SilentDefense sensor":                           "forescout",
		"Dragos Platform collector":                                "dragos",
		"Mozilla/5.0 (ProjectSonar; +https://opendata.rapid7.com)": "rapid7-sonar",
		"ISF-Framework industrial exploit":                         "isf",
		"smod modbus framework":                                    "smod",
		"plcscan/0.1":                                              "plcscan",
	}
	for ua, want := range cases {
		v := IdentifyHTTP(HTTPSignals{UserAgent: ua, Path: "/"})
		if !has(v.Tools, want) {
			t.Errorf("UA %q: tools=%v; want %q", ua, v.Tools, want)
		}
	}
}

func TestOTScannersAreVulnScanners(t *testing.T) {
	for _, tool := range []string{"claroty", "nozomi", "tenable-ot", "dragos", "plcscan", "s7scan"} {
		if !IsVulnScanner(tool) {
			t.Errorf("%q should classify as a vuln-scanner", tool)
		}
	}
	// ISF is an exploitation framework (Metasploit-class), not a scanner.
	if !IsC2("isf") {
		t.Error("isf should classify as a C2/exploitation framework")
	}
}
