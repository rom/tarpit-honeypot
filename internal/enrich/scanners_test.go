package enrich

import "testing"

func TestKnownScanner(t *testing.T) {
	cases := []struct {
		asnOrg, rdns, want string
	}{
		{"CENSYS-ARIN-01", "scanner-12.censys-scanner.com", "censys"},
		{"", "census1.shodan.io", "shodan"},
		{"", "scan-04a.shadowserver.org", "shadowserver"},
		{"RAPID7", "rec.sonar.labs.rapid7.com", "rapid7-sonar"},
		{"", "9.184.broadband.stretchoid.com", "stretchoid"},
		{"", "scan.internet-measurement.com", "internet-measurement"},
		{"BinaryEdge Ltd", "", "binaryedge"},
		{"Beijing Qihu Technology (360)", "", "magellan-360"},
		// Second-batch operators.
		{"", "scanner.projectdiscovery.io", "projectdiscovery"},
		{"GreyNoise Intelligence", "", "greynoise"},
		{"", "node.fofa.info", "fofa-knownsec"},
		{"", "crawler.zoomeye.org", "zoomeye"},
		{"", "probe.netlas.io", "netlas"},
		{"FullHunt", "", "fullhunt"},
		{"Qualys Inc", "", "qualys"},
		{"", "scan.ipinfo.io", "ipinfo"},
		// A normal residential/cloud source is not a scanner.
		{"Comcast Cable Communications", "c-73-12-0-1.hsd1.ca.comcast.net", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := KnownScanner(c.asnOrg, c.rdns); got != c.want {
			t.Errorf("KnownScanner(%q,%q) = %q, want %q", c.asnOrg, c.rdns, got, c.want)
		}
	}
}
