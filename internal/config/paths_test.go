package config

import "testing"

func TestPaths(t *testing.T) {
	c := &Config{}
	c.Sensor.DataDir = "/var/lib/thp"
	c.Sensor.OUIFile = "/etc/thp/oui.csv"
	c.Sensor.GeoIP.CityDB = "/etc/thp/city.mmdb"
	c.Sensor.Tor.Enabled = true
	c.Sensor.Tor.ExitFile = "/etc/thp/tor.txt"
	c.Sensor.ThreatIntel.Enabled = true
	c.Sensor.ThreatIntel.Lists = []ThreatIntelList{{Label: "blde", File: "/etc/thp/blde.txt"}}
	c.Sensor.CloudRanges.Enabled = true
	c.Sensor.CloudRanges.Lists = []CloudRangeEntry{{Provider: "aws", File: "/etc/thp/cloud/aws.txt"}}
	c.Sensor.FingerprintDB.Enabled = true
	c.Sensor.FingerprintDB.Sources = []FingerprintDBSource{{Kind: "ja4", File: "/etc/thp/fp/ja4.txt"}}
	c.Sensor.Payloads.Analyze = true
	c.Sensor.Payloads.MalwareHashes = "/etc/thp/malware/known.txt"
	c.Sniffer.P0fDB = "/etc/thp/p0f.fp"

	byKey := map[string]PathRef{}
	for _, p := range c.Paths("/etc/thp/config.yaml") {
		byKey[p.Key] = p
	}
	for _, k := range []string{"config", "oui_file", "geoip.city_db", "tor.exit_file",
		"threat_intel:blde", "cloud_ranges:aws", "fingerprint_db:ja4",
		"payloads.malware_hashes", "sniffer.p0f_db", "data_dir", "events_db"} {
		if _, ok := byKey[k]; !ok {
			t.Errorf("Paths missing key %q", k)
		}
	}
	if byKey["cloud_ranges:aws"].Category != "enrichment" || byKey["cloud_ranges:aws"].Writable {
		t.Errorf("cloud_ranges ref wrong: %+v", byKey["cloud_ranges:aws"])
	}
	if byKey["oui_file"].Category != "enrichment" || byKey["oui_file"].Writable {
		t.Errorf("oui_file ref wrong: %+v", byKey["oui_file"])
	}
	if byKey["geoip.city_db"].Category != "database" {
		t.Errorf("geoip category = %q; want database", byKey["geoip.city_db"].Category)
	}
	if !byKey["data_dir"].Writable {
		t.Errorf("data_dir should be writable")
	}
	// Disabled tor/threat are omitted.
	c2 := &Config{}
	c2.Sensor.Tor.ExitFile = "/x"
	for _, p := range c2.Paths() {
		if p.Key == "tor.exit_file" {
			t.Errorf("disabled tor.exit_file should be omitted")
		}
	}
}
