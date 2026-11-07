package config

import "path/filepath"

// PathRef is one filesystem path the sensor reads or writes, classified so
// operators (and the enrichment installer) can see exactly which config
// files, enrichment inputs, and databases a running sensor uses.
type PathRef struct {
	// Category is one of: "config" (config + TLS material), "enrichment"
	// (operator-supplied reputation/tor/oui inputs), "database"
	// (GeoIP/ASN + the local event store), or "state" (sensor-written
	// data under data_dir).
	Category string `json:"category"`
	// Key is a stable identifier for the path (e.g. "oui_file",
	// "geoip.city_db", "tor.exit_file", "threat_intel:<label>"). The
	// enrichment installer matches downloaded files to destinations by Key.
	Key string `json:"key"`
	// Path is the configured filesystem path.
	Path string `json:"path"`
	// Writable is true when the sensor writes the path (state/output);
	// false for read-only inputs (config, enrichment, databases).
	Writable bool `json:"writable"`
}

// Paths returns every filesystem path the effective config references —
// the config file(s) passed in, the enrichment inputs, the databases, and
// the data-dir state — for the `list-paths` subcommand, the web UI's config
// view, and the enrichment installer. Empty paths are omitted.
func (c *Config) Paths(configFiles ...string) []PathRef {
	var out []PathRef
	add := func(cat, key, path string, w bool) {
		if path != "" {
			out = append(out, PathRef{Category: cat, Key: key, Path: path, Writable: w})
		}
	}

	for i, f := range configFiles {
		key := "config"
		if len(configFiles) > 1 {
			key = "config[" + itoa(i) + "]"
		}
		add("config", key, f, false)
	}
	add("config", "ui.tls_cert", c.UI.TLSCert, false)
	add("config", "ui.tls_key", c.UI.TLSKey, false)
	for _, ch := range c.Channels {
		add("config", "channel:"+ch.ID+":ca_cert", ch.CACertFile, false)
	}

	// Enrichment inputs (operator-supplied; what the installer manages).
	add("enrichment", "oui_file", c.Sensor.OUIFile, false)
	if c.Sensor.Tor.Enabled {
		add("enrichment", "tor.exit_file", c.Sensor.Tor.ExitFile, false)
	}
	if c.Sensor.ThreatIntel.Enabled {
		for _, l := range c.Sensor.ThreatIntel.Lists {
			add("enrichment", "threat_intel:"+l.Label, l.File, false)
		}
	}
	if c.Sensor.CloudRanges.Enabled {
		for _, l := range c.Sensor.CloudRanges.Lists {
			add("enrichment", "cloud_ranges:"+l.Provider, l.File, false)
		}
	}
	if c.Sensor.Anonymizer.Enabled {
		for _, l := range c.Sensor.Anonymizer.Lists {
			add("enrichment", "anonymizer_ranges:"+l.Kind, l.File, false)
		}
	}
	if c.Sensor.ASNReputation.Enabled {
		for _, l := range c.Sensor.ASNReputation.Lists {
			add("enrichment", "asn_reputation:"+l.Label, l.File, false)
		}
	}
	if c.Sensor.FingerprintDB.Enabled {
		for _, s := range c.Sensor.FingerprintDB.Sources {
			add("enrichment", "fingerprint_db:"+s.Kind, s.File, false)
		}
	}
	if c.Sensor.Payloads.Analyze {
		add("enrichment", "payloads.malware_hashes", c.Sensor.Payloads.MalwareHashes, false)
	}
	if c.Sensor.CredIntel.Enabled {
		add("enrichment", "cred_intel.passwords_file", c.Sensor.CredIntel.PasswordsFile, false)
	}
	if c.Sensor.DomainIntel.Enabled {
		add("enrichment", "domain_intel.blocklist_file", c.Sensor.DomainIntel.BlocklistFile, false)
	}
	if c.Sensor.ASNInfo.Enabled {
		add("enrichment", "asn_info.file", c.Sensor.ASNInfo.File, false)
	}
	add("enrichment", "sniffer.p0f_db", c.Sniffer.P0fDB, false)
	if c.KEV.File != "" {
		add("enrichment", "kev.file", c.KEV.File, false)
	}

	// Databases (read-only inputs + the local event store).
	add("database", "geoip.city_db", c.Sensor.GeoIP.CityDB, false)
	add("database", "geoip.asn_db", c.Sensor.GeoIP.ASNDB, false)

	// Sensor-written state under data_dir.
	if d := c.Sensor.DataDir; d != "" {
		add("state", "data_dir", d, true)
		add("database", "events_db", filepath.Join(d, "events.db"), true)
		add("state", "devices_json", filepath.Join(d, "devices.json"), true)
		add("state", "correlate_state", filepath.Join(d, "correlate-state.json"), true)
		add("state", "payloads_dir", filepath.Join(d, "payloads"), true)
		add("state", "sessions_dir", filepath.Join(d, "sessions"), true)
		add("state", "shell_fs_dir", filepath.Join(d, "shell-fs"), true)
		add("state", "captures_dir", filepath.Join(d, "captures"), true)
	}
	return out
}

// itoa is a tiny non-negative int formatter (avoids strconv for one call).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
