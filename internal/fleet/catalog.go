package fleet

// RuleDoc documents one fleet detector for the CLI / docs / UI.
type RuleDoc struct {
	ID      string   `json:"id"`      // full rule id, e.g. "fleet:source-multi-sensor"
	Summary string   `json:"summary"` // one-line description of what it detects
	Config  []string `json:"config"`  // the fleet.* config keys that tune it
}

// Catalog returns every cross-sensor detector the correlator can emit, in a
// stable order. It's the single source of truth for `list-fleet-rules` and the
// docs, so the rule set stays discoverable without reading the code.
func Catalog() []RuleDoc {
	return []RuleDoc{
		{"fleet:source-multi-sensor", "one source IP hitting many sensors (a single attacker sweeping the fleet)", []string{"source_sensors", "broad_coverage"}},
		{"fleet:asn-multi-sensor", "one ASN across many sensors (coordinated / distributed from one network)", []string{"asn_sensors", "broad_coverage"}},
		{"fleet:fingerprint-shared", "one ja3/ja4/hassh across many sensors AND sources (shared toolkit / botnet)", []string{"fp_sensors", "fp_sources"}},
		{"fleet:payload-campaign", "the same malware artifact (SHA-256) on many sensors (one distribution campaign)", []string{"payload_sensors"}},
		{"fleet:credential-campaign", "the same username:password on many sensors (stuffing list / leaked honeytoken cred)", []string{"cred_sensors"}},
		{"fleet:cve-wave", "the same CVE on many sensors (a worm / mass-exploitation wave)", []string{"cve_sensors", "broad_coverage"}},
		{"fleet:subnet-coordinated", "many IPs from one /24 (or /64) covering many sensors (one-IP-per-target botnet)", []string{"subnet_sensors", "subnet_sources"}},
		{"fleet:outlier-sensor", "a sensor whose high-sev volume is far above its peers (specifically targeted)", []string{"outlier_min_events", "outlier_factor", "outlier_min_peers"}},
		{"fleet:scan-trajectory", "one source walking dest IPs in address order across sensors (predicts next target)", []string{"trajectory_hits", "trajectory_sensors", "trajectory_monotonic"}},
		{"fleet:synchronized-burst", "many sensors spiking at once (a fleet-wide changepoint; no shared source needed)", []string{"burst_window", "burst_min_events", "burst_sensors"}},
		{"fleet:first-fleet-contact", "a brand-new ASN / fingerprint reaching several sensors (new infrastructure)", []string{"first_contact_sensors", "first_seen_horizon"}},
		{"fleet:identity-pivot", "one actor across rotating IPs, linked by a composite identity", []string{"pivot_sources", "pivot_sensors"}},
		{"fleet:geo-distributed-actor", "one fingerprint/credential from many countries (impossible travel at fleet scale)", []string{"geo_countries", "geo_sensors"}},
		{"fleet:target-profile-match", "distinct sources running the same multi-CVE playbook (a shared runbook)", []string{"profile_cves", "profile_sources", "profile_sensors"}},
		{"fleet:honeytoken-spread", "the same canary token tripped on many sensors (a planted token leaked + propagating)", []string{"honeytoken_sensors"}},
		{"fleet:cve-emergence", "a brand-new CVE reaching several sensors (an n-day going live fleet-wide)", []string{"cve_emergence_sensors", "first_seen_horizon"}},
		{"fleet:cross-protocol-actor", "one source touching many distinct services across sensors (fleet-wide enumeration)", []string{"cross_proto_handlers", "cross_proto_sensors"}},
		{"fleet:fingerprint-asn-spread", "one fingerprint operated from many ASNs (a toolkit run from many networks)", []string{"fp_asns", "fp_asn_sensors"}},
		{"fleet:threat-intel-surge", "many enrichment-flagged sources (threat-intel / Tor) converging on the fleet", []string{"threat_surge_sources", "threat_surge_sensors"}},
		{"fleet:tool-campaign", "one identified tool across many sensors/sources (a kit sweeping the fleet)", []string{"tool_sensors", "tool_sources"}},
		{"fleet:c2-shared", "the same harvested C2 / dropper URL on many sensors (shared command-and-control)", []string{"c2_sensors"}},
		{"fleet:user-agent-shared", "the same HTTP User-Agent across many sensors/sources (HTTP scanner family)", []string{"ua_sensors", "ua_sources"}},
		{"fleet:tactic-convergence", "one MITRE technique from many sources across sensors (a coordinated TTP push)", []string{"tactic_sources", "tactic_sensors"}},
		{"fleet:recidivist-network", "an ASN active across many distinct time buckets (a network that keeps coming back)", []string{"recidivist_bucket", "recidivist_windows"}},
		{"fleet:port-campaign", "many sources focused on one destination port (a service-targeted campaign)", []string{"port_campaign_sources", "port_campaign_sensors", "port_campaign_exclude"}},
		{"fleet:credential-spray-fleet", "one username tried with many passwords across sensors (distributed brute-force)", []string{"cred_spray_passwords", "cred_spray_sensors"}},
		{"fleet:asn-org-campaign", "one AS-org spanning many ASNs across sensors (a provider-wide campaign)", []string{"asn_org_asns", "asn_org_sensors"}},
	}
}
