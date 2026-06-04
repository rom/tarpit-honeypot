package enrich

import "strings"

// KnownScanner attributes an IP to a known internet-wide network-scanning /
// reconnaissance operator (Censys, Shodan, Project Magellan, etc.) from its ASN
// organization and reverse-DNS name. This is IP-level attribution — it fires
// even when the probe carries no self-identifying User-Agent, unlike the
// UA-based tool fingerprinting. Returns the operator name, or "" if unknown.
//
// Substrings are matched case-insensitively against both the ASN org and the
// rDNS hostname; the rDNS patterns are the most reliable (scanners PTR their
// hosts to a research/abuse domain). Curated, high-signal only.
func KnownScanner(asnOrg, rdns string) string {
	hay := strings.ToLower(asnOrg) + "\x00" + strings.ToLower(rdns)
	for _, s := range scannerOperators {
		for _, needle := range s.needles {
			if strings.Contains(hay, needle) {
				return s.name
			}
		}
	}
	return ""
}

type scannerOperator struct {
	name    string
	needles []string // lowercase substrings found in ASN org or rDNS
}

// scannerOperators is the curated catalog of internet-scan operators. Order
// matters only for overlapping needles (none currently overlap).
var scannerOperators = []scannerOperator{
	{"censys", []string{"censys"}},                                     // censys.io / censys-scanner.com
	{"shodan", []string{"shodan", "census.shodan", "shodan.io"}},       // *.shodan.io
	{"binaryedge", []string{"binaryedge"}},                             // *.binaryedge.ninja
	{"shadowserver", []string{"shadowserver"}},                         // scan-*.shadowserver.org
	{"rapid7-sonar", []string{"rapid7", "sonar.labs", "projectsonar"}}, // *.sonar.labs.rapid7.com
	{"stretchoid", []string{"stretchoid"}},                             // *.stretchoid.com
	{"internet-measurement", []string{"internet-measurement", "internetmeasurement", "driftnet"}},
	{"criminalip", []string{"criminalip", "criminal-ip", "aspina"}}, // criminalip.com (AI Spera)
	{"leakix", []string{"leakix"}},                                  // *.leakix.org
	{"onyphe", []string{"onyphe"}},                                  // onyphe.net
	{"netsystems-research", []string{"netsystemsresearch", "netsystems research"}},
	{"palo-alto-expanse", []string{"expanse", "expanseinc", "cortex xpanse", "palo alto networks"}},
	{"alphastrike", []string{"alphastrike", "alpha strike"}}, // alphastrike.io
	{"bitsight", []string{"bitsight", "anubisnetworks"}},
	{"securitytrails", []string{"securitytrails", "dnstrails"}},
	{"intrinsec", []string{"intrinsec"}},
	{"censys-team", []string{"censys.io"}},
	{"recyber", []string{"recyber"}}, // recyber.net (mass scanner)
	{"probely", []string{"probely"}},
	{"quadmetrics", []string{"quadmetrics"}},
	{"modat", []string{"modat", "modat.io"}},
	{"cyber-resilience", []string{"cyber resilience", "cyberresilience"}},
	{"academic-research", []string{"university of michigan", "scan.shadowserver", "researchscan", "academic scan", "scanproject"}},
	{"magellan-360", []string{"magellan", "qihoo", "360.cn", "beijing qihu"}}, // Qihoo 360 Project Magellan
	{"netcraft", []string{"netcraft"}},
	{"ipip", []string{"ipip.net"}},
	{"bufferover", []string{"bufferover"}},
	{"arbor-atlas", []string{"arbor", "netscout"}},
	// --- second batch: attack-surface-mgmt, recon search engines, scanners ---
	{"projectdiscovery", []string{"projectdiscovery", "chaos.projectdiscovery", "interactsh"}},
	{"greynoise", []string{"greynoise"}},
	{"fofa-knownsec", []string{"fofa", "knownsec", "baimaohui"}}, // FOFA / 知道创宇
	{"zoomeye", []string{"zoomeye"}},                             // Knownsec ZoomEye
	{"hunter-qianxin", []string{"hunter.how", "qianxin"}},        // QiAnXin Hunter
	{"netlas", []string{"netlas"}},                               // netlas.io
	{"odin", []string{"odin.io"}},                                // odin.io
	{"fullhunt", []string{"fullhunt"}},                           // fullhunt.io
	{"spur", []string{"spur.us"}},                                // spur.us
	{"ipinfo", []string{"ipinfo.io"}},                            // ipinfo.io probes
	{"riskiq", []string{"riskiq", "passivetotal"}},               // Microsoft RiskIQ
	{"securityscorecard", []string{"securityscorecard"}},
	{"tenable", []string{"tenable", "nessus cloud"}},
	{"qualys", []string{"qualys"}},
	{"detectify", []string{"detectify"}},
	{"intruder", []string{"intruder.io"}},
	{"appcheck", []string{"appcheck-ng"}},
	{"cyble", []string{"cyble"}},
	{"intelx", []string{"intelx.io", "intelligence x"}},
	{"greenbone", []string{"greenbone"}},                               // OpenVAS cloud
	{"sicherheitstacho", []string{"sicherheitstacho", "telekom-cert"}}, // Deutsche Telekom
	{"ernw", []string{"ernw"}},
	{"kudelski", []string{"kudelski"}},
	{"internet-census", []string{"internetcensus", "internet census"}},
	{"dataprovider", []string{"dataprovider.com"}},
	{"mj12bot", []string{"mj12bot", "majestic12"}}, // Majestic crawler
	{"ahrefs", []string{"ahrefs"}},
	{"semrush", []string{"semrush"}},
}

// metaString returns a string meta value, or "" if absent / wrong type.
func metaString(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}
