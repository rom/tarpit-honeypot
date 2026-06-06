package toolfp

// vendors maps a tool/scanner identifier (the values produced by the
// uaSignatures / SSH / DNS / scananalysis fingerprints) to the
// organization or project behind it — useful reference context for an
// analyst triaging an event ("nozomi" → "Nozomi Networks"). Only the
// affiliation is asserted here; it is descriptive metadata, not detection.
//
// Coverage is deliberately broad for the OT/ICS asset-discovery, internet
// research-scan, and commercial vulnerability-scanner ecosystems (where the
// vendor name is genuinely useful), plus the well-known offensive tooling.
// Open-source community tools are attributed to their project/author.
var vendors = map[string]string{
	// --- OT / ICS asset-discovery + monitoring platforms ---
	"claroty":    "Claroty Ltd.",
	"nozomi":     "Nozomi Networks",
	"tenable-ot": "Tenable, Inc. (Tenable.ot / Indegy)",
	"forescout":  "Forescout Technologies (SilentDefense)",
	"dragos":     "Dragos, Inc.",
	"otorio":     "OTORIO Ltd.",
	"scadafence": "ScadaFence (acquired by Honeywell)",

	// --- ICS exploitation / recon toolkits ---
	"isf":     "Industrial Security Exploitation Framework (dark-lbp, open source)",
	"smod":    "smod — Modbus pentest framework (open source)",
	"plcscan": "PLCScan (open source)",
	"s7scan":  "s7scan (open source)",
	"modscan": "ModScan (open source)",

	// --- internet-wide research / OSINT scanners ---
	"rapid7-sonar":         "Rapid7 (Project Sonar / opendata.rapid7.com)",
	"rapid7":               "Rapid7",
	"censys":               "Censys, Inc.",
	"shodan":               "Shodan (shodan.io)",
	"binaryedge":           "BinaryEdge",
	"shadowserver":         "The Shadowserver Foundation",
	"onyphe":               "ONYPHE",
	"criminalip":           "AI Spera (Criminal IP)",
	"leakix":               "LeakIX",
	"netsystems-research":  "NetSystems Research",
	"internet-measurement": "internet-measurement.com (Driftnet)",
	"driftnet-scanner":     "Driftnet",
	"expanse":              "Palo Alto Networks (Cortex Xpanse / Expanse)",
	"stretchoid":           "Stretchoid",
	"projectdiscovery":     "ProjectDiscovery",
	"odin-scanner":         "ODIN (odin.io)",
	"securitytrails":       "SecurityTrails (Recorded Future)",
	"netcraft":             "Netcraft",
	"bytespider-bot":       "ByteDance (Bytespider)",
	"research-crawler":     "academic / research internet survey",

	// --- commercial vulnerability scanners ---
	"nessus":        "Tenable, Inc. (Nessus)",
	"tenable":       "Tenable, Inc.",
	"qualys":        "Qualys, Inc.",
	"nexpose":       "Rapid7 (Nexpose)",
	"insightvm":     "Rapid7 (InsightVM)",
	"acunetix":      "Invicti (Acunetix)",
	"netsparker":    "Invicti (Netsparker)",
	"invicti":       "Invicti Security",
	"appscan":       "HCL Software (AppScan)",
	"openvas":       "Greenbone (OpenVAS / GVM)",
	"detectify":     "Detectify",
	"intruder":      "Intruder.io",
	"pentest-tools": "Pentest-Tools.com",
	"burpsuite":     "PortSwigger (Burp Suite)",
	"owasp-zap":     "OWASP / Checkmarx (ZAP)",

	// --- port / mass scanners ---
	"nmap":      "Nmap Project (Gordon Lyon)",
	"nmap-nse":  "Nmap Project (NSE script)",
	"masscan":   "Robert Graham (masscan)",
	"zgrab":     "ZMap Project / Censys",
	"zmap":      "ZMap Project",
	"rustscan":  "RustScan (open source)",
	"naabu":     "ProjectDiscovery (naabu)",
	"l9explore": "LeakIX (l9explore)",

	// --- offensive frameworks / C2 ---
	"metasploit":   "Rapid7 (Metasploit Framework)",
	"cobaltstrike": "Fortra (Cobalt Strike)",
	"core-impact":  "Fortra (Core Impact)",
	"bruteratel":   "Brute Ratel C4 (Dark Vortex)",
	"sliver":       "Bishop Fox (Sliver)",
	"mythic":       "Mythic (open source)",
	"empire":       "PowerShell Empire (open source)",
	"havoc":        "Havoc Framework (open source)",
	"nuclei":       "ProjectDiscovery (nuclei)",
	"sqlmap":       "sqlmap project (open source)",
	"nikto":        "CIRT.net (Nikto)",
	"wpscan":       "Automattic (WPScan)",

	// --- credential brute-forcers ---
	"hydra":  "van Hauser / THC (hydra)",
	"medusa": "JoMo-Kun (Medusa)",
	"ncrack": "Nmap Project (Ncrack)",
}

// Vendor returns the organization/project behind a tool identifier, or ""
// when unknown. Descriptive reference metadata only.
func Vendor(tool string) string { return vendors[tool] }

// Vendors maps each known tool in the list to its vendor, preserving order
// and skipping unknowns. Returns nil when none are known.
func Vendors(tools []string) []string {
	var out []string
	for _, t := range tools {
		if v := vendors[t]; v != "" {
			out = appendUnique(out, v)
		}
	}
	return out
}
