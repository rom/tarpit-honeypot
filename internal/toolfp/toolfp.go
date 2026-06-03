// Package toolfp identifies the scanning / attack tool behind a
// connection and estimates whether the client is automation or a
// human at a keyboard. It works from cheap, already-captured signals
// (User-Agent, request path, header set, JA3/JA4 fingerprints, banner
// shape) — no extra round-trips. Handlers feed it what they captured;
// it returns tool tags + an automation verdict that the listener
// promotes to event meta + anomalies, so a SIEM can pivot on
// "tool=nmap" or "automation=true".
package toolfp

import "strings"

// HTTPSignals is what the http/mgmt-web handlers hand toolfp.
type HTTPSignals struct {
	Method    string
	Path      string
	UserAgent string
	// HeaderKeys is the ordered list of header names seen (lower-case).
	HeaderKeys []string
}

// Verdict bundles the result.
type Verdict struct {
	// Tools is the set of tool/scanner names identified (e.g.
	// ["nmap"], ["sqlmap"], ["metasploit"]). Empty when unrecognized.
	Tools []string
	// Automation is true when the client looks like a script/scanner
	// rather than an interactive browser.
	Automation bool
	// Scanner is true when one of the identified Tools is a known
	// vulnerability scanner (Nessus, OpenVAS/Greenbone, Qualys, Nexpose/
	// InsightVM, Acunetix, Nikto, Nuclei, sqlmap, …). Lets a SOC pivot on
	// "a vuln scan hit us" regardless of which product.
	Scanner bool
	// Category is the coarse class of the strongest identified tool, for
	// SOC pivots: "c2" (Cobalt Strike / Mythic / Empire / Covenant / …),
	// "vuln-scanner", "headless" (Selenium / Puppeteer / headless Chrome),
	// "tool" (any other identified tool), or "" (unidentified).
	Category string
	// Confidence is how reliable the identification is (0-100), expressing
	// signal strength rather than how dangerous the tool is. See the Conf*
	// constants and ConfidenceLabel.
	Confidence int
	// Reason is a short human-readable explanation of the verdict.
	Reason string
}

// Confidence levels for a tool/automation identification — how reliable the
// signal is, not how dangerous the tool is:
//
//	high   — the client self-identified (UA tool string, SSH banner sent in
//	         clear) or matched a cryptographic fingerprint (JA3 hash).
//	medium — a tool-specific request path matched, or automation was clear
//	         from a missing/non-browser User-Agent (the *specific* tool is
//	         less certain than a self-identification).
//	low    — automation inferred purely from a weak heuristic (browser UA
//	         but absent Accept-* headers); no tool named.
const (
	ConfHigh   = 90
	ConfMedium = 65
	ConfLow    = 40
)

// ConfidenceLabel maps a numeric confidence to a coarse label
// ("high"/"medium"/"low"), or "" for zero.
func ConfidenceLabel(c int) string {
	switch {
	case c >= 80:
		return "high"
	case c >= 55:
		return "medium"
	case c > 0:
		return "low"
	default:
		return ""
	}
}

// c2Frameworks are command-and-control / red-team frameworks — the highest-
// severity identification class.
var c2Frameworks = map[string]bool{
	"cobaltstrike": true, "metasploit": true, "mythic": true, "empire": true,
	"covenant": true, "sliver": true, "havoc": true, "bruteratel": true,
	"core-impact": true, "antsword": true, "behinder": true, "godzilla": true,
	"merlin": true, "villain": true, "pupy": true, "poshc2": true,
	"nimplant": true, "silenttrinity": true, "koadic": true, "quasar": true,
	"asyncrat": true, "njrat": true, "deimos": true,
}

// headlessBrowsers are automation drivers masquerading as browsers.
var headlessBrowsers = map[string]bool{
	"headless-chrome": true, "phantomjs": true, "puppeteer": true,
	"playwright": true, "selenium": true,
}

// IsC2 / IsHeadless classify an identified tool name.
func IsC2(tool string) bool       { return c2Frameworks[tool] }
func IsHeadless(tool string) bool { return headlessBrowsers[tool] }

// classify returns the coarse Category for a set of identified tools,
// preferring the most severe class.
func classify(tools []string) string {
	for _, t := range tools {
		if IsC2(t) {
			return "c2"
		}
	}
	for _, t := range tools {
		if IsVulnScanner(t) {
			return "vuln-scanner"
		}
	}
	for _, t := range tools {
		if IsHeadless(t) {
			return "headless"
		}
	}
	if len(tools) > 0 {
		return "tool"
	}
	return ""
}

// vulnScanners is the set of identified tool names that are vulnerability
// scanners (vs. recon engines, content-discovery fuzzers, or brute-forcers).
var vulnScanners = map[string]bool{
	"nessus": true, "tenable": true, "openvas": true, "qualys": true, "nexpose": true,
	"insightvm": true, "rapid7": true, "acunetix": true, "netsparker": true,
	"invicti": true, "appscan": true, "nikto": true, "nuclei": true,
	"arachni": true, "w3af": true, "skipfish": true, "wapiti": true,
	"owasp-zap": true, "burpsuite": true, "vega": true, "wpscan": true,
	"joomscan": true, "droopescan": true, "cmsmap": true, "sqlmap": true,
	"commix": true, "xsstrike": true, "dalfox": true, "jaeles": true,
	"metasploit": true, "whatweb": true,
	"nosqlmap": true, "tplmap": true, "ssrfmap": true, "cmseek": true,
	"vulmap": true, "clusterd": true, "jok3r": true, "osmedeus": true,
	"routersploit": true, "autosploit": true, "vulners": true, "garak": true,
	"wafw00f": true,
	"sn1per":  true, "afrog": true, "fscan": true, "kscan": true, "goby": true,
	"vscan": true, "w13scan": true, "xray": true, "pocsuite": true, "dismap": true,
	"yakit": true,
}

// IsVulnScanner reports whether an identified tool name is a vulnerability
// scanner.
func IsVulnScanner(tool string) bool { return vulnScanners[tool] }

// uaSignatures maps a lower-cased User-Agent substring to a tool name.
// These are the literal UA strings the named tools send by default.
var uaSignatures = map[string]string{
	// Port / service scanners.
	"nmap scripting engine": "nmap",
	"masscan":               "masscan",
	"zgrab":                 "zgrab",
	"zmap":                  "zmap",
	"l9explore":             "l9explore",
	"l9tcpid":               "l9explore",

	// Internet-wide recon / OSINT engines.
	"censysinspect":            "censys",
	"shodan":                   "shodan",
	"binaryedge":               "binaryedge",
	"netsystemsresearch":       "netsystems-research",
	"internet-measurement.com": "internet-measurement",
	"internetmeasurement":      "internet-measurement",
	"leakix":                   "leakix",
	"expanse":                  "expanse",
	"stretchoid":               "stretchoid",
	"shadowserver":             "shadowserver",
	"onyphe":                   "onyphe",
	"criminalip":               "criminalip",
	"projectdiscovery":         "projectdiscovery",
	"odin":                     "odin-scanner",
	"censys.io":                "censys",

	// Web vulnerability scanners.
	"sqlmap":           "sqlmap",
	"nikto":            "nikto",
	"nuclei":           "nuclei",
	"acunetix":         "acunetix",
	"nessus":           "nessus",
	"openvas":          "openvas",
	"qualys":           "qualys",
	"netsparker":       "netsparker",
	"invicti":          "invicti",
	"appscan":          "appscan",
	"arachni":          "arachni",
	"w3af":             "w3af",
	"skipfish":         "skipfish",
	"wapiti":           "wapiti",
	"whatweb":          "whatweb",
	"zaproxy":          "owasp-zap",
	"owasp zap":        "owasp-zap",
	"burp":             "burpsuite",
	"vega":             "vega",
	"wpscan":           "wpscan",
	"joomscan":         "joomscan",
	"droopescan":       "droopescan",
	"cmsmap":           "cmsmap",
	"commix":           "commix",
	"xsstrike":         "xsstrike",
	"nuclei-templates": "nuclei",
	// More enterprise / network vulnerability scanners.
	"nessuscli":   "nessus",
	"nexpose":     "nexpose",
	"insightvm":   "insightvm",
	"greenbone":   "openvas",
	"gvm":         "openvas",
	"meterpreter": "metasploit",

	// Content discovery / fuzzers.
	"dirbuster":   "dirbuster",
	"gobuster":    "gobuster",
	"feroxbuster": "feroxbuster",
	"ffuf":        "ffuf",
	"dirsearch":   "dirsearch",
	"wfuzz":       "wfuzz",
	"katana":      "katana",
	"httpx":       "httpx",

	// Credential brute-forcers.
	"hydra":      "hydra",
	"medusa":     "medusa",
	"ncrack":     "ncrack",
	"patator":    "patator",
	"brutespray": "brutespray",

	// Exploitation / C2 / red-team frameworks + webshell managers.
	"metasploit":        "metasploit",
	"core impact":       "core-impact",
	"cobaltstrike":      "cobaltstrike",
	"cobalt strike":     "cobaltstrike",
	"mythic":            "mythic",
	"empire":            "empire",
	"powershell-empire": "empire",
	"covenant":          "covenant",
	"sliver":            "sliver",
	"havoc":             "havoc",
	"brute ratel":       "bruteratel",
	"antsword":          "antsword",
	"behinder":          "behinder",
	"godzilla":          "godzilla",

	// Headless-browser / automation drivers (recon, scraping, exploit
	// delivery) — never a real interactive user. (naabu/rustscan are
	// classified below with the other scanners.)
	"headlesschrome": "headless-chrome",
	"headless":       "headless-chrome",
	"phantomjs":      "phantomjs",
	"puppeteer":      "puppeteer",
	"playwright":     "playwright",
	"selenium":       "selenium",
	"webdriver":      "selenium",

	// Generic HTTP libraries / scripting runtimes (lower confidence — many
	// legit clients, but never an interactive browser).
	"go-http-client":             "go-scanner",
	"python-requests":            "python-script",
	"python-urllib":              "python-script",
	"python-httpx":               "python-script",
	"aiohttp":                    "python-script",
	"scrapy":                     "python-script",
	"mechanize":                  "python-script",
	"curl/":                      "curl",
	"wget/":                      "wget",
	"libwww-perl":                "perl-script",
	"okhttp":                     "okhttp-script",
	"apache-httpclient":          "java-http",
	"java/":                      "java-http",
	"jakarta commons-httpclient": "java-http",
	"guzzlehttp":                 "php-script",
	"lua-resty-http":             "lua-script",
	"node-fetch":                 "node-script",
	"axios":                      "node-script",
	"got (https://github.com/sindresorhus/got)": "node-script",
	"winhttp":                "windows-script",
	"powershell":             "powershell",
	"restsharp":              "dotnet-http",
	"ruby":                   "ruby-script",
	"faraday":                "ruby-script",
	"http.rb":                "ruby-script",
	"zabbix":                 "zabbix-probe",
	"hello, world":           "scanner-stub",
	"custom-asynchttpclient": "scanner-stub",
	// More recon engines / SaaS scanners.
	"rapid7":           "rapid7",
	"tenable":          "tenable",
	"detectify":        "detectify",
	"intruder.io":      "intruder",
	"pentest-tools":    "pentest-tools",
	"modat":            "modat-scanner",
	"netcraft":         "netcraft",
	"cortex xpanse":    "expanse",
	"paloaltonetworks": "expanse",
	"bytespider":       "bytespider-bot",
	"google-cloud-sdk": "gcloud-script",
	// More vuln scanners / fuzzers.
	"rustscan":  "rustscan",
	"naabu":     "naabu",
	"testssl":   "testssl",
	"sslyze":    "sslyze",
	"nmap.org":  "nmap",
	"dalfox":    "dalfox",
	"crlfuzz":   "crlfuzz",
	"jaeles":    "jaeles",
	"gospider":  "gospider",
	"hakrawler": "hakrawler",
	// More HTTP clients / runtimes.
	"httpie":         "httpie",
	"postmanruntime": "postman",
	"insomnia":       "insomnia",
	"reqwest":        "rust-http",
	"hyper":          "rust-http",
	"http_request2":  "php-script",
	"symfony":        "php-script",
	"typhoeus":       "ruby-script",
	"deno":           "deno-script",
	"bun":            "bun-script",
	"electron":       "electron-client",
	"uipath":         "rpa-bot",
	// --- HTTP client libraries / frameworks, grouped by language ---
	// shell / cli.
	"lwp-request": "perl-script",
	"libcurl":     "c-http",
	// python.
	"urllib3":       "python-script",
	"pycurl":        "python-script",
	"httplib2":      "python-script",
	"treq":          "python-script",
	"uplink":        "python-script",
	"tornado":       "python-script",
	"grequests":     "python-script",
	"requests-html": "python-script",
	// perl.
	"lwp::":         "perl-script",
	"http::tiny":    "perl-script",
	"mojolicious":   "perl-script",
	"www-mechanize": "perl-script",
	"anyevent-http": "perl-script",
	// go.
	"go-resty":  "go-http",
	"fasthttp":  "go-http",
	"heroku-go": "go-http",
	// java / jvm.
	"jersey":       "java-http",
	"unirest-java": "java-http",
	"vert.x":       "java-http",
	"jetty":        "java-http",
	"reactornetty": "java-http",
	"retrofit":     "java-http",
	"openfeign":    "java-http",
	"ktor-client":  "kotlin-http",
	"scalaj-http":  "scala-http",
	"akka-http":    "scala-http",
	// c / c++.
	"libsoup":  "c-http",
	"libwww":   "c-http",
	"wininet":  "windows-script",
	"winhttp.": "windows-script",
	// .net.
	"system.net.http": "dotnet-http",
	"flurl":           "dotnet-http",
	"servicestack":    "dotnet-http",
	".net cli":        "dotnet-http",
	// rust.
	"ureq":  "rust-http",
	"isahc": "rust-http",
	// --- more recon / attack tooling ---
	"vulnx":       "vulnx",
	"cariddi":     "cariddi",
	"subfinder":   "subfinder",
	"amass":       "amass",
	"dnsx":        "dnsx",
	"interactsh":  "interactsh",
	"gau ":        "gau",
	"waybackurls": "waybackurls",
	"nuclei-fuzz": "nuclei",
	// PowerShell web cmdlets + more runtimes.
	"pwsh":              "powershell",
	"invoke-webrequest": "powershell",
	"invoke-restmethod": "powershell",
	"windowspowershell": "powershell",
	"niquests":          "python-script",
	"primp":             "python-script",
	"httprobe":          "httprobe",
	// Parameter / endpoint discovery tooling.
	"arjun":       "arjun",
	"paramspider": "paramspider",
	"kiterunner":  "kiterunner",
	"x8":          "x8",
	"nuclei-dast": "nuclei",
	// More recon / threat-intel scanners.
	"securitytrails": "securitytrails",
	"driftnet":       "driftnet-scanner",
	"alphastrike":    "alphastrike",
	"recyber":        "recyber",
	"internetscan":   "internet-scanner",
	"mauscan":        "mauscan",
	"aazscan":        "aazscan",

	// --- Batch: 50+ additional scanner / recon / brute-force / C2 / botnet
	// fingerprints (User-Agent self-identification). ---
	// Network / web / OSINT scanners + recon CLIs.
	"wafw00f":      "wafw00f",
	"unicornscan":  "unicornscan",
	"assetfinder":  "assetfinder",
	"massdns":      "massdns",
	"puredns":      "puredns",
	"shuffledns":   "shuffledns",
	"dnsrecon":     "dnsrecon",
	"fierce":       "fierce",
	"sublist3r":    "sublist3r",
	"theharvester": "theharvester",
	"recon-ng":     "recon-ng",
	"researchscan": "researchscan",
	"gdnplus":      "gdnplus-scanner",
	"hostedscan":   "hostedscan",
	"vulners":      "vulners",
	// Web / app vulnerability + exploit scanners.
	"nosqlmap":     "nosqlmap",
	"tplmap":       "tplmap",
	"ssrfmap":      "ssrfmap",
	"cmseek":       "cmseek",
	"vulmap":       "vulmap",
	"clusterd":     "clusterd",
	"jok3r":        "jok3r",
	"osmedeus":     "osmedeus",
	"routersploit": "routersploit",
	"autosploit":   "autosploit",
	"searchsploit": "searchsploit",
	"garak":        "garak", // LLM/AI vulnerability scanner
	// Secret / repo scrapers.
	"git-dumper": "git-dumper",
	"gitdumper":  "git-dumper",
	"trufflehog": "trufflehog",
	"gitleaks":   "gitleaks",
	// Credential brute-force / post-exploitation toolkits.
	"netexec":      "netexec",
	"crackmapexec": "crackmapexec",
	// Tunneling / pivot / relay tools (a post-exploitation tell).
	"chisel":    "chisel",
	"ligolo":    "ligolo",
	"gost/":     "gost",
	"frpc":      "frp",
	"rsockstun": "rsockstun",
	// Phishing proxies / kits.
	"gophish":   "gophish",
	"evilginx":  "evilginx",
	"muraena":   "muraena",
	"modlishka": "modlishka",
	// C2 frameworks + RATs.
	"merlin":        "merlin",
	"villain":       "villain",
	"pupy":          "pupy",
	"poshc2":        "poshc2",
	"nimplant":      "nimplant",
	"silenttrinity": "silenttrinity",
	"koadic":        "koadic",
	"quasar":        "quasar",
	"asyncrat":      "asyncrat",
	"njrat":         "njrat",
	"deimos":        "deimos",
	// Crypto-miners / IoT botnet loaders.
	"xmrig":   "xmrig",
	"kinsing": "kinsing",
	"hajime":  "hajime",
	"gafgyt":  "gafgyt",
	"tsunami": "tsunami",
	// Misc HTTP clients favoured by tooling.
	"hyper/":            "hyper-rust",
	"interactsh-client": "interactsh",

	// --- Batch: 25 more recon / OSINT / vuln-scan / ProjectDiscovery / Chinese-
	// offensive-toolkit fingerprints. ---
	"sn1per":       "sn1per",
	"afrog":        "afrog",
	"fscan":        "fscan",
	"kscan":        "kscan",
	"yakit":        "yakit",
	"goby":         "goby",
	"vscan":        "vscan",
	"w13scan":      "w13scan",
	"xray":         "xray",
	"pocsuite":     "pocsuite",
	"spiderfoot":   "spiderfoot",
	"gowitness":    "gowitness",
	"aquatone":     "aquatone",
	"eyewitness":   "eyewitness",
	"dirstalk":     "dirstalk",
	"metabigor":    "metabigor",
	"asnmap":       "asnmap",
	"cdncheck":     "cdncheck",
	"tlsx":         "tlsx",
	"uncover":      "uncover",
	"notify":       "projectdiscovery",
	"proxify":      "proxify",
	"chaos-client": "chaos-client",
	"dnsgen":       "dnsgen",
	"dismap":       "dismap",
}

// pathSignatures maps a request-path substring to a tool/probe — used
// when the UA is spoofed or absent (most scanners send a benign UA but
// hit tool-specific paths).
var pathSignatures = map[string]string{
	// Scanner self-probes.
	"/nmaplowercheck":  "nmap", // nmap http-probe
	"/nice%20ports%2c": "nmap", // nmap service-scan path
	"/sdk/../":         "sqlmap",
	"/?search=sqlmap":  "sqlmap",

	// Recon / source + secret leakage.
	"/.git/head":           "scanner-recon",
	"/.git/config":         "scanner-recon",
	"/.svn/entries":        "scanner-recon",
	"/.env":                "scanner-recon",
	"/.aws/credentials":    "scanner-recon",
	"/server-status":       "scanner-recon",
	"/actuator/":           "scanner-recon",
	"/solr/":               "scanner-recon",
	"/manager/html":        "scanner-recon", // Tomcat
	"/phpmyadmin":          "scanner-recon",
	"/adminer.php":         "scanner-recon",
	"/wp-json/wp/v2/users": "wpscan", // user enumeration
	"/wp-login.php":        "wpscan",
	"/xmlrpc.php":          "wpscan",
	"/telescope/requests":  "scanner-recon", // Laravel Telescope
	"/debug/default/view":  "scanner-recon", // Yii debug

	// Named CVE / framework exploit probes.
	"/vendor/phpunit/phpunit/src/util/php/eval-stdin.php": "cve-2017-9841",  // PHPUnit RCE
	"/_ignition/execute-solution":                         "cve-2021-3129",  // Laravel Ignition RCE
	"/wls-wsat/coordinatorporttype":                       "cve-2017-10271", // WebLogic
	"/console/css/%252e":                                  "weblogic-exploit",
	"/api/jsonws/invoke":                                  "liferay-exploit",
	"/remote/fgt_lang":                                    "cve-2018-13379", // FortiOS SSL-VPN traversal
	"/remote/login":                                       "fortinet-probe",
	"/+cscou+/../":                                        "citrix-exploit", // CVE-2019-19781
	"/vpn/../vpns/":                                       "citrix-exploit",
	"/dana-na/":                                           "pulse-vpn-probe", // Pulse Secure
	"/owa/auth/":                                          "exchange-probe",
	"/autodiscover/autodiscover.json":                     "proxyshell", // Exchange ProxyShell
	"/ecp/":                                               "exchange-probe",
	"/catalog-portal/ui/oauth/verify":                     "vmware-exploit", // CVE-2022-22954
	"/cgi-bin/viewlog.asp":                                "zyxel-exploit",  // CVE-2020-9054
	"/setup.cgi":                                          "router-exploit",
	"/boaform/admin":                                      "router-exploit",
	"/cgi-bin/luci":                                       "router-exploit",
	"/hnap1/":                                             "router-exploit",
	"/gponform/diag_form":                                 "router-exploit", // GPON CVE-2018-10561
	"/shell?":                                             "mirai-exploit",  // common Mirai/Gafgyt RCE
	"/cgi-bin/mainfunction.cgi":                           "router-exploit", // DrayTek
	"/jenkins/script":                                     "jenkins-exploit",
	"/struts2-showcase/":                                  "struts-exploit",
	"${jndi:":                                             "log4shell",          // Log4Shell in path/query
	"/api/v2/static/none/":                                "confluence-exploit", // CVE-2021-26084
	"/login.action":                                       "confluence-probe",
	"/druid/index.html":                                   "scanner-recon",
	"/geoserver/web/":                                     "geoserver-exploit",
	"/cgi-bin/.%2e/":                                      "cve-2021-41773",
	"/telerik.web.ui.webresource.axd":                     "cve-2019-18935",
	"/cfide/administrator/":                               "coldfusion-probe",
	"/cf_scripts/scripts/ajax/ckeditor/":                  "coldfusion-exploit",
	"/solr/admin/cores":                                   "solr-probe",
	"/_cat/indices":                                       "elasticsearch-probe",
	"/+cscoe+/logon.html":                                 "cisco-asa-probe",
	"/cgi-bin/system_mgr.cgi":                             "dlink-exploit",
	"/cgi-bin/nas_sharing.cgi":                            "dlink-exploit",
	"/goform/set_lansetting":                              "router-exploit",
	"/api/sonicos/":                                       "sonicwall-probe",
	"/secure/contactadministrators!default.jspa":          "cve-2019-11581",
	"/wp-content/plugins/":                                "wpscan",
	"/v2/_catalog":                                        "registry-probe",
}

// browserUASubstrings are tokens that, when present, indicate a real
// browser (or something faithfully impersonating one). Used in the
// automation heuristic.
var browserUASubstrings = []string{
	"mozilla/5.0", "applewebkit", "gecko/", "chrome/", "safari/",
	"firefox/", "edg/", "opr/",
}

// IdentifyHTTP returns the tool/automation verdict for an HTTP request.
func IdentifyHTTP(s HTTPSignals) Verdict {
	v := Verdict{}
	ua := strings.ToLower(s.UserAgent)
	path := strings.ToLower(s.Path)

	uaMatched := false
	for needle, tool := range uaSignatures {
		if strings.Contains(ua, needle) {
			v.Tools = appendUnique(v.Tools, tool)
			uaMatched = true
		}
	}
	for needle, tool := range pathSignatures {
		if strings.Contains(path, needle) {
			v.Tools = appendUnique(v.Tools, tool)
		}
	}
	for _, tool := range v.Tools {
		if IsVulnScanner(tool) {
			v.Scanner = true
			break
		}
	}
	v.Category = classify(v.Tools)

	// Automation heuristic + identification confidence.
	switch {
	case len(v.Tools) > 0:
		v.Automation = true
		v.Reason = "matched tool signature"
		// A UA tool string is a self-identification (high); a path-only
		// match means the UA was spoofed/absent and we inferred the tool
		// from a tool-specific request path (medium).
		if uaMatched {
			v.Confidence = ConfHigh
		} else {
			v.Confidence = ConfMedium
		}
	case s.UserAgent == "":
		// A browser always sends a User-Agent; its absence on an HTTP/1.1
		// request is a strong automation signal.
		v.Automation = true
		v.Reason = "no User-Agent header"
		v.Confidence = ConfMedium
	case !looksLikeBrowserUA(ua):
		v.Automation = true
		v.Reason = "non-browser User-Agent"
		v.Confidence = ConfMedium
	case !hasBrowserHeaderSet(s.HeaderKeys):
		// A real browser sends Accept / Accept-Language / Accept-Encoding;
		// scripts impersonating a browser UA usually omit them.
		v.Automation = true
		v.Reason = "browser UA but missing Accept-* headers"
		v.Confidence = ConfLow
	default:
		v.Automation = false
		v.Reason = "browser-like"
	}
	return v
}

// known scanner JA3 hashes (md5 of the JA3 string). A small, curated
// set — the common scanners' default TLS stacks produce stable JA3s.
var ja3Signatures = map[string]string{
	// (illustrative — operators extend this from their own corpus)
	"a0e9f5d64349fb13191bc781f81f42e1": "java-tls", // generic Java client (metasploit/burp)
	"e7d705a3286e19ea42f587b344ee6865": "go-tls",   // Go crypto/tls (many scanners)
}

// IdentifyTLS maps a JA3 hash to a known TLS-stack/tool name, or "".
func IdentifyTLS(ja3 string) string {
	return ja3Signatures[strings.TrimSpace(ja3)]
}

type sshSig struct{ needle, tool string }

// sshClientSignatures matches a lower-cased SSH client identification
// string ("SSH-2.0-<software>") to a tool/library, most-specific first so
// libssh2 wins over libssh. OpenSSH is intentionally excluded — it's the
// overwhelming legitimate default and would be pure noise.
var sshClientSignatures = []sshSig{
	{"libssh2", "libssh2"}, // curl / scripts
	{"libssh", "libssh"},   // hydra + many scanners
	{"paramiko", "paramiko"},
	{"phpseclib", "phpseclib"},
	{"jsch", "jsch"},
	{"trilead", "trilead-ssh"},
	{"renci.sshnet", "ssh.net"},
	{"sshnet", "ssh.net"},
	{"rebex", "rebex-ssh"},
	{"putty", "putty"},
	{"winscp", "winscp"},
	{"russh", "russh"},
	{"scanssh", "scanssh"},
	{"zgrab", "zgrab"},
	{"nmap", "nmap"},
	{"twistedconch", "twisted-conch"},
	{"erlang", "erlang-ssh"},
	{"maverick", "maverick-ssh"},
	{"sshlib", "sshlib"},
	{"go", "go-ssh"}, // matched specially: exactly SSH-2.0-Go
}

// IdentifySSH maps an SSH client identification string to known
// tool/library names. Reliable because the banner is sent in the clear
// before key exchange.
func IdentifySSH(clientID string) []string {
	id := strings.ToLower(strings.TrimSpace(clientID))
	if id == "" {
		return nil
	}
	var tools []string
	for _, s := range sshClientSignatures {
		switch s.needle {
		case "go":
			// The Go x/crypto banner is exactly "SSH-2.0-Go" (optionally
			// with a trailing comment) — don't match every "...go..." word.
			if id == "ssh-2.0-go" || strings.HasPrefix(id, "ssh-2.0-go ") || strings.HasPrefix(id, "ssh-2.0-go-") {
				tools = appendUnique(tools, s.tool)
			}
		case "libssh":
			// libssh2 already implies libssh substring; don't double-tag.
			if !contains(tools, "libssh2") && strings.Contains(id, "libssh") {
				tools = appendUnique(tools, s.tool)
			}
		default:
			if strings.Contains(id, s.needle) {
				tools = appendUnique(tools, s.tool)
			}
		}
	}
	return tools
}

func contains(list []string, item string) bool {
	for _, e := range list {
		if e == item {
			return true
		}
	}
	return false
}

func looksLikeBrowserUA(ua string) bool {
	for _, b := range browserUASubstrings {
		if strings.Contains(ua, b) {
			return true
		}
	}
	return false
}

func hasBrowserHeaderSet(keys []string) bool {
	hasAccept, hasLang := false, false
	for _, k := range keys {
		switch k {
		case "accept":
			hasAccept = true
		case "accept-language":
			hasLang = true
		}
	}
	return hasAccept && hasLang
}

func appendUnique(list []string, item string) []string {
	for _, e := range list {
		if e == item {
			return list
		}
	}
	return append(list, item)
}
