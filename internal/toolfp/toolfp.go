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
	"dnscat2": true, "hoaxshell": true, "manjusaka": true,
	"chashell": true, "godoh": true, "shad0w": true, "caldera": true,
	"supershell": true, "phpsploit": true, "weevely": true,
	"hardhatc2": true, "adaptixc2": true,
	"slackor": true, "toxssin": true, "trevorc2": true,
	"geacon": true, "crossc2": true, "redwarden": true, "starkiller": true, "nimbo-c2": true,
	// Batch 10: more red-team C2 + commodity RAT/loader families.
	"nighthawk": true, "nuages": true, "remcos": true, "dcrat": true,
	"venomrat": true, "xworm": true, "limerat": true, "revengerat": true,
	"warzonerat": true, "netwire": true, "nanocore": true, "orcus": true,
	"darkcomet": true, "spynote": true, "agenttesla": true, "formbook": true,
	"smokeloader": true,
	// Batch 11: banking-trojan / loader / RAT families seen staging over HTTP.
	"emotet": true, "trickbot": true, "qakbot": true, "icedid": true,
	"bumblebee": true, "darkgate": true, "pikabot": true, "latrodectus": true,
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
	"yakit":      true,
	"graphqlmap": true, "log4j-scanner": true, "struts-pwn": true, "fuxploider": true,
	"shortscan": true, "davtest": true, "magescan": true, "aem-hacker": true,
	"wprecon": true, "byp4xx": true, "h2csmuggler": true,
	"jexboss": true, "weblogicscan": true, "vbscan": true, "typo3scan": true,
	"struts-scan": true, "tomcatwardeployer": true, "corsy": true, "smuggler": true,
	"dontgo403": true, "nomore403": true, "lfimap": true, "fimap": true,
	"sslscan": true, "cipherscan": true, "a2sv": true, "ike-scan": true,
	"gxss": true, "kxss": true, "ppfuzz": true, "ppmap": true, "gopherus": true,
	"dirdar": true, "wpprobe": true, "joomlavs": true, "drupwn": true,
	"graphql-cop": true, "akto": true,
	"wafninja": true, "sqlninja": true, "bbqsql": true, "jsql": true,
	"snallygaster": true, "yawast": true,
	"ghauri": true, "sstimap": true, "tinja": true, "xsser": true, "xspear": true,
	"oralyzer": true, "openredirex": true, "crlfsuite": true, "wcvs": true,
	"mongoaudit": true, "domdig": true,
	"dotdotpwn": true, "panoptic": true, "xxeinjector": true, "blisqy": true,
	"kadimus": true, "liffy": true, "retirejs": true,
	"vuls": true, "rapidscan": true, "sitadel": true, "scanqli": true, "dirhunt": true,
	// Batch 10: more web/CMS/API/mobile vulnerability + injection scanners.
	"moodlescan": true, "cmsscan": true, "scant3r": true, "403fuzzer": true,
	"headerpwn": true, "smugglefuzz": true, "param-miner": true,
	"spring4shell-scan": true, "fastjson-scan": true, "shiro-scan": true,
	"wpintel": true, "apkleaks": true, "mobsf": true, "jwtcat": true,
	"ratproxy": true, "golismero": true, "wascan": true, "striker": true,
	"yuki-chan": true, "spaghetti": true, "taipan": true, "wpseku": true,
	"plecost": true, "nettacker": true, "blackwidow": true, "v3n0m": true,
	"wpgarlic": true, "ssrfire": true,
	// Batch 11: more web / API / injection vulnerability scanners.
	"scan4all": true, "dirmap": true, "uniscan": true, "webpwn3r": true,
	"vulscan": true, "jwtxploiter": true, "graphql-path-enum": true,
	"batchql": true, "dsss": true, "sqliv": true,
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

	// --- Batch: 25 more AD / post-exploitation / web-exploit / DNS-C2
	// fingerprints (User-Agent self-identification). ---
	// Active Directory / Windows post-exploitation toolkits.
	"kerbrute":     "kerbrute",
	"smbmap":       "smbmap",
	"enum4linux":   "enum4linux",
	"evil-winrm":   "evil-winrm",
	"impacket":     "impacket",
	"bloodhound":   "bloodhound",
	"certipy":      "certipy",
	"windapsearch": "windapsearch",
	// Web / API / app exploit + vuln scanners.
	"graphw00f":   "graphw00f",
	"graphqlmap":  "graphqlmap",
	"log4j-scan":  "log4j-scanner",
	"struts-pwn":  "struts-pwn",
	"fuxploider":  "fuxploider",
	"shortscan":   "shortscan",
	"davtest":     "davtest",
	"magescan":    "magescan",
	"aem-hacker":  "aem-hacker",
	"wprecon":     "wprecon",
	"byp4xx":      "byp4xx",
	"h2csmuggler": "h2csmuggler",
	// Crawlers / tech fingerprinters.
	"crawlergo":  "crawlergo",
	"webanalyze": "webanalyze",
	// DNS / HTTP C2 + RATs.
	"dnscat":    "dnscat2",
	"hoaxshell": "hoaxshell",
	"manjusaka": "manjusaka",

	// --- Batch: 75 more offensive-tooling fingerprints (User-Agent
	// self-identification), spanning AD/post-exploitation, web-/product-
	// exploit scanners, recon/subdomain/JS discovery, secret scrapers,
	// cloud/k8s auditors, pivot/tunnel relays, DNS/HTTP C2 + webshells. ---
	// Active Directory / Windows post-exploitation (Impacket family + tooling).
	"mitm6":       "mitm6",
	"pcredz":      "pcredz",
	"lsassy":      "lsassy",
	"nanodump":    "nanodump",
	"donpapi":     "donpapi",
	"coercer":     "coercer",
	"petitpotam":  "petitpotam",
	"secretsdump": "secretsdump",
	"getnpusers":  "getnpusers",
	"getuserspns": "getuserspns",
	"psexec.py":   "psexec",
	"wmiexec":     "wmiexec",
	"smbexec":     "smbexec",
	"mssqlclient": "mssqlclient",
	"ticketer":    "ticketer",
	"ntlmrelayx":  "ntlmrelayx",
	"rubeus":      "rubeus",
	"sharphound":  "sharphound",
	// Java / deserialization exploitation.
	"ysoserial":  "ysoserial",
	"marshalsec": "marshalsec",
	// Web / product / CMS exploit + vuln scanners.
	"jexboss":           "jexboss",
	"weblogicscan":      "weblogicscan",
	"vbscan":            "vbscan",
	"typo3scan":         "typo3scan",
	"struts-scan":       "struts-scan",
	"tomcatwardeployer": "tomcatwardeployer",
	"corsy":             "corsy",
	"smuggler":          "smuggler",
	"dontgo403":         "dontgo403",
	"nomore403":         "nomore403",
	"lfimap":            "lfimap",
	"fimap":             "fimap",
	// TLS / SSL / IKE configuration scanners.
	"sslscan":    "sslscan",
	"cipherscan": "cipherscan",
	"a2sv":       "a2sv",
	"ike-scan":   "ike-scan",
	// Subdomain / DNS / asset recon.
	"gauplus":      "gauplus",
	"waymore":      "waymore",
	"urlfinder":    "urlfinder",
	"findomain":    "findomain",
	"knockpy":      "knockpy",
	"zdns":         "zdns",
	"dnsvalidator": "dnsvalidator",
	"photon":       "photon",
	// JavaScript / endpoint / secret-in-source discovery.
	"linkfinder":   "linkfinder",
	"secretfinder": "secretfinder",
	"getjs":        "getjs",
	"xnlinkfinder": "xnlinkfinder",
	"crawley":      "crawley",
	// Secret / repository scrapers.
	"noseyparker":   "noseyparker",
	"gitdorker":     "gitdorker",
	"dumpsterdiver": "dumpsterdiver",
	// Cloud / Kubernetes recon + auditing.
	"pacu":        "pacu",
	"scoutsuite":  "scoutsuite",
	"prowler":     "prowler",
	"s3scanner":   "s3scanner",
	"kube-hunter": "kube-hunter",
	// Pivot / tunnel / relay (a post-exploitation tell).
	"stowaway":    "stowaway",
	"neo-regeorg": "neo-regeorg",
	"regeorg":     "regeorg",
	"pivotnacci":  "pivotnacci",
	"revsocks":    "revsocks",
	// Credential brute-force + phishing kits.
	"crowbar":        "crowbar",
	"brutex":         "brutex",
	"changeme":       "changeme",
	"zphisher":       "zphisher",
	"onesixtyone":    "onesixtyone",
	"smtp-user-enum": "smtp-user-enum",
	// DNS / HTTP C2 + webshell managers.
	"chashell":   "chashell",
	"godoh":      "godoh",
	"shad0w":     "shad0w",
	"caldera":    "caldera",
	"supershell": "supershell",
	"phpsploit":  "phpsploit",
	"weevely":    "weevely",

	// --- Batch: 30 more web-exploit / API / OSINT / recon-framework / cloud
	// fingerprints (User-Agent self-identification). ---
	// Web / API exploit + injection scanners.
	"gxss":        "gxss",
	"kxss":        "kxss",
	"ppfuzz":      "ppfuzz",
	"ppmap":       "ppmap",
	"gopherus":    "gopherus",
	"dirdar":      "dirdar",
	"wpprobe":     "wpprobe",
	"joomlavs":    "joomlavs",
	"drupwn":      "drupwn",
	"graphql-cop": "graphql-cop",
	"akto":        "akto",
	// JS / CSP / endpoint discovery.
	"csprecon": "csprecon",
	"mantra":   "mantra",
	"jsluice":  "jsluice",
	"uddup":    "uddup",
	// All-in-one recon frameworks.
	"autorecon": "autorecon",
	"reconftw":  "reconftw",
	"rengine":   "rengine",
	"favfreak":  "favfreak",
	// People / account / breach OSINT.
	"h8mail":   "h8mail",
	"holehe":   "holehe",
	"maigret":  "maigret",
	"sherlock": "sherlock",
	"ghunt":    "ghunt",
	"dnstwist": "dnstwist",
	// GraphQL tooling.
	"inql":         "inql",
	"clairvoyance": "clairvoyance",
	"crackql":      "crackql",
	// Cloud / IAM enumeration + post-exploitation.
	"cloudfox":      "cloudfox",
	"enumerate-iam": "enumerate-iam",

	// --- Batch: 50 more web-exploit / API / AD / cloud / recon / C2
	// fingerprints (User-Agent self-identification). ---
	// Web injection / XSS / redirect / cache / NoSQL scanners.
	"ghauri":      "ghauri",
	"sstimap":     "sstimap",
	"tinja":       "tinja",
	"xsser":       "xsser",
	"xspear":      "xspear",
	"oralyzer":    "oralyzer",
	"openredirex": "openredirex",
	"crlfsuite":   "crlfsuite",
	"wcvs":        "wcvs",
	"mongoaudit":  "mongoaudit",
	"domdig":      "domdig",
	// JWT attack tooling.
	"jwt_tool":    "jwt-tool",
	"jwt-cracker": "jwt-cracker",
	"jwt-hack":    "jwt-hack",
	// AD / Windows enumeration + Kerberos abuse.
	"ldapdomaindump":     "ldapdomaindump",
	"pingcastle":         "pingcastle",
	"adrecon":            "adrecon",
	"bloodyad":           "bloodyad",
	"pre2k":              "pre2k",
	"targetedkerberoast": "targetedkerberoast",
	"krbrelayx":          "krbrelayx",
	"certsync":           "certsync",
	"spraycharles":       "spraycharles",
	"snmpwn":             "snmpwn",
	// Cloud / bucket enumeration.
	"cloudbrute":     "cloudbrute",
	"gcpbucketbrute": "gcpbucketbrute",
	"cloud_enum":     "cloud_enum",
	"festin":         "festin",
	"s3enum":         "s3enum",
	"cf-hero":        "cf-hero",
	// Subdomain takeover + DNS / asset recon.
	"dnsreaper":         "dnsreaper",
	"subzy":             "subzy",
	"subjack":           "subjack",
	"scilla":            "scilla",
	"haktrails":         "haktrails",
	"tldfinder":         "tldfinder",
	"shosubgo":          "shosubgo",
	"github-subdomains": "github-subdomains",
	"alterx":            "alterx",
	"gotator":           "gotator",
	"ripgen":            "ripgen",
	"bgpview":           "bgpview",
	// Crawlers / endpoint + JS discovery.
	"galer":     "galer",
	"urldedupe": "urldedupe",
	"dorkscout": "dorkscout",
	// Port scanners.
	"nimscan":      "nimscan",
	"sandmap":      "sandmap",
	"threader3000": "threader3000",
	// C2 frameworks.
	"hardhatc2": "hardhatc2",
	"adaptixc2": "adaptixc2",

	// --- Batch: 50 more web-exploit / AD / cloud / OSINT / C2 fingerprints
	// (User-Agent self-identification). ---
	// Web injection / LFI / XXE / SQLi scanners.
	"dotdotpwn":   "dotdotpwn",
	"panoptic":    "panoptic",
	"xxeinjector": "xxeinjector",
	"blisqy":      "blisqy",
	"kadimus":     "kadimus",
	"liffy":       "liffy",
	"retirejs":    "retirejs",
	// Web proxies / tech fingerprint / panel + content discovery.
	"caido":      "caido",
	"wappalyzer": "wappalyzer",
	"cangibrina": "cangibrina",
	"breacher":   "breacher",
	"rustbuster": "rustbuster",
	"filebuster": "filebuster",
	// .NET / secret cracking + exploitation.
	"viewgen":     "viewgen",
	"badsecrets":  "badsecrets",
	"blacklist3r": "blacklist3r",
	// Kubernetes / container escape + recon.
	"kubeletctl":   "kubeletctl",
	"peirates":     "peirates",
	"kdigger":      "kdigger",
	"amicontained": "amicontained",
	"deepce":       "deepce",
	// Cloud (AWS / Azure / M365) audit + attack.
	"cloudsplaining": "cloudsplaining",
	"pmapper":        "pmapper",
	"stormspotter":   "stormspotter",
	"azurehound":     "azurehound",
	"roadrecon":      "roadrecon",
	"o365spray":      "o365spray",
	"teamfiltration": "teamfiltration",
	"trevorspray":    "trevorspray",
	// AD / LDAP / SMB enumeration + coercion.
	"rusthound":  "rusthound",
	"soaphound":  "soaphound",
	"ldeep":      "ldeep",
	"manspider":  "manspider",
	"smbeagle":   "smbeagle",
	"snaffler":   "snaffler",
	"dfscoerce":  "dfscoerce",
	"pywhisker":  "pywhisker",
	"masky":      "masky",
	"adidnsdump": "adidnsdump",
	"ldapnomnom": "ldapnomnom",
	// OSINT / username / phone recon.
	"reconspider": "reconspider",
	"finalrecon":  "finalrecon",
	"blackbird":   "blackbird",
	"nexfil":      "nexfil",
	"toutatis":    "toutatis",
	"phoneinfoga": "phoneinfoga",
	// Phishing.
	"evilgophish": "evilgophish",
	// C2 frameworks + RATs.
	"slackor":  "slackor",
	"toxssin":  "toxssin",
	"trevorc2": "trevorc2",

	// --- Batch: 50 more C2 / AD / cloud / OSINT / recon / DoS fingerprints
	// (User-Agent self-identification), incl. Cobalt Strike cross-platform
	// beacons + tooling. ---
	// Cobalt Strike beacons / proxies + other C2.
	"geacon":     "geacon",
	"crossc2":    "crossc2",
	"redwarden":  "redwarden",
	"starkiller": "starkiller",
	"nimbo-c2":   "nimbo-c2",
	// Vulnerability / web scanners.
	"vuls":      "vuls",
	"rapidscan": "rapidscan",
	"sitadel":   "sitadel",
	"scanqli":   "scanqli",
	"dirhunt":   "dirhunt",
	// AD / Windows post-exploitation + enumeration.
	"seatbelt":   "seatbelt",
	"sharpup":    "sharpup",
	"powerup":    "powerup",
	"certify":    "certify",
	"sharpview":  "sharpview",
	"adexplorer": "adexplorer",
	"godap":      "godap",
	// Cloud / CI/CD / GitHub-Actions attack + audit.
	"gato":        "gato",
	"purplepanda": "purplepanda",
	"kubescape":   "kubescape",
	"legitify":    "legitify",
	"poutine":     "poutine",
	"octoscan":    "octoscan",
	// OSINT.
	"osintgram":   "osintgram",
	"twint":       "twint",
	"instaloader": "instaloader",
	"socialscan":  "socialscan",
	// Recon / scanners / exploit search + screenshotters.
	"sifter":    "sifter",
	"pnscan":    "pnscan",
	"vajra":     "vajra",
	"getsploit": "getsploit",
	"fuzzuli":   "fuzzuli",
	"scrying":   "scrying",
	"witnessme": "witnessme",
	// Wordlist / credential generators.
	"cupp":             "cupp",
	"psudohash":        "psudohash",
	"username-anarchy": "username-anarchy",
	// DoS / flood / stress tools.
	"t50":          "t50",
	"hyenae":       "hyenae",
	"mhddos":       "mhddos",
	"bonesi":       "bonesi",
	"slowloris":    "slowloris",
	"slowhttptest": "slowhttptest",
	"goldeneye":    "goldeneye",
	"hulk":         "hulk",
	"torshammer":   "torshammer",
	"xerxes":       "xerxes",
	"pyloris":      "pyloris",
	"davoset":      "davoset",
	"saphyra":      "saphyra",

	// --- Batch: 25 more web-injection / WAF / OSINT-engine / recon
	// fingerprints (User-Agent self-identification). ---
	// SQL-injection + web-exploit + secret-file scanners.
	"wafninja":     "wafninja",
	"sqlninja":     "sqlninja",
	"bbqsql":       "bbqsql",
	"jsql":         "jsql",
	"snallygaster": "snallygaster",
	"yawast":       "yawast",
	// WAF / origin / web recon.
	"whatwaf":    "whatwaf",
	"identywaf":  "identywaf",
	"cloudflair": "cloudflair",
	"vhostscan":  "vhostscan",
	// Interception / MITM tooling.
	"cadaver":   "cadaver",
	"mitmproxy": "mitmproxy",
	"bettercap": "bettercap",
	// Internet-wide search-engine clients.
	"fofa":     "fofa",
	"zoomeye":  "zoomeye",
	"netlas":   "netlas",
	"fullhunt": "fullhunt",
	// OSINT / recon frameworks + dorking + DNS enum.
	"raccoon":    "raccoon",
	"sn0int":     "sn0int",
	"infoga":     "infoga",
	"metagoofil": "metagoofil",
	"pagodo":     "pagodo",
	"sudomy":     "sudomy",
	"dnsenum":    "dnsenum",
	"wpforce":    "wpforce",

	// --- Batch: 100 more offensive-tooling fingerprints (User-Agent
	// self-identification), spanning C2/RAT/loaders, web-/CMS-/API-/mobile-
	// vuln scanners, AD/Windows post-exploitation, cloud/k8s/IaC auditors,
	// and OSINT/recon. ---
	// C2 / RAT / loader families (-> "c2").
	"nighthawk":   "nighthawk",
	"nuages":      "nuages",
	"remcos":      "remcos",
	"dcrat":       "dcrat",
	"venomrat":    "venomrat",
	"xworm":       "xworm",
	"limerat":     "limerat",
	"revengerat":  "revengerat",
	"warzone":     "warzonerat",
	"netwire":     "netwire",
	"nanocore":    "nanocore",
	"orcus":       "orcus",
	"darkcomet":   "darkcomet",
	"spynote":     "spynote",
	"agenttesla":  "agenttesla",
	"formbook":    "formbook",
	"smokeloader": "smokeloader",
	"msfvenom":    "metasploit",
	// Web / CMS / API / mobile vulnerability + injection scanners (-> "vuln-scanner").
	"moodlescan":    "moodlescan",
	"cmsscan":       "cmsscan",
	"scant3r":       "scant3r",
	"403fuzzer":     "403fuzzer",
	"headerpwn":     "headerpwn",
	"smugglefuzz":   "smugglefuzz",
	"paramminer":    "param-miner",
	"spring4shell":  "spring4shell-scan",
	"fastjson-scan": "fastjson-scan",
	"shiroscan":     "shiro-scan",
	"wpintel":       "wpintel",
	"apkleaks":      "apkleaks",
	"mobsf":         "mobsf",
	"jwtcat":        "jwtcat",
	"ratproxy":      "ratproxy",
	"golismero":     "golismero",
	"wascan":        "wascan",
	"striker":       "striker",
	"yukichan":      "yuki-chan",
	"spaghetti":     "spaghetti",
	"taipan":        "taipan",
	"wpseku":        "wpseku",
	"plecost":       "plecost",
	"nettacker":     "nettacker",
	"blackwidow":    "blackwidow",
	"v3n0m":         "v3n0m",
	"wpgarlic":      "wpgarlic",
	"ssrfire":       "ssrfire",
	// Active Directory / Windows post-exploitation (-> "tool").
	"bofhound":        "bofhound",
	"adcspwn":         "adcspwn",
	"pkinittools":     "pkinittools",
	"gmsadumper":      "gmsadumper",
	"powerview":       "powerview",
	"powermad":        "powermad",
	"sharpgpoabuse":   "sharpgpoabuse",
	"sweetpotato":     "sweetpotato",
	"godpotato":       "godpotato",
	"juicypotato":     "juicypotato",
	"printspoofer":    "printspoofer",
	"roguepotato":     "roguepotato",
	"sharpdpapi":      "sharpdpapi",
	"sharpsccm":       "sharpsccm",
	"sccmhunter":      "sccmhunter",
	"group3r":         "group3r",
	"dploot":          "dploot",
	"hekatomb":        "hekatomb",
	"scshell":         "scshell",
	"atexec":          "atexec",
	"dcomexec":        "dcomexec",
	"rpcdump":         "rpcdump",
	"samrdump":        "samrdump",
	"lookupsid":       "lookupsid",
	"powerhuntshares": "powerhuntshares",
	"orpheus":         "orpheus",
	"krbjack":         "krbjack",
	"ldapper":         "ldapper",
	// Cloud / Kubernetes / IaC audit + attack (-> "tool").
	"checkov":     "checkov",
	"tfsec":       "tfsec",
	"kics":        "kics",
	"trivy":       "trivy",
	"grype":       "grype",
	"kube-bench":  "kube-bench",
	"kubeaudit":   "kubeaudit",
	"botb":        "botb",
	"cloudquery":  "cloudquery",
	"awspx":       "awspx",
	"cartography": "cartography",
	// OSINT / recon / breach + exfil tooling (-> "tool").
	"nrich":             "nrich",
	"mailcat":           "mailcat",
	"gitfive":           "gitfive",
	"zehef":             "zehef",
	"ignorant":          "ignorant",
	"waybackpy":         "waybackpy",
	"linkedin2username": "linkedin2username",
	"crosslinked":       "crosslinked",
	"emailfinder":       "emailfinder",
	"mosint":            "mosint",
	"spoofcheck":        "spoofcheck",
	"dnsdumpster":       "dnsdumpster",
	"subdomainizer":     "subdomainizer",
	"subdominator":      "subdominator",
	"egress-assess":     "egress-assess",

	// --- Batch: 50 more offensive-tooling fingerprints (User-Agent
	// self-identification), heavy on credential brute-force / stuffing /
	// password-spray tools (so the "top tools" view surfaces them), plus
	// banking-trojan/loader staging, web/API vuln scanners, and recon. ---
	// Banking-trojan / loader / RAT families (-> "c2").
	"emotet":      "emotet",
	"trickbot":    "trickbot",
	"qakbot":      "qakbot",
	"icedid":      "icedid",
	"bumblebee":   "bumblebee",
	"darkgate":    "darkgate",
	"pikabot":     "pikabot",
	"latrodectus": "latrodectus",
	// Credential brute-force / stuffing / password-spray (-> "tool").
	"openbullet":   "openbullet",
	"sentrymba":    "sentry-mba",
	"snipr":        "snipr",
	"silverbullet": "silverbullet",
	"blackbullet":  "blackbullet",
	"cr3dov3r":     "cr3dov3r",
	"credmaster":   "credmaster",
	"spray365":     "spray365",
	"msolspray":    "msolspray",
	"go365":        "go365",
	"ruler":        "ruler",
	"mailsniper":   "mailsniper",
	"fireprox":     "fireprox",
	"omnispray":    "omnispray",
	"smartbrute":   "smartbrute",
	"legba":        "legba",
	"cerbrutus":    "cerbrutus",
	// Web / API / injection vulnerability scanners (-> "vuln-scanner").
	"scan4all":          "scan4all",
	"dirmap":            "dirmap",
	"uniscan":           "uniscan",
	"webpwn3r":          "webpwn3r",
	"vulscan":           "vulscan",
	"jwtxploiter":       "jwtxploiter",
	"graphql-path-enum": "graphql-path-enum",
	"batchql":           "batchql",
	"dsss":              "dsss",
	"sqliv":             "sqliv",
	// Recon / endpoint-discovery / secret-scraper tooling (-> "tool").
	"jsfinder":     "jsfinder",
	"spyhunt":      "spyhunt",
	"reconcobra":   "reconcobra",
	"sitedorks":    "sitedorks",
	"tugarecon":    "tugarecon",
	"shhgit":       "shhgit",
	"gitrob":       "gitrob",
	"heritrix":     "heritrix",
	"nutch":        "nutch",
	"webcopilot":   "webcopilot",
	"urlhunter":    "urlhunter",
	"porch-pirate": "porch-pirate",
	"swaggerhole":  "swaggerhole",
	"apkhunt":      "apkhunt",
	"githound":     "githound",
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
// CobaltStrikeStager reports whether path matches Cobalt Strike's default
// checksum8 staging URI: a single 4-character [A-Za-z0-9] segment whose bytes
// sum (mod 256) to 92 (x86 stager) or 93 (x64 stager). This is the classic,
// malleable-profile-independent tell of a default CS team server staging a
// beacon. Returns the stager architecture ("x86"/"x64") and whether it matched.
// The checksum is byte-sensitive, so pass the original-case path.
func CobaltStrikeStager(path string) (arch string, ok bool) {
	p := strings.TrimPrefix(path, "/")
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i] // allow a query/fragment, but a trailing path segment must not
	}
	if len(p) != 4 {
		return "", false
	}
	sum := 0
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			sum += int(c)
		default:
			return "", false
		}
	}
	switch sum % 256 {
	case 92:
		return "x86", true
	case 93:
		return "x64", true
	}
	return "", false
}

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
	// Cobalt Strike default checksum8 staging URI — a profile-independent,
	// high-signal tell that a default CS team server is staging a beacon.
	// Computed over the ORIGINAL-case path (the checksum is byte-sensitive).
	if _, ok := CobaltStrikeStager(s.Path); ok {
		v.Tools = appendUnique(v.Tools, "cobaltstrike")
		uaMatched = true // treat as a strong (high-confidence) identification
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
	// Batch: 20 more SSH stacks/libraries that attack tooling rides on, plus
	// SSH-specific offensive tools, identified from the cleartext SSH-2.0
	// client banner. Embedded/IoT + scripting SSH stacks (dropbear powers many
	// IoT botnet implants; AsyncSSH/Net::SSH/SSHJ are the engines under Python/
	// Ruby/Java attack frameworks incl. Metasploit's ssh_login), purpose-built
	// SSH attack tools (sshamble, ssh-mitm), and clients abused in intrusions
	// (Xshell — backdoored in the ShadowPad supply-chain compromise).
	{"dropbear", "dropbear"},
	{"tinyssh", "tinyssh"},
	{"wolfssh", "wolfssh"},
	{"asyncssh", "asyncssh"},
	{"net::ssh", "ruby-net-ssh"},
	{"sshj", "sshj"},
	{"ganymed", "ganymed-ssh2"},
	{"granados", "granados"},
	{"flowssh", "flowssh"},
	{"cryptlib", "cryptlib"},
	{"ttssh", "teraterm"},
	{"ssh2js", "node-ssh2"},
	{"sshamble", "sshamble"},
	{"ssh-mitm", "ssh-mitm"},
	{"sshd-core", "apache-mina-sshd"},
	{"weonlydo", "weonlydo-ssh"},
	{"syncplify", "syncplify-ssh"},
	{"smartftp", "smartftp-ssh"},
	{"xshell", "xshell"},
	{"securecrt", "securecrt"},
	// Batch: 40 more SSH client/stack banners — SSH libraries across languages,
	// enterprise/MFT SSH servers & clients, PAM/zero-trust bastions (whose
	// proxy presents its own client banner to the backend), network-device SSH
	// stacks, and SSH-specific brute/recon attack tools. Substring-matched on
	// the cleartext SSH-2.0 identification string.
	{"j2ssh", "j2ssh"},
	{"chilkat", "chilkat-ssh"},
	{"ipworks", "ipworks-ssh"},
	{"tectia", "tectia-ssh"},
	{"f-secure", "f-secure-ssh"},
	{"pkix", "pkix-ssh"},
	{"-hpn", "hpn-ssh"},
	{"redssh", "redssh"},
	{"sharpssh", "sharpssh"},
	{"crushftp", "crushftp"},
	{"goanywhere", "goanywhere-ssh"},
	{"globalscape", "globalscape-ssh"},
	{"completeftp", "completeftp"},
	{"titanftp", "titanftp"},
	{"serv-u", "serv-u"},
	{"wingftp", "wingftp"},
	{"filezilla", "filezilla-ssh"},
	{"termius", "termius"},
	{"royalts", "royalts"},
	{"devolutions", "devolutions"},
	{"bitvise", "bitvise"},
	{"mobaxterm", "mobaxterm"},
	{"teleport", "teleport-ssh"},
	{"warpgate", "warpgate"},
	{"sshpiper", "sshpiper"},
	{"wallix", "wallix"},
	{"cyberark", "cyberark-ssh"},
	{"scaleft", "scaleft"},
	{"smallstep", "smallstep-ssh"},
	{"boundary", "boundary-ssh"},
	{"rosssh", "mikrotik-ssh"},
	{"cisco-", "cisco-ssh"},
	{"comware", "comware-ssh"},
	{"huawei", "huawei-ssh"},
	{"netscreen", "netscreen-ssh"},
	{"ncrack", "ncrack"},
	{"sshprank", "sshprank"},
	{"ssh-snake", "ssh-snake"},
	{"crassh", "crassh"},
	{"ssh-auditor", "ssh-auditor"},
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

type dnsToolSig struct{ needle, tool string }

// dnsToolSignatures fingerprints the tool / out-of-band-interaction service /
// tunnel behind a DNS query from the QNAME alone: BIND server-info recon
// probes (version.bind & friends), OOB-interaction callback domains that
// SSRF/RCE/log4shell exploits beacon to (Burp Collaborator, interactsh OAST,
// dnslog.cn, ceye.io, Canarytokens), public DNS-rebinding services, and
// DNS-tunnel/C2 tool markers. The QNAME is attacker-controlled, so this is a
// medium-confidence signal — the name reveals intent, not a crypto match.
var dnsToolSignatures = []dnsToolSig{
	// BIND / server-info recon (CHAOS-class lookups).
	{"version.bind", "fpdns"},
	{"version.server", "fpdns"},
	{"hostname.bind", "dns-recon-probe"},
	{"id.server", "dns-recon-probe"},
	{"authors.bind", "dns-recon-probe"},
	// Out-of-band interaction / SSRF-RCE callback services.
	{"burpcollaborator", "burp-collaborator"},
	{"oast.fun", "interactsh"},
	{"oast.site", "interactsh"},
	{"oast.online", "interactsh"},
	{"interact.sh", "interactsh"},
	{"dnslog.cn", "dnslog"},
	{"ceye.io", "ceye"},
	{"canarytokens.com", "canarytoken"},
	// Public DNS-rebinding services.
	{"nip.io", "dns-rebind-service"},
	{"sslip.io", "dns-rebind-service"},
	{"xip.io", "dns-rebind-service"},
	{"1u.ms", "dns-rebind-service"},
	// DNS tunneling / C2 tools.
	{"dnscat", "dnscat2"},
	{"dns2tcp", "dns2tcp"},
	{"tcpoverdns", "tcp-over-dns"},
}

// IdentifyDNS maps a DNS QNAME to known DNS recon / tunnel / OOB-interaction
// tools and services. Returns the matched tool names (empty when none).
func IdentifyDNS(qname string) []string {
	name := strings.ToLower(strings.TrimSpace(qname))
	if name == "" {
		return nil
	}
	var tools []string
	for _, s := range dnsToolSignatures {
		if strings.Contains(name, s.needle) {
			tools = appendUnique(tools, s.tool)
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
