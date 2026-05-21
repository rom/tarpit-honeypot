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
	// Reason is a short human-readable explanation of the verdict.
	Reason string
}

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

	// Exploitation frameworks / webshell managers.
	"metasploit":   "metasploit",
	"core impact":  "core-impact",
	"cobaltstrike": "cobaltstrike",
	"antsword":     "antsword",
	"behinder":     "behinder",
	"godzilla":     "godzilla",

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

	for needle, tool := range uaSignatures {
		if strings.Contains(ua, needle) {
			v.Tools = appendUnique(v.Tools, tool)
		}
	}
	for needle, tool := range pathSignatures {
		if strings.Contains(path, needle) {
			v.Tools = appendUnique(v.Tools, tool)
		}
	}

	// Automation heuristic.
	switch {
	case len(v.Tools) > 0:
		v.Automation = true
		v.Reason = "matched tool signature"
	case s.UserAgent == "":
		// A browser always sends a User-Agent; its absence on an HTTP/1.1
		// request is a strong automation signal.
		v.Automation = true
		v.Reason = "no User-Agent header"
	case !looksLikeBrowserUA(ua):
		v.Automation = true
		v.Reason = "non-browser User-Agent"
	case !hasBrowserHeaderSet(s.HeaderKeys):
		// A real browser sends Accept / Accept-Language / Accept-Encoding;
		// scripts impersonating a browser UA usually omit them.
		v.Automation = true
		v.Reason = "browser UA but missing Accept-* headers"
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
