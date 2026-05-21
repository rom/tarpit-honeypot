// Package cve is a small, in-source catalog of well-known CVEs that map
// to the services this honeypot emulates. It has two jobs:
//
//  1. Vulnerable-banner / fake-patch-level emulation: ForService lets a
//     handler (or archetype) decide which CVEs a service should *look*
//     vulnerable to, so a scanner fingerprinting versions sees a
//     believable unpatched box. The honeypot never becomes actually
//     exploitable — it only advertises the version and recognizes the
//     follow-up exploit attempt.
//
//  2. Exploit-attempt recognition: MatchPayload scans an attacker's
//     request bytes for the characteristic signature of a known
//     exploit (Log4Shell's ${jndi:, Shellshock's "() {", the Citrix
//     path-traversal, …) so the handler can emit a high-severity
//     cve:<id> event and harvest the payload.
//
// This is deliberately a curated, conservative list — high-signal
// exploit strings only, so MatchPayload has a near-zero false-positive
// rate on benign traffic.
package cve

import (
	"sort"
	"strings"
)

// Record describes one known CVE relevant to an emulated service.
type Record struct {
	ID   string  // e.g. "CVE-2021-44228"
	Name string  // e.g. "Log4Shell"
	CVSS float64 // base score
	// Service is the handler name this CVE applies to ("http", "smb",
	// "https", "fortinet", …). "http" records also match https.
	Service string
	// Signatures are substrings whose presence in an attacker's request
	// payload indicates an attempt to exploit this CVE. Matched
	// case-insensitively; normalized to lowercase once at package init.
	// High-signal only.
	Signatures []string
	// Technique is the ATT&CK technique the exploit attempt maps to.
	Technique string
	// Tactic is the ATT&CK tactic (usually initial-access / execution).
	Tactic      string
	Description string
}

// catalog is the curated CVE list. Signatures are matched lowercase.
var catalog = []Record{
	{
		ID: "CVE-2021-44228", Name: "Log4Shell", CVSS: 10.0, Service: "http",
		Signatures: []string{"${jndi:", "${jndi:ldap", "${jndi:rmi", "${jndi:dns", "${${::-j}", "${lower:jndi"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Apache Log4j2 JNDI lookup remote code execution.",
	},
	{
		ID: "CVE-2014-6271", Name: "Shellshock", CVSS: 9.8, Service: "http",
		Signatures: []string{"() {", "() { :;};", "() { :; };"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "GNU Bash environment-variable function-definition RCE via CGI.",
	},
	{
		ID: "CVE-2017-5638", Name: "Struts2 OGNL", CVSS: 10.0, Service: "http",
		Signatures: []string{"%{(#_='multipart/form-data')", "#context['com.opensymphony", "ognl.OgnlContext"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Apache Struts2 Content-Type OGNL injection RCE.",
	},
	{
		ID: "CVE-2022-22965", Name: "Spring4Shell", CVSS: 9.8, Service: "http",
		Signatures: []string{"class.module.classloader", "class.module.classLoader"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Spring Framework class.module.classLoader data-binding RCE.",
	},
	{
		ID: "CVE-2022-26134", Name: "Confluence OGNL", CVSS: 9.8, Service: "http",
		Signatures: []string{"${@java.lang.runtime", "@java.lang.runtime@getruntime().exec"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Atlassian Confluence OGNL injection RCE.",
	},
	{
		ID: "CVE-2021-26855", Name: "ProxyLogon", CVSS: 9.8, Service: "http",
		Signatures: []string{"/owa/auth/x.js", "x-anonresource", "x-beresource", "/ecp/default.flt"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Microsoft Exchange SSRF authentication bypass (ProxyLogon).",
	},
	{
		ID: "CVE-2019-19781", Name: "Citrix ADC path traversal", CVSS: 9.8, Service: "citrix_gateway",
		Signatures: []string{"/vpn/../vpns/", "/vpns/cfg/smb.conf", "/vpns/portal/scripts/newbm.pl"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Citrix ADC/Gateway directory traversal to RCE.",
	},
	{
		ID: "CVE-2018-13379", Name: "FortiOS path traversal", CVSS: 9.8, Service: "fortinet",
		Signatures: []string{"/remote/fgt_lang?lang=/../", "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Fortinet FortiOS SSL VPN path traversal credential disclosure.",
	},
	{
		ID: "CVE-2019-11510", Name: "Pulse Secure file read", CVSS: 10.0, Service: "pulse",
		Signatures: []string{"/dana-na/../dana/html5acc/guacamole/", "/dana-na/../dana/html5acc/", "/+cscou+/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Pulse Connect Secure arbitrary file read.",
	},
	{
		ID: "CVE-2020-5902", Name: "F5 BIG-IP TMUI", CVSS: 9.8, Service: "http",
		Signatures: []string{"/tmui/login.jsp/..;/", "/tmui/locallb/workspace/tmshcmd.jsp", "..;/tmui/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "F5 BIG-IP TMUI authentication bypass RCE.",
	},
	{
		ID: "CVE-2018-7600", Name: "Drupalgeddon2", CVSS: 9.8, Service: "http",
		Signatures: []string{"#post_render", "/?q=user/password&name[%23", "name[#post_render]"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Drupal form-API render-array RCE.",
	},
	{
		ID: "CVE-2017-0144", Name: "EternalBlue", CVSS: 8.1, Service: "smb",
		// The "\PIPE\" tree-connect path appears as ASCII in the SMB1
		// request the EternalBlue toolchain sends; matched by the smb
		// handler against the captured request bytes.
		Signatures: []string{"\\pipe\\", "\\pipe\\srvsvc"},
		Technique:  "T1210", Tactic: "lateral-movement",
		Description: "Microsoft SMBv1 remote code execution (MS17-010).",
	},
	{
		ID: "CVE-2019-0708", Name: "BlueKeep", CVSS: 9.8, Service: "rdp",
		// The rogue "MS_T120" virtual-channel name appears as ASCII in
		// the RDP MCS Connect-Initial PDU the exploit sends; matched by
		// the rdp handler against the captured request bytes.
		Signatures: []string{"ms_t120"},
		Technique:  "T1210", Tactic: "lateral-movement",
		Description: "Microsoft RDP pre-auth use-after-free RCE.",
	},
	{
		ID: "CVE-2021-34473", Name: "ProxyShell", CVSS: 9.8, Service: "http",
		Signatures: []string{"/autodiscover/autodiscover.json", "powershell-liveid", "/mapi/nspi/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Microsoft Exchange ProxyShell pre-auth RCE chain.",
	},
	{
		ID: "CVE-2021-41773", Name: "Apache path traversal", CVSS: 9.8, Service: "http",
		Signatures: []string{"/cgi-bin/.%2e/", "/icons/.%2e/%2e%2e/", "%2e%2e/%2e%2e/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Apache HTTP Server 2.4.49 path traversal / RCE.",
	},
	{
		ID: "CVE-2017-9841", Name: "PHPUnit eval-stdin", CVSS: 9.8, Service: "http",
		Signatures: []string{"/vendor/phpunit/phpunit/src/util/php/eval-stdin.php", "eval-stdin.php"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "PHPUnit eval-stdin.php remote code execution.",
	},
	{
		ID: "CVE-2023-46604", Name: "ActiveMQ OpenWire RCE", CVSS: 10.0, Service: "http",
		Signatures: []string{"classpathxmlapplicationcontext", "spring/spring-context"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Apache ActiveMQ OpenWire deserialization RCE.",
	},
	{
		ID: "CVE-2022-1388", Name: "F5 iControl REST", CVSS: 9.8, Service: "http",
		Signatures: []string{"/mgmt/tm/util/bash", "x-f5-auth-token"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "F5 BIG-IP iControl REST authentication bypass RCE.",
	},
	{
		ID: "CVE-2024-3400", Name: "PAN-OS GlobalProtect", CVSS: 10.0, Service: "https",
		Signatures: []string{"/ssl-vpn/hipreport.esp", "sessionid=../../../"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Palo Alto PAN-OS GlobalProtect command injection.",
	},
	{
		ID: "CVE-2017-10271", Name: "WebLogic WLS-WSAT", CVSS: 7.5, Service: "http",
		Signatures: []string{"/wls-wsat/coordinatorporttype", "/wls-wsat/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Oracle WebLogic WLS-WSAT XML deserialization RCE.",
	},
	{
		ID: "CVE-2020-14882", Name: "WebLogic console RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/console/css/%252e%252e%252fconsole.portal", "com.tangosol.coherence.mvel2"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Oracle WebLogic console unauthenticated RCE.",
	},
	{
		ID: "CVE-2019-18935", Name: "Telerik UI deserialization", CVSS: 9.8, Service: "http",
		Signatures: []string{"telerik.web.ui.webresource.axd?type=rau", "dialogparametersholder"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Progress Telerik UI for ASP.NET AJAX insecure deserialization RCE.",
	},
	{
		ID: "CVE-2021-3129", Name: "Laravel Ignition RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/_ignition/execute-solution", "makeviewvariableoptionalsolution"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Laravel Ignition (debug mode) file-write to RCE.",
	},
	{
		ID: "CVE-2021-26084", Name: "Confluence OGNL injection", CVSS: 9.8, Service: "http",
		Signatures: []string{"createpage-entervariables.action", "/pages/doenterpagevariables.action"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Atlassian Confluence Webwork OGNL injection RCE.",
	},
	{
		ID: "CVE-2017-12615", Name: "Tomcat PUT JSP", CVSS: 8.1, Service: "http",
		Signatures: []string{".jsp::$data", ".jsp%20"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Apache Tomcat PUT-based JSP upload RCE.",
	},
	{
		ID: "CVE-2021-42013", Name: "Apache 2.4.50 traversal", CVSS: 9.8, Service: "http",
		Signatures: []string{"/cgi-bin/.%%32%65", ".%%32%65%%32%65/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Apache HTTP Server 2.4.50 path traversal / RCE (CVE-2021-41773 bypass).",
	},
	{
		ID: "CVE-2023-34362", Name: "MOVEit Transfer SQLi", CVSS: 9.8, Service: "http",
		Signatures: []string{"/moveitisapi/moveitisapi.dll", "x-silock-comment", "/guestaccess.aspx"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Progress MOVEit Transfer SQL injection to RCE.",
	},
	{
		ID: "CVE-2022-30190", Name: "Follina MSDT", CVSS: 7.8, Service: "http",
		Signatures: []string{"ms-msdt:", "!exec/../"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Microsoft Support Diagnostic Tool (MSDT) URL-protocol RCE.",
	},
	{
		ID: "CVE-2021-21972", Name: "vSphere Client RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/ui/vropspluginui/rest/services/uploadova", "/ui/vropspluginui/rest/services/getstatus"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "VMware vCenter vSphere Client (vROps plugin) unauthenticated RCE.",
	},
	{
		ID: "CVE-2024-3273", Name: "D-Link NAS RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/cgi-bin/nas_sharing.cgi"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "D-Link NAS nas_sharing.cgi backdoor + command injection.",
	},
	{
		ID: "CVE-2018-10561", Name: "GPON router auth bypass", CVSS: 9.8, Service: "http",
		Signatures: []string{"/gponform/diag_form", "?images/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Dasan GPON home router authentication bypass + command injection.",
	},
	{
		ID: "CVE-2017-7921", Name: "Hikvision auth bypass", CVSS: 10.0, Service: "http",
		Signatures: []string{"/system/deviceinfo?auth=", "/security/users?auth=", "/onvif-http/snapshot?auth="},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Hikvision IP camera improper authentication (backdoor) info disclosure.",
	},
	{
		ID: "CVE-2022-40684", Name: "FortiOS auth bypass", CVSS: 9.8, Service: "fortinet",
		Signatures: []string{"/api/v2/cmdb/system/admin", "/api/v2/cmdb/system/api-user"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Fortinet FortiOS/FortiProxy administrative-interface auth bypass.",
	},
	// Advisory-only records (no payload signature — timing/version or
	// non-HTTP protocol). They give vuln_emulation advisories + cve:<id>
	// events an ATT&CK mapping via Lookup.
	{
		ID: "CVE-2018-15473", Name: "OpenSSH user enumeration", CVSS: 5.3, Service: "ssh",
		Technique: "T1087", Tactic: "discovery",
		Description: "OpenSSH pre-auth username enumeration via timing/response differences.",
	},
	{
		ID: "CVE-2018-0171", Name: "Cisco Smart Install", CVSS: 9.8, Service: "cisco",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Cisco IOS Smart Install (port 4786) unauthenticated config/RCE.",
	},
	// More web exploit signatures.
	{
		ID: "CVE-2023-22518", Name: "Confluence setup-restore", CVSS: 9.8, Service: "http",
		Signatures: []string{"/json/setup-restore.action", "/json/setup-restore-local.action"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Atlassian Confluence improper-authorization data-destruction / takeover.",
	},
	{
		ID: "CVE-2023-20198", Name: "Cisco IOS-XE Web UI", CVSS: 10.0, Service: "http",
		Signatures: []string{"/webui/logoutconfirm.html?logon_hash=", "/%2577ebui_wsma_http"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Cisco IOS-XE web UI privilege escalation / implant install.",
	},
	{
		ID: "CVE-2024-4577", Name: "PHP-CGI argument injection", CVSS: 9.8, Service: "http",
		Signatures: []string{"/php-cgi/php-cgi.exe", "%add+allow_url_include", "auto_prepend_file%3dphp"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "PHP-CGI on Windows argument injection (Best-Fit encoding) RCE.",
	},
	{
		ID: "CVE-2023-42793", Name: "JetBrains TeamCity auth bypass", CVSS: 9.8, Service: "http",
		Signatures: []string{"/app/rest/users/id:1/tokens/", "/app/rest/debug/processes"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "JetBrains TeamCity authentication bypass to RCE.",
	},
	{
		ID: "CVE-2021-40539", Name: "ManageEngine ADSelfService", CVSS: 9.8, Service: "http",
		Signatures: []string{"/restapi/logoncustomization", "/help/admin-guide/generalsettings/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Zoho ManageEngine ADSelfService Plus REST API auth bypass RCE.",
	},
	{
		ID: "CVE-2024-21887", Name: "Ivanti Connect Secure", CVSS: 9.1, Service: "pulse",
		Signatures: []string{"/api/v1/totp/user-backup-code/", "/api/v1/license/keys-status/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Ivanti Connect Secure command injection (chained with auth bypass).",
	},
	// ICS advisory records (control-protocol exploits, no HTTP signature) —
	// give the cve:<id> events + vuln_emulation advisories an ATT&CK mapping.
	{
		ID: "CVE-2020-15782", Name: "Siemens S7-1200/1500 memory bypass", CVSS: 8.1, Service: "s7",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Siemens SIMATIC S7-1200/1500 protection-mechanism bypass / memory R-W.",
	},
	{
		ID: "CVE-2023-3595", Name: "Rockwell 1756-EN2T RCE", CVSS: 9.8, Service: "ethernetip",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Rockwell ControlLogix 1756-EN* CIP out-of-bounds write RCE / DoS.",
	},
	{
		ID: "CVE-2021-22681", Name: "Rockwell Studio 5000 key", CVSS: 10.0, Service: "ethernetip",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Rockwell Logix controllers hardcoded key — unauthenticated control.",
	},
	{
		ID: "CVE-2022-1161", Name: "Rockwell Logix hidden code", CVSS: 10.0, Service: "ethernetip",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Rockwell Logix controllers — boot-code injection of hidden program.",
	},
	// CUPS / IPP printing chain (Sept 2024). foomatic-rip is the RCE
	// primitive: a crafted PPD's FoomaticRIPCommandLine runs an arbitrary
	// shell command when a job prints. Detectable over IPP (TCP 631).
	{
		ID: "CVE-2024-47177", Name: "CUPS foomatic-rip RCE", CVSS: 9.0, Service: "ipp",
		Signatures: []string{"foomaticripcommandline"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "cups-filters foomatic-rip arbitrary command execution via FoomaticRIPCommandLine.",
	},
	// The remaining three links advertise the unpatched chain (advisory-
	// only — no single TCP-side exploit string).
	{
		ID: "CVE-2024-47176", Name: "cups-browsed SSRF/bind", CVSS: 8.6, Service: "ipp",
		Technique: "T1190", Tactic: "initial-access",
		Description: "cups-browsed binds 0.0.0.0:631 and trusts Get-Printer-Attributes from any source.",
	},
	{
		ID: "CVE-2024-47076", Name: "libcupsfilters no-validate", CVSS: 8.6, Service: "ipp",
		Technique: "T1190", Tactic: "initial-access",
		Description: "libcupsfilters cfGetPrinterAttributes returns attacker IPP data unvalidated.",
	},
	{
		ID: "CVE-2024-47175", Name: "libppd PPD injection", CVSS: 8.6, Service: "ipp",
		Technique: "T1190", Tactic: "initial-access",
		Description: "libppd ppdCreatePPDFromIPP2 writes attacker IPP attributes into a PPD unescaped.",
	},
	// Printer / MFP web-UI (EWS) advisories — advertised by the printer
	// archetypes so a version scanner records an unpatched device.
	{
		ID: "CVE-2024-12510", Name: "Xerox VersaLink pass-back", CVSS: 6.7, Service: "http",
		Technique: "T1212", Tactic: "credential-access",
		Description: "Xerox VersaLink LDAP/SMB pass-back — config change redirects auth to capture creds.",
	},
	{
		ID: "CVE-2023-26067", Name: "Lexmark privilege escalation", CVSS: 8.0, Service: "http",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Lexmark devices improper input validation in the EWS leading to privilege escalation.",
	},
	{
		ID: "CVE-2022-1026", Name: "Kyocera data disclosure", CVSS: 7.1, Service: "http",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Kyocera Net Manager / device path traversal exposing stored credentials.",
	},
}

// init normalizes every catalog signature to lowercase once, so
// MatchPayload (called on every request) only lowercases the payload.
func init() {
	for i := range catalog {
		for j, s := range catalog[i].Signatures {
			catalog[i].Signatures[j] = strings.ToLower(s)
		}
	}
}

// MatchPayload returns the catalog records whose exploit signature
// appears in payload for the given handler. handler "https" also matches
// "http"-service records (HTTP-layer exploits arrive over TLS too).
func MatchPayload(handler, payload string) []Record {
	if payload == "" {
		return nil
	}
	low := strings.ToLower(payload)
	var out []Record
	for _, r := range catalog {
		if !serviceMatches(r.Service, handler) {
			continue
		}
		for _, sig := range r.Signatures { // sigs are already lowercase
			if strings.Contains(low, sig) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// ForService returns every catalogued CVE for a handler (used to drive
// fake-vulnerable-banner / patch-level advisories). handler "https"
// includes "http" records.
func ForService(handler string) []Record {
	var out []Record
	for _, r := range catalog {
		if serviceMatches(r.Service, handler) {
			out = append(out, r)
		}
	}
	return out
}

// All returns a copy of the full CVE catalog sorted by id. Records with
// no Signatures are advisory-only (banner / patch-level emulation); the
// rest are also recognized as live exploit attempts by MatchPayload.
// Used by `tarpit-honeypot list-cves`.
func All() []Record {
	out := append([]Record(nil), catalog...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Detectable reports whether a record carries exploit signatures (so
// MatchPayload can flag a live attempt) versus being advisory-only.
func (r Record) Detectable() bool { return len(r.Signatures) > 0 }

// Lookup returns the record for an exact CVE id.
func Lookup(id string) (Record, bool) {
	for _, r := range catalog {
		if r.ID == id {
			return r, true
		}
	}
	return Record{}, false
}

// serviceMatches reports whether a catalog record for recordService
// applies to a listener running handler.
func serviceMatches(recordService, handler string) bool {
	if recordService == handler {
		return true
	}
	// HTTP-layer CVEs apply over TLS too.
	if recordService == "http" && handler == "https" {
		return true
	}
	return false
}
