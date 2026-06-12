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

	// The following are curated cross-references, merged from cveExtra at
	// package init (see attribution docs):
	//   CWE  – the weakness class(es), e.g. ["CWE-502"] for unsafe deser.
	//   CPE  – the affected-product CPE 2.3 (vendor:product), wildcarded.
	//   EPSS – Exploit-Prediction Scoring System probability (0..1), a
	//          point-in-time snapshot used as a relative-priority hint.
	CWE  []string
	CPE  string
	EPSS float64
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
		// Advisory-only (no substring signatures — OT payloads are binary). The
		// modbus handler attributes this directly when it sees UMAS (FC 0x5A).
		ID: "CVE-2018-7842", Name: "Schneider Modicon UMAS auth bypass", CVSS: 9.8, Service: "modbus",
		Technique: "T0855", Tactic: "impact",
		Description: "Schneider Electric Modicon M340/M580 UMAS reservation/auth bypass.",
	},
	{
		ID: "CVE-2018-12613", Name: "phpMyAdmin LFI", CVSS: 8.8, Service: "http",
		Signatures: []string{"target=db_sql.php%253f", "?target=sql.php%3f", "db_datadict.php%253f"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "phpMyAdmin 4.8.x local file inclusion via the target parameter.",
	},
	{
		ID: "CVE-2009-1151", Name: "phpMyAdmin setup RCE", CVSS: 8.8, Service: "http",
		Signatures: []string{"/scripts/setup.php", "/setup/index.php"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "phpMyAdmin setup-script PHP code injection via crafted POST.",
	},
	{
		ID: "CVE-2018-20062", Name: "ThinkPHP RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"invokefunction&function=call_user_func_array", "\\think\\app/invokefunction", "s=/index/\\think"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "ThinkPHP 5.x request-routing remote code execution.",
	},
	{
		ID: "CVE-2019-11043", Name: "PHP-FPM RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/php-fpm%0a", "index.php%0a", "PHP_VALUE%0a"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "PHP-FPM + nginx underflow remote code execution (env_path_info).",
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
	// Active Directory / Windows server advisories (advertised by the
	// domain-controller archetype). ZeroLogon is the Netlogon auth bypass;
	// PrintNightmare is the Print Spooler RCE; noPac is sAMAccountName
	// spoofing to Domain Admin.
	{
		ID: "CVE-2020-1472", Name: "ZeroLogon", CVSS: 10.0, Service: "dcerpc",
		Technique: "T1210", Tactic: "lateral-movement",
		Description: "Netlogon (MS-NRPC) cryptographic flaw — unauthenticated DC takeover.",
	},
	{
		ID: "CVE-2021-34527", Name: "PrintNightmare", CVSS: 8.8, Service: "dcerpc",
		Technique: "T1210", Tactic: "lateral-movement",
		Description: "Windows Print Spooler (MS-RPRN) remote code execution.",
	},
	{
		ID: "CVE-2021-42278", Name: "noPac (sAMAccountName spoofing)", CVSS: 8.8, Service: "kerberos",
		Technique: "T1558", Tactic: "credential-access",
		Description: "AD sAMAccountName spoofing chained with CVE-2021-42287 for Domain Admin.",
	},
	// ---- Additional detectable web / appliance exploit signatures ----
	// Edge-device & enterprise-app pre-auth chains scanned en masse. Each
	// signature is a distinctive request-path or payload token from the
	// public PoC, kept high-signal so MatchPayload stays near-zero on
	// benign traffic.
	{
		ID: "CVE-2023-35078", Name: "Ivanti EPMM API auth bypass", CVSS: 9.8, Service: "http",
		Signatures: []string{"/mifs/aad/api/v2/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Ivanti Endpoint Manager Mobile (MobileIron Core) unauthenticated API access.",
	},
	{
		ID: "CVE-2023-38035", Name: "Ivanti Sentry MICS auth bypass", CVSS: 9.8, Service: "http",
		Signatures: []string{"/mics/services/configservice"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Ivanti Sentry MICS administrative interface authentication bypass to RCE.",
	},
	{
		ID: "CVE-2024-1709", Name: "ScreenConnect auth bypass", CVSS: 10.0, Service: "http",
		Signatures: []string{"/setupwizard.aspx/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "ConnectWise ScreenConnect path-confusion authentication bypass (admin takeover).",
	},
	{
		ID: "CVE-2023-22515", Name: "Confluence broken access control", CVSS: 10.0, Service: "http",
		Signatures: []string{"/setup/setupadministrator.action"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Atlassian Confluence broken access control — create admin / takeover.",
	},
	{
		ID: "CVE-2024-23897", Name: "Jenkins CLI arbitrary file read", CVSS: 9.8, Service: "http",
		Signatures: []string{"/cli?remoting=false", "@/etc/passwd", "connectnode @"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Jenkins CLI args4j expandAtFiles arbitrary file read (to RCE).",
	},
	{
		ID: "CVE-2024-27198", Name: "JetBrains TeamCity auth bypass", CVSS: 9.8, Service: "http",
		Signatures: []string{";.jsp?jsp=/app/rest"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "JetBrains TeamCity request-routing authentication bypass (admin token / RCE).",
	},
	{
		ID: "CVE-2022-22954", Name: "VMware Workspace ONE SSTI", CVSS: 9.8, Service: "http",
		Signatures: []string{"/catalog-portal/ui/oauth/verify"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "VMware Workspace ONE Access server-side template injection RCE.",
	},
	{
		ID: "CVE-2021-21985", Name: "vCenter vSAN H5 RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/ui/h5-vsan/rest/proxy/service/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "VMware vCenter Server vSAN Health (H5) plugin unauthenticated RCE.",
	},
	{
		ID: "CVE-2019-2725", Name: "WebLogic async deserialization", CVSS: 9.8, Service: "http",
		Signatures: []string{"/_async/asyncresponseservice"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Oracle WebLogic Server async/WLS9 XML deserialization RCE.",
	},
	{
		ID: "CVE-2023-46747", Name: "F5 BIG-IP TMUI SSRF RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/tmui/login.jsp/..;/mgmt/tm/util/bash", "/tmui/login.jsp/..;/mgmt/shared/authn/login"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "F5 BIG-IP TMUI AJP request-smuggling SSRF authentication bypass to RCE.",
	},
	{
		ID: "CVE-2021-22005", Name: "vCenter analytics file upload", CVSS: 9.8, Service: "http",
		Signatures: []string{"/analytics/telemetry/ph/api/hyper/send"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "VMware vCenter Server analytics service arbitrary file upload to RCE.",
	},
	{
		ID: "CVE-2020-3452", Name: "Cisco ASA/FTD WebVPN file read", CVSS: 7.5, Service: "http",
		Signatures: []string{"/+cscoe+/files/file_list.json?path="},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Cisco ASA/FTD WebVPN directory traversal unauthenticated file read.",
	},
	{
		ID: "CVE-2022-29464", Name: "WSO2 arbitrary file upload RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/fileupload/toolsany"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "WSO2 Carbon (API Manager / Identity Server) unrestricted file upload RCE.",
	},
	{
		ID: "CVE-2021-35587", Name: "Oracle Access Manager deserialization", CVSS: 9.8, Service: "http",
		Signatures: []string{"/oam/server/opensso/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Oracle Access Manager OpenSSO agent unauthenticated deserialization RCE.",
	},
	{
		ID: "CVE-2024-21893", Name: "Ivanti Connect Secure SSRF", CVSS: 8.2, Service: "pulse",
		Signatures: []string{"/dana-ws/saml20.ws"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Ivanti Connect Secure SAML component SSRF (chained to unauth RCE).",
	},
	{
		ID: "CVE-2023-3519", Name: "Citrix NetScaler RCE", CVSS: 9.8, Service: "citrix_gateway",
		Signatures: []string{"/gwtest/formssso?event=start&target="},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Citrix NetScaler ADC/Gateway unauthenticated stack-overflow RCE.",
	},
	{
		ID: "CVE-2022-27925", Name: "Zimbra mboximport traversal", CVSS: 7.2, Service: "http",
		Signatures: []string{"/service/extension/backup/mboximport"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Zimbra Collaboration mboximport ZIP path traversal to webshell RCE.",
	},
	{
		ID: "CVE-2023-27350", Name: "PaperCut auth bypass RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/app?service=page/setupcompleted"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "PaperCut MF/NG SetupCompleted authentication bypass to scripted RCE.",
	},
	{
		ID: "CVE-2024-0204", Name: "GoAnywhere MFT auth bypass", CVSS: 9.8, Service: "http",
		Signatures: []string{"/initialaccountsetup.xhtml"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Fortra GoAnywhere MFT admin-portal forced-browsing authentication bypass.",
	},
	{
		ID: "CVE-2023-0669", Name: "GoAnywhere MFT pre-auth RCE", CVSS: 7.2, Service: "http",
		Signatures: []string{"/goanywhere/lic/accept"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Fortra GoAnywhere MFT license-response servlet deserialization RCE.",
	},
	{
		ID: "CVE-2018-11776", Name: "Struts2 namespace OGNL (S2-057)", CVSS: 8.1, Service: "http",
		Signatures: []string{"(#_memberaccess"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Apache Struts2 namespace/results OGNL injection RCE (S2-057).",
	},
	{
		ID: "CVE-2017-12149", Name: "JBoss invoker deserialization", CVSS: 9.8, Service: "http",
		Signatures: []string{"/invoker/jmxinvokerservlet", "/invoker/readonly"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "RedHat JBoss AS/EAP HTTPInvoker ReadOnlyAccessFilter Java deserialization RCE.",
	},
	{
		ID: "CVE-2021-29441", Name: "Alibaba Nacos auth bypass", CVSS: 9.8, Service: "http",
		Signatures: []string{"/nacos/v1/auth/users?page"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Alibaba Nacos User-Agent authentication bypass — add admin / config theft.",
	},
	{
		ID: "CVE-2022-44877", Name: "CWP Control Web Panel RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/login/index.php?login=$(", "/login/index.php?login=%24%28"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Control Web Panel (CWP) login parameter unauthenticated command injection.",
	},
	{
		ID: "CVE-2015-1427", Name: "Elasticsearch Groovy RCE", CVSS: 9.8, Service: "elasticsearch",
		Signatures: []string{"java.lang.math.class.forname", "\"lang\":\"groovy\""},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Elasticsearch Groovy scripting-engine sandbox escape remote code execution.",
	},
	{
		ID: "CVE-2014-3120", Name: "Elasticsearch MVEL RCE", CVSS: 7.5, Service: "elasticsearch",
		Signatures: []string{"mvel", "\"script\":\"import "},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Elasticsearch default dynamic MVEL scripting remote code execution.",
	},
	// ---- Web app / appliance CVEs (2024–2025), detectable by request shape ----
	{
		ID: "CVE-2024-51378", Name: "CyberPanel getresetstatus RCE", CVSS: 10.0, Service: "http",
		Signatures: []string{"/dataBases/upgrademysqlstatus", "/ftp/getresetstatus", "/dns/getresetstatus"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "CyberPanel pre-auth command injection via the *getresetstatus endpoints (statusfile) — mass-exploited by PSAUX ransomware.",
	},
	{
		ID: "CVE-2024-57727", Name: "SimpleHelp path traversal", CVSS: 7.5, Service: "http",
		Signatures: []string{"/toolbox-resource/", "..%2f..%2f..%2f..%2fprogramdata"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "SimpleHelp remote support unauthenticated path traversal — arbitrary file read (server config / credentials).",
	},
	{
		ID: "CVE-2024-32113", Name: "Apache OFBiz path traversal RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/webtools/control/main/programexport", "/programexport;/", "viewjavascript;/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Apache OFBiz path traversal to the ProgramExport screen — Groovy RCE via a view-handler override.",
	},
	{
		ID: "CVE-2024-38475", Name: "Apache mod_rewrite path traversal", CVSS: 9.1, Service: "http",
		Signatures: []string{"/cgi-bin/%2e%2e%2f", "/legacyendpoint/%2f%2f", "%3f/etc/passwd"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Apache HTTP Server mod_rewrite output normalization flaw — substitution escapes the doc root (source disclosure / RCE depending on config).",
	},
	{
		ID: "CVE-2024-5806", Name: "MOVEit Transfer SFTP auth bypass", CVSS: 9.1, Service: "http",
		Signatures: []string{"/api/v1/folders", "guestaccess.aspx", "/machine2.aspx"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Progress MOVEit Transfer SFTP module improper authentication — impersonation / auth bypass.",
	},
	{
		ID: "CVE-2024-20439", Name: "Cisco Smart Licensing static cred", CVSS: 9.8, Service: "http",
		Signatures: []string{"/cslu/v1/scheduler/jobs", "/cslu/v1/files"},
		Technique:  "T1078", Tactic: "initial-access",
		Description: "Cisco Smart Licensing Utility undocumented static administrative credential — full API access.",
	},
	{
		ID: "CVE-2024-11680", Name: "ProjectSend auth bypass", CVSS: 9.8, Service: "http",
		Signatures: []string{"options.php?action=add_user", "/? section=options", "default_options.php"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "ProjectSend improper authorization (options.php) — set config, create accounts, upload webshells.",
	},
	{
		ID: "CVE-2025-49144", Name: "Notepad++ installer privilege escalation", CVSS: 7.3, Service: "http",
		Signatures: nil,
		Technique:  "T1574", Tactic: "privilege-escalation",
		Description: "Notepad++ v8.8.1 installer uncontrolled executable search path — local privilege escalation (advisory).",
	},

	// ---- Additional advisory-only records (binary/version/non-HTTP) ----
	{
		ID: "CVE-2024-50623", Name: "Cleo Harmony/VLTrader unrestricted upload", CVSS: 9.8, Service: "http",
		Signatures: nil, // exploited via the Autorun/Synchronization path; advisory to avoid FPs
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Cleo Harmony / VLTrader / LexiCom unrestricted file upload+download → RCE (Cl0p mass exploitation). Advisory-only.",
	},
	{
		ID: "CVE-2024-12356", Name: "BeyondTrust PRA/RS command injection", CVSS: 9.8, Service: "http",
		Signatures: nil,
		Technique:  "T1190", Tactic: "initial-access",
		Description: "BeyondTrust Privileged Remote Access / Remote Support unauthenticated command injection. Advisory-only.",
	},
	// No single TCP-side exploit string (heap overflows, NTLM relay, version
	// gates); these advertise the unpatched product + give cve:<id> events
	// and vuln_emulation advisories an ATT&CK mapping via Lookup.
	{
		ID: "CVE-2023-4966", Name: "Citrix Bleed", CVSS: 9.4, Service: "citrix_gateway",
		Technique: "T1539", Tactic: "credential-access",
		Description: "Citrix NetScaler ADC/Gateway session-token memory disclosure (CitrixBleed).",
	},
	{
		ID: "CVE-2024-55591", Name: "FortiOS auth bypass", CVSS: 9.8, Service: "fortinet",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Fortinet FortiOS/FortiProxy Node.js websocket authentication bypass to super-admin.",
	},
	{
		ID: "CVE-2022-42475", Name: "FortiOS SSL-VPN heap overflow", CVSS: 9.8, Service: "fortinet",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Fortinet FortiOS SSL-VPN pre-auth heap buffer overflow remote code execution.",
	},
	{
		ID: "CVE-2023-27997", Name: "FortiOS XORtigate", CVSS: 9.8, Service: "fortinet",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Fortinet FortiOS SSL-VPN pre-auth heap overflow (XORtigate) remote code execution.",
	},
	{
		ID: "CVE-2025-0282", Name: "Ivanti Connect Secure RCE", CVSS: 9.0, Service: "pulse",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Ivanti Connect Secure/Policy Secure pre-auth stack buffer overflow RCE.",
	},
	{
		ID: "CVE-2024-47575", Name: "FortiManager FortiJump", CVSS: 9.8, Service: "fortinet",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Fortinet FortiManager fgfmd missing authentication for critical function (FortiJump).",
	},
	{
		ID: "CVE-2022-26809", Name: "Windows RPC runtime RCE", CVSS: 9.8, Service: "dcerpc",
		Technique: "T1210", Tactic: "lateral-movement",
		Description: "Microsoft Windows RPC runtime (rpcrt4) remote code execution.",
	},
	{
		ID: "CVE-2019-1040", Name: "Windows NTLM tampering (Drop the MIC)", CVSS: 6.5, Service: "dcerpc",
		Technique: "T1557", Tactic: "credential-access",
		Description: "Windows NTLM MIC tampering enabling relay to privileged services.",
	},
	{
		ID: "CVE-2020-1350", Name: "SIGRed Windows DNS RCE", CVSS: 10.0, Service: "dns",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Microsoft Windows DNS Server SIG record integer overflow wormable RCE.",
	},
	{
		ID: "CVE-2016-10033", Name: "PHPMailer transport RCE", CVSS: 9.8, Service: "http",
		Technique: "T1190", Tactic: "initial-access",
		Description: "PHPMailer mailSend Sendmail argument injection remote code execution.",
	},
	{
		ID: "CVE-2017-7494", Name: "SambaCry", CVSS: 9.8, Service: "smb",
		Technique: "T1210", Tactic: "lateral-movement",
		Description: "Samba is_known_pipename() arbitrary shared-library load remote code execution.",
	},
	{
		ID: "CVE-2024-6387", Name: "regreSSHion", CVSS: 8.1, Service: "ssh",
		Technique: "T1190", Tactic: "initial-access",
		Description: "OpenSSH sshd signal-handler race condition pre-auth remote code execution.",
	},
	// ---- SSH (OpenSSH / libssh / SSH-1) advisory catalog ----
	// Mostly advisory-only (no payload signature): handshake/version/auth-level
	// flaws the honeypot surfaces via banner + attribution. CVE-2016-0777 is
	// additionally flagged live by the ssh handler from a vulnerable client
	// version (the roaming key-leak window).
	{
		ID: "CVE-2008-0166", Name: "Debian OpenSSL predictable keys", CVSS: 7.5, Service: "ssh",
		Technique: "T1552.004", Tactic: "credential-access",
		Description: "Debian/Ubuntu OpenSSL PRNG patch produced predictable SSH/TLS keys — host and user keys become guessable.",
	},
	{
		ID: "CVE-2016-0777", Name: "OpenSSH client roaming key leak", CVSS: 6.5, Service: "ssh",
		Technique: "T1552.004", Tactic: "credential-access",
		Description: "OpenSSH client roaming (5.4–7.1) lets a malicious server read client process memory, leaking the user's private key.",
	},
	{
		ID: "CVE-2016-0778", Name: "OpenSSH client roaming overflow", CVSS: 7.5, Service: "ssh",
		Technique: "T1203", Tactic: "execution",
		Description: "OpenSSH client roaming buffer overflow / file-descriptor leak triggerable by a malicious server.",
	},
	{
		ID: "CVE-2016-6210", Name: "OpenSSH user enumeration (timing)", CVSS: 5.3, Service: "ssh",
		Technique: "T1087", Tactic: "discovery",
		Description: "OpenSSH sshd reveals valid usernames via auth-response timing (bcrypt for valid vs fast reject for invalid).",
	},
	{
		ID: "CVE-2016-10009", Name: "OpenSSH ssh-agent PKCS#11 RCE", CVSS: 7.5, Service: "ssh",
		Technique: "T1190", Tactic: "initial-access",
		Description: "OpenSSH ssh-agent loads attacker-controlled PKCS#11 modules, enabling code execution via a forwarded agent.",
	},
	{
		ID: "CVE-2015-5600", Name: "OpenSSH keyboard-interactive auth amplification", CVSS: 8.5, Service: "ssh",
		Technique: "T1110", Tactic: "credential-access",
		Description: "OpenSSH kbdint devices let one connection request thousands of password prompts, defeating MaxAuthTries.",
	},
	{
		ID: "CVE-2010-4478", Name: "OpenSSH J-PAKE auth bypass", CVSS: 7.5, Service: "ssh",
		Technique: "T1212", Tactic: "credential-access",
		Description: "OpenSSH (experimental J-PAKE) authentication bypass via crafted shared-secret values.",
	},
	{
		ID: "CVE-2010-5107", Name: "OpenSSH pre-auth connection-slot DoS", CVSS: 5.0, Service: "ssh",
		Technique: "T1499", Tactic: "impact",
		Description: "OpenSSH default LoginGraceTime/MaxStartups lets unauthenticated clients exhaust connection slots.",
	},
	{
		ID: "CVE-2017-15906", Name: "OpenSSH SFTP read-only bypass", CVSS: 5.3, Service: "ssh",
		Technique: "T1190", Tactic: "initial-access",
		Description: "OpenSSH sshd read-only mode still allows zero-length file creation through the SFTP server.",
	},
	{
		ID: "CVE-2018-20685", Name: "OpenSSH scp client directory traversal", CVSS: 5.3, Service: "ssh",
		Technique: "T1190", Tactic: "initial-access",
		Description: "OpenSSH scp client fails to validate server-supplied filenames, allowing path traversal during download.",
	},
	{
		ID: "CVE-2019-6109", Name: "OpenSSH scp client output spoofing", CVSS: 6.8, Service: "ssh",
		Technique: "T1059", Tactic: "execution",
		Description: "OpenSSH scp client missing character encoding lets a malicious server spoof the client terminal via filenames.",
	},
	{
		ID: "CVE-2019-6110", Name: "OpenSSH scp client ANSI injection", CVSS: 6.8, Service: "ssh",
		Technique: "T1059", Tactic: "execution",
		Description: "OpenSSH scp client allows ANSI escape-sequence injection into the client terminal via crafted filenames.",
	},
	{
		ID: "CVE-2019-6111", Name: "OpenSSH scp client arbitrary overwrite", CVSS: 5.9, Service: "ssh",
		Technique: "T1190", Tactic: "initial-access",
		Description: "OpenSSH scp client (SCP protocol) lets a malicious server overwrite arbitrary client files during download.",
	},
	{
		ID: "CVE-2020-14145", Name: "OpenSSH client host-key info leak", CVSS: 5.9, Service: "ssh",
		Technique: "T1557", Tactic: "credential-access",
		Description: "OpenSSH client host-key-algorithm ordering leaks known-hosts state, aiding first-connection man-in-the-middle.",
	},
	{
		ID: "CVE-2020-15778", Name: "OpenSSH scp command injection", CVSS: 7.8, Service: "ssh",
		Technique: "T1059", Tactic: "execution",
		Description: "OpenSSH scp allows OS command injection via backtick/shell metacharacters in remote file paths.",
	},
	{
		ID: "CVE-2021-28041", Name: "OpenSSH ssh-agent double free", CVSS: 7.1, Service: "ssh",
		Technique: "T1499", Tactic: "impact",
		Description: "OpenSSH ssh-agent double-free reachable through constrained forwarded-agent keys.",
	},
	{
		ID: "CVE-2021-41617", Name: "OpenSSH AuthorizedKeysCommand privesc", CVSS: 7.0, Service: "ssh",
		Technique: "T1068", Tactic: "privilege-escalation",
		Description: "OpenSSH sshd runs AuthorizedKeysCommand/AuthorizedPrincipalsCommand with unintended supplemental groups.",
	},
	{
		ID: "CVE-2023-38408", Name: "OpenSSH forwarded ssh-agent PKCS#11 RCE", CVSS: 9.8, Service: "ssh",
		Technique: "T1190", Tactic: "initial-access",
		Description: "OpenSSH ssh-agent remote code execution via an attacker-controlled PKCS#11 provider over a forwarded agent.",
	},
	{
		ID: "CVE-2023-51385", Name: "OpenSSH ProxyCommand injection", CVSS: 6.5, Service: "ssh",
		Technique: "T1059", Tactic: "execution",
		Description: "OpenSSH ssh ProxyCommand OS command injection via shell metacharacters in a hostname/username (e.g. a git submodule URL).",
	},
	{
		ID: "CVE-2023-51384", Name: "OpenSSH ssh-add PKCS#11 constraint bypass", CVSS: 5.3, Service: "ssh",
		Technique: "T1552.004", Tactic: "credential-access",
		Description: "OpenSSH ssh-add does not apply destination constraints to PKCS#11 keys added to the agent.",
	},
	{
		ID: "CVE-2025-26465", Name: "OpenSSH client VerifyHostKeyDNS MITM", CVSS: 6.8, Service: "ssh",
		Technique: "T1557", Tactic: "credential-access",
		Description: "OpenSSH client with VerifyHostKeyDNS can be coerced to accept a machine-in-the-middle host key (logic error).",
	},
	{
		ID: "CVE-2025-26466", Name: "OpenSSH pre-auth memory/CPU DoS", CVSS: 5.9, Service: "ssh",
		Technique: "T1499", Tactic: "impact",
		Description: "OpenSSH pre-authentication resource exhaustion (memory and CPU) via crafted SSH2 ping/pong messages.",
	},
	{
		ID: "CVE-2006-5051", Name: "OpenSSH signal-handler race", CVSS: 8.1, Service: "ssh",
		Technique: "T1190", Tactic: "initial-access",
		Description: "OpenSSH sshd signal-handler race condition pre-auth RCE — the bug class later reintroduced as regreSSHion.",
	},
	{
		ID: "CVE-2003-0693", Name: "OpenSSH buffer-management RCE", CVSS: 9.8, Service: "ssh",
		Technique: "T1190", Tactic: "initial-access",
		Description: "OpenSSH sshd buffer_append_space/buffer management error enabling pre-auth remote code execution.",
	},
	{
		ID: "CVE-2001-0144", Name: "SSH1 CRC-32 compensation-attack RCE", CVSS: 10.0, Service: "ssh",
		Technique: "T1190", Tactic: "initial-access",
		Description: "SSH-1 deattack detector integer overflow (CRC-32 compensation attack) enabling pre-auth remote code execution.",
	},
	{
		ID: "CVE-2018-10933", Name: "libssh server authentication bypass", CVSS: 9.1, Service: "ssh",
		Technique: "T1212", Tactic: "credential-access",
		Description: "libssh server accepts a client-sent SSH2_MSG_USERAUTH_SUCCESS, bypassing authentication entirely.",
	},
	{
		ID: "CVE-2023-2283", Name: "libssh pubkey auth bypass", CVSS: 6.5, Service: "ssh",
		Technique: "T1212", Tactic: "credential-access",
		Description: "libssh public-key authentication state-machine flaw can grant access on partial verification.",
	},
	{
		ID: "CVE-2021-3634", Name: "libssh rekey out-of-bounds write", CVSS: 6.5, Service: "ssh",
		Technique: "T1190", Tactic: "initial-access",
		Description: "libssh key re-exchange with a different host-key type causes a heap out-of-bounds write.",
	},
	{
		ID: "CVE-2002-0640", Name: "OpenSSH challenge-response overflow", CVSS: 10.0, Service: "ssh",
		Technique: "T1190", Tactic: "initial-access",
		Description: "OpenSSH sshd PAM/BSD challenge-response (SKEY/BSD_AUTH) buffer overflow enabling pre-auth RCE.",
	},
	{
		ID: "CVE-2008-1657", Name: "OpenSSH ForceCommand bypass", CVSS: 6.5, Service: "ssh",
		Technique: "T1059", Tactic: "execution",
		Description: "OpenSSH lets a client override the server's ForceCommand via a crafted ~/.ssh/rc, running arbitrary commands.",
	},
	{
		ID: "CVE-2021-21974", Name: "ESXi OpenSLP heap overflow (ESXiArgs)", CVSS: 8.8, Service: "esxi",
		Technique: "T1190", Tactic: "initial-access",
		Description: "VMware ESXi OpenSLP heap overflow remote code execution (ESXiArgs ransomware).",
	},
	{
		ID: "CVE-2023-46805", Name: "Ivanti Connect Secure auth bypass", CVSS: 8.2, Service: "pulse",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Ivanti Connect Secure web-component authentication bypass (chained with CVE-2024-21887).",
	},
	// ---- OT / ICS control-protocol advisories ----
	// Binary control-protocol exploits (Modbus/UMAS, S7, CODESYS, OPC UA,
	// DNP3, IEC-104, FINS, MELSEC, MMS, Fox, GE-SRTP, PCWorx, HART-IP, ATG,
	// KNX). No safe substring signature exists for these framed/binary
	// protocols, so they are advisory-only: the matching OT handler /
	// archetype advertises the unpatched controller under vuln_emulation,
	// and Lookup gives the cve:<id> event an ATT&CK mapping. Verified
	// against CISA ICS advisories + NVD (2026-05 snapshot).
	{
		ID: "CVE-2021-22779", Name: "Schneider Modicon UMAS auth bypass", CVSS: 9.8, Service: "modbus",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Schneider Electric Modicon M340/M580 UMAS (over Modbus/502) authentication bypass enabling unauthenticated read/write control.",
	},
	{
		ID: "CVE-2018-7852", Name: "Schneider Modicon Modbus DoS", CVSS: 7.5, Service: "modbus",
		Technique: "T1499", Tactic: "impact",
		Description: "Schneider Electric Modicon M340 denial of service via crafted Modbus/UMAS packets that halt the controller.",
	},
	{
		ID: "CVE-2016-2200", Name: "Siemens S7-1500 web DoS", CVSS: 7.5, Service: "s7",
		Technique: "T1499", Tactic: "impact",
		Description: "Siemens SIMATIC S7-1500 CPU integrated web server denial of service (defect mode) via crafted packets.",
	},
	{
		ID: "CVE-2019-10929", Name: "Siemens S7-1500 S7CommPlus MITM", CVSS: 5.3, Service: "s7comm_plus",
		Technique: "T1557", Tactic: "credential-access",
		Description: "Siemens SIMATIC S7-1500 weak S7CommPlus integrity protection lets an on-path attacker modify TIA Portal<->PLC traffic on port 102.",
	},
	{
		ID: "CVE-2022-31806", Name: "CODESYS V2 runtime no default auth", CVSS: 9.8, Service: "codesys",
		Technique: "T1190", Tactic: "initial-access",
		Description: "CODESYS Control V2 runtime ships without password protection by default, permitting unauthenticated control and DoS.",
	},
	{
		ID: "CVE-2020-10245", Name: "CODESYS V3 web-server heap overflow", CVSS: 10.0, Service: "codesys",
		Technique: "T1190", Tactic: "initial-access",
		Description: "CODESYS V3 web server (CmpWebServerHandlerV3) heap buffer overflow enabling unauthenticated remote code execution / crash.",
	},
	{
		ID: "CVE-2022-31802", Name: "CODESYS Gateway V2 auth bypass", CVSS: 9.8, Service: "codesys",
		Technique: "T1190", Tactic: "initial-access",
		Description: "CODESYS Gateway Server V2 compares only a password prefix, so a truncated password authenticates (auth bypass).",
	},
	{
		ID: "CVE-2021-27432", Name: "OPC UA .NET uncontrolled recursion DoS", CVSS: 7.5, Service: "opcua",
		Technique: "T1499", Tactic: "impact",
		Description: "OPC Foundation UA .NET Standard/Legacy uncontrolled recursion on crafted messages causes a stack-overflow denial of service.",
	},
	{
		ID: "CVE-2023-4346", Name: "KNX BCU-key device lockout", CVSS: 7.5, Service: "knx",
		Technique: "T1499", Tactic: "impact",
		Description: "An attacker on the KNX bus can set a BCU key on KNX devices, permanently locking out legitimate access (KNXlock).",
	},
	{
		ID: "CVE-2015-5374", Name: "Siemens SIPROTEC EN100 DoS", CVSS: 7.8, Service: "iec104",
		Technique: "T1499", Tactic: "impact",
		Description: "Crafted UDP/50000 packets brick the Siemens SIPROTEC EN100 (IEC-104) Ethernet module until manual reboot (used by Industroyer).",
	},
	{
		ID: "CVE-2019-13524", Name: "GE PACSystems RX3i halt DoS", CVSS: 7.5, Service: "ge_srtp",
		Technique: "T1499", Tactic: "impact",
		Description: "Crafted SRTP packets force GE PACSystems RX3i controllers into halt mode (denial of service requiring battery pull + reboot).",
	},
	{
		ID: "CVE-2020-6986", Name: "Omron CJ-series FINS DoS", CVSS: 7.5, Service: "fins",
		Technique: "T1499", Tactic: "impact",
		Description: "A burst of crafted packets to the Omron CJ-series FINS/Ethernet module causes a service fault (denial of service).",
	},
	{
		ID: "CVE-2021-20591", Name: "Mitsubishi MELSEC iQ-R session DoS", CVSS: 5.3, Service: "melsec",
		Technique: "T1499", Tactic: "impact",
		Description: "Improper session management in Mitsubishi MELSEC iQ-R lets an attacker exhaust connection slots, blocking legitimate MELSOFT clients.",
	},
	{
		ID: "CVE-2022-38138", Name: "Triangle MicroWorks 61850 MMS DoS", CVSS: 7.5, Service: "mms",
		Technique: "T1499", Tactic: "impact",
		Description: "Uninitialized-pointer flaw in the widely-OEM'd TMW IEC-61850 (MMS) library crashes peers on crafted MMS messages.",
	},
	{
		ID: "CVE-2013-2783", Name: "Triangle MicroWorks DNP3 infinite loop", CVSS: 7.1, Service: "dnp3",
		Technique: "T1499", Tactic: "impact",
		Description: "Project Robus: a crafted DNP3 TCP packet drives TMW DNP3 libraries / SCADA Data Gateway into an infinite loop (DoS).",
	},
	{
		ID: "CVE-2017-16744", Name: "Tridium Niagara path traversal", CVSS: 6.6, Service: "fox",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Path traversal in Tridium Niagara AX/Niagara 4 (Fox/platform) enables arbitrary file read and privilege escalation.",
	},
	{
		ID: "CVE-2016-8367", Name: "Phoenix Contact ILC missing auth", CVSS: 9.8, Service: "pcworx",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Phoenix Contact ILC 1xx controllers (PCWorx) expose read/write of PLC variables without authentication.",
	},
	{
		// Advisory-only (the wdbrpc handler attributes these on WDB access).
		ID: "CVE-2010-2965", Name: "VxWorks WDB debug agent exposed", CVSS: 10.0, Service: "wdbrpc",
		Technique: "T1190", Tactic: "initial-access",
		Description: "VxWorks WDB target/debug agent left enabled — unauthenticated memory read/write and code execution on the RTOS.",
	},
	{
		ID: "CVE-2019-12256", Name: "URGENT/11 IPv4-options overflow", CVSS: 9.8, Service: "wdbrpc",
		Technique: "T1190", Tactic: "initial-access",
		Description: "VxWorks IPnet stack overflow parsing IPv4 options (URGENT/11) — remote code execution.",
	},
	{
		ID: "CVE-2019-12255", Name: "URGENT/11 TCP urgent-pointer", CVSS: 9.8, Service: "wdbrpc",
		Technique: "T1190", Tactic: "initial-access",
		Description: "VxWorks IPnet TCP urgent-pointer out-of-bounds (URGENT/11) — memory corruption / RCE.",
	},
	{
		ID: "CVE-2020-16209", Name: "FieldComm HART-IP hipserver overflow", CVSS: 9.8, Service: "hartip",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Stack buffer overflow in the FieldComm Group HART-IP reference server (hipserver) allows unauthenticated RCE / DoS.",
	},
	{
		ID: "CVE-2025-58428", Name: "Veeder-Root TLS4B ATG command injection", CVSS: 9.9, Service: "atg",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Veeder-Root TLS4B automatic-tank-gauge interface lets a remote attacker run system-level OS commands (command injection).",
	},
	{
		ID: "CVE-2018-8867", Name: "GE PACSystems input-validation DoS", CVSS: 7.5, Service: "ge_srtp",
		Technique: "T1499", Tactic: "impact",
		Description: "Improper input validation in GE PACSystems (CPE3xx/4xx, RSTi-EP) lets crafted packets render the controller unavailable.",
	},

	// --- TCP/IP-stack attacks. These ride the honeynet's userspace TCP
	// stack (internal/tcpstack) rather than an application handler, so
	// Service is "tcp". LAND is recognized live (a SYN whose source
	// IP:port equals the destination — the tcp-land anomaly — is dropped,
	// never answered); the fragment-class entries pair with the
	// ip-fragmented anomaly; the rest are advisory references for the
	// stack-fingerprint surface a scanner probes. ---
	{
		ID: "CVE-1999-0015", Name: "Teardrop overlapping-fragment DoS", CVSS: 5.0, Service: "tcp",
		Technique: "T1499", Tactic: "impact",
		Description: "Overlapping IP fragment offsets crash a vulnerable reassembly path (Teardrop). The userspace stack flags fragmented input (ip-fragmented) instead of reassembling it.",
	},
	{
		ID: "CVE-1999-0016", Name: "LAND same-source/dest DoS", CVSS: 5.0, Service: "tcp",
		Technique: "T1499", Tactic: "impact",
		Description: "A spoofed SYN whose source IP:port equals the destination makes a vulnerable stack reply to itself, wedging the CPU (LAND). Detected live as the tcp-land anomaly and dropped.",
	},
	{
		ID: "CVE-2004-0230", Name: "TCP RST/SYN in-window DoS", CVSS: 5.0, Service: "tcp",
		Technique: "T1499", Tactic: "impact",
		Description: "Blind in-window RST/SYN injection tears down established TCP sessions (the slipping-in-the-window class) without being on-path.",
	},
	{
		ID: "CVE-2008-4609", Name: "TCP sockstress state exhaustion", CVSS: 7.1, Service: "tcp",
		Technique: "T1499", Tactic: "impact",
		Description: "Completing handshakes then advertising a zero/tiny window exhausts the target's connection-state memory (sockstress). The decoy bounds its flow table with an idle reaper.",
	},
	{
		ID: "CVE-2016-5696", Name: "Linux off-path TCP injection", CVSS: 5.9, Service: "tcp",
		Technique: "T1499", Tactic: "impact",
		Description: "The Linux global TCP challenge-ACK rate limit is a side channel that lets an off-path attacker infer sequence numbers and reset/inject connections blind.",
	},
	{
		ID: "CVE-2018-5391", Name: "FragmentSmack IP-fragment DoS", CVSS: 7.5, Service: "tcp",
		Technique: "T1499", Tactic: "impact",
		Description: "Crafted IP fragments with worst-case reassembly cost drive CPU to 100% (FragmentSmack). The userspace stack flags fragments (ip-fragmented) and never reassembles.",
	},
	{
		ID: "CVE-2019-11477", Name: "SACK Panic", CVSS: 7.5, Service: "tcp",
		Technique: "T1499", Tactic: "impact",
		Description: "A crafted run of TCP Selective-ACKs with a low MSS overflows the Linux kernel SKB structure and panics the host (SACK Panic).",
	},
	{
		ID: "CVE-2020-11896", Name: "Ripple20 Treck TCP/IP RCE", CVSS: 10.0, Service: "tcp",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Remote code execution in the Treck embedded TCP/IP stack via crafted IP/UDP packets (Ripple20) — the OT/IoT device class the honeynet emulates.",
	},

	// --- recent (2023-2025) in-the-wild / CISA-KEV additions ---
	{
		ID: "CVE-2023-22527", Name: "Confluence OGNL template injection RCE", CVSS: 10.0, Service: "http",
		Signatures: []string{"/template/aui/text-inline.vm", "\\u0027${"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Atlassian Confluence Data Center/Server SSTI: an unauthenticated OGNL injection into the text-inline.vm Velocity template yields remote code execution.",
	},
	{
		ID: "CVE-2024-24919", Name: "Check Point Security Gateway arbitrary file read", CVSS: 8.6, Service: "http",
		Signatures: []string{"acshell/../", "/clients/mycrl"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Check Point Quantum/CloudGuard Gateway with remote-access VPN: a path-traversal in the portal lets an unauthenticated attacker read any file (e.g. /etc/shadow), harvesting password hashes and the ike/vpn config.",
	},
	{
		ID: "CVE-2024-0012", Name: "PAN-OS management auth bypass", CVSS: 9.8, Service: "http",
		Signatures: []string{"/php/utils/createremoteappwebsession.php", "/unauth/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Palo Alto PAN-OS management web interface authentication bypass; chained with CVE-2024-9474 for root command execution on the firewall.",
	},
	{
		ID: "CVE-2024-23692", Name: "Rejetto HFS template injection RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"{.exec|", "{.exec |"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Rejetto HTTP File Server 2.3m server-side template injection: an unauthenticated request with an {.exec|...} macro runs arbitrary commands.",
	},
	{
		ID: "CVE-2024-28995", Name: "SolarWinds Serv-U path traversal", CVSS: 8.6, Service: "http",
		Signatures: []string{"internaldir=..", "internaldir=%2f.."},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "SolarWinds Serv-U file transfer: a directory-traversal in the InternalDir/InternalFile parameters lets an unauthenticated attacker read arbitrary files off the host.",
	},
	{
		ID: "CVE-2023-35082", Name: "Ivanti EPMM (MobileIron) API auth bypass", CVSS: 9.8, Service: "http",
		Signatures: []string{"/mifs/asfv3/api/v2/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Ivanti Endpoint Manager Mobile (formerly MobileIron Core) authentication bypass exposing the administrative API to unauthenticated callers.",
	},
	{
		ID: "CVE-2025-31324", Name: "SAP NetWeaver Visual Composer file upload RCE", CVSS: 10.0, Service: "http",
		Signatures: []string{"/developmentserver/metadatauploader"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "SAP NetWeaver Visual Composer Metadata Uploader allows an unauthenticated attacker to upload a malicious binary (web shell) and achieve remote code execution.",
	},
	{
		ID: "CVE-2024-36401", Name: "GeoServer OGC evaluation RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"valuereference=exec(", "exec(java.lang.runtime"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "GeoServer evaluates OGC WMS/WFS property names as Apache Commons JXPath expressions, letting an unauthenticated attacker run arbitrary code via a crafted valueReference.",
	},
	{
		ID: "CVE-2024-4885", Name: "Progress WhatsUp Gold path-traversal RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/nmapi/recurringactiontrigger"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Progress WhatsUp Gold GetFileWithoutZip path traversal in the NmAPI endpoint allows unauthenticated remote code execution as the service account.",
	},
	{
		ID: "CVE-2024-38856", Name: "Apache OFBiz auth bypass RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"programexport", "viewmaplist"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Apache OFBiz screen-rendering authentication bypass: chaining a permitted view to ProgramExport reaches the Groovy ProgramExport endpoint for unauthenticated RCE.",
	},
	{
		ID: "CVE-2023-6553", Name: "WordPress Backup Migration RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/wp-content/plugins/backup-backup/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "WordPress Backup Migration plugin: an unauthenticated PHP object-injection via the content-disposition header in includes/backup-heart.php yields remote code execution.",
	},
	{
		ID: "CVE-2024-27956", Name: "WordPress Automatic plugin SQLi", CVSS: 9.9, Service: "http",
		Signatures: []string{"/wp-content/plugins/wp-automatic/inc/csv.php"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "WordPress WP-Automatic plugin SQL injection in the CSV import (q parameter) allowing admin-user creation and site takeover; mass-exploited.",
	},
	{
		ID: "CVE-2024-25600", Name: "WordPress Bricks Builder RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/wp-json/bricks/v1/render_element"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "WordPress Bricks theme/builder unauthenticated remote code execution via eval of the render_element queryEditor parameter; widely exploited by botnets.",
	},
	{
		ID: "CVE-2023-34960", Name: "Chamilo LMS command injection", CVSS: 9.8, Service: "http",
		Signatures: []string{"/main/webservices/additional_webservices.php"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Chamilo LMS WSConvertPpt SOAP web service passes attacker input to a shell, allowing unauthenticated command injection.",
	},
	{
		ID: "CVE-2022-30525", Name: "Zyxel firewall ZTP command injection", CVSS: 9.8, Service: "http",
		Signatures: []string{"/ztp/cgi-bin/handler", "setwanportst"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Zyxel USG/ATP/VPN firewalls in ZTP mode pass the setWanPortSt mtu/data field to a shell, allowing unauthenticated remote command injection as nobody.",
	},
	{
		ID: "CVE-2023-1389", Name: "TP-Link Archer AX21 command injection", CVSS: 8.8, Service: "http",
		Signatures: []string{"country=$(", "country=%24%28", "country=`"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "TP-Link Archer AX21 router web management country field is passed unsanitized to a shell — heavily abused by Mirai/Condi botnets for IoT recruitment.",
	},
	// Advisory-only (binary / handshake-level exploits we advertise + version-emulate
	// but whose attempt is recognized structurally by the handler, not by a payload string):
	{
		ID: "CVE-2023-48795", Name: "Terrapin SSH prefix truncation", CVSS: 5.9, Service: "ssh",
		Technique: "T1557", Tactic: "credential-access",
		Description: "Terrapin: a man-in-the-middle can truncate the SSH extension-negotiation by manipulating handshake sequence numbers, downgrading security (e.g. disabling keystroke-timing countermeasures).",
	},
	{
		ID: "CVE-2024-21762", Name: "FortiOS SSL-VPN out-of-bounds write RCE", CVSS: 9.8, Service: "fortinet",
		Technique: "T1190", Tactic: "initial-access",
		Description: "FortiOS SSL-VPN out-of-bounds write reachable pre-authentication for remote code execution on the FortiGate; a CISA-KEV edge-device exploit.",
	},
	{
		ID: "CVE-2025-22457", Name: "Ivanti Connect Secure stack overflow RCE", CVSS: 9.0, Service: "pulse",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Ivanti Connect Secure / Policy Secure stack-based buffer overflow exploited in the wild for unauthenticated remote code execution on the VPN appliance.",
	},

	// --- second wave: IoT/DVR/camera botnet targets + recent enterprise RCEs ---
	{
		ID: "CVE-2024-10914", Name: "D-Link NAS account_mgr command injection", CVSS: 9.2, Service: "http",
		Signatures: []string{"/cgi-bin/account_mgr.cgi?cmd=cgi_user_add", "account_mgr.cgi?cmd=cgi_user_add"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "D-Link DNS-320/325/340L NAS: the `name` parameter of account_mgr.cgi's cgi_user_add is passed to a shell — unauthenticated command injection, mass-exploited by Mirai variants.",
	},
	{
		ID: "CVE-2024-3721", Name: "TBK DVR command injection", CVSS: 6.3, Service: "http",
		Signatures: []string{"/device.rsp?opt=sys&cmd=", "mdb=sss&cmd="},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "TBK DVR-4104/4216 device.rsp shell-metacharacter injection in the cmd parameter — a staple Mirai/IoT-botnet recruitment exploit.",
	},
	{
		ID: "CVE-2024-7029", Name: "AVTECH IP camera command injection", CVSS: 8.7, Service: "http",
		Signatures: []string{"/cgi-bin/supervisor/factory.cgi", "action=makeo&brightness="},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "AVTECH IP cameras: the brightness parameter of Factory.cgi is injected into a shell — used by the Corona/Mirai botnet for unauthenticated RCE on exposed cameras.",
	},
	{
		ID: "CVE-2024-0769", Name: "D-Link DIR-859 path traversal", CVSS: 9.8, Service: "http",
		Signatures: []string{"/hedwig.cgi", "service=../../"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "D-Link DIR-859 hedwig.cgi path traversal in the service parameter, disclosing credentials from the device config for full takeover.",
	},
	{
		ID: "CVE-2024-29973", Name: "Zyxel NAS command injection", CVSS: 9.8, Service: "http",
		Signatures: []string{"/cgi-bin/remote_help-cgi", "remote_help-cgi?type=command"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Zyxel NAS326/NAS542: the setCookie parameter of remote_help-cgi is passed to a shell — unauthenticated command injection.",
	},
	{
		ID: "CVE-2024-27348", Name: "Apache HugeGraph Gremlin RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/apis/gremlin", "java.lang.runtime", "optionalthreadfactory"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Apache HugeGraph Server: a crafted Gremlin query escapes the sandbox via reflection (OGNL/thread-factory) for unauthenticated remote code execution.",
	},
	{
		ID: "CVE-2024-4040", Name: "CrushFTP VFS escape / template injection", CVSS: 9.8, Service: "http",
		Signatures: []string{"/webinterface/function/", "<getfeaturelist", "zip_read_max_size"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "CrushFTP server-side template injection lets an unauthenticated attacker escape the VFS sandbox to read arbitrary files (and reach RCE) — a CISA-KEV file-transfer exploit.",
	},
	{
		ID: "CVE-2024-28000", Name: "LiteSpeed Cache privilege escalation", CVSS: 9.8, Service: "http",
		Signatures: []string{"litespeed_hash", "role=administrator&litespeed"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "WordPress LiteSpeed Cache plugin: a weak hash check on the litespeed_hash cookie lets an unauthenticated attacker forge an admin session and take over the site.",
	},
	{
		ID: "CVE-2024-4358", Name: "Telerik Report Server auth bypass", CVSS: 9.8, Service: "http",
		Signatures: []string{"/startup/register", "restapi/v1.0/datadesigner"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Progress Telerik Report Server: the Startup/Register page lets an unauthenticated attacker create an admin account; chained with a deserialization bug for RCE.",
	},
	{
		ID: "CVE-2024-9264", Name: "Grafana DuckDB SQL-expression RCE", CVSS: 9.4, Service: "http",
		Signatures: []string{"/api/ds/query", "\"datasource\":{\"type\":\"__expr__\"", "duckdb"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Grafana SQL Expressions evaluate via the bundled DuckDB CLI; an authenticated-but-low-priv attacker reaches command execution / arbitrary file read through a crafted query.",
	},
	{
		ID: "CVE-2024-21683", Name: "Confluence language-pack RCE", CVSS: 8.3, Service: "http",
		Signatures: []string{"addlanguage.action", "/admin/plugins/newcode/"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Atlassian Confluence Data Center: uploading a malicious JavaScript 'language' via addlanguage.action achieves authenticated remote code execution.",
	},
	{
		ID: "CVE-2023-48788", Name: "Fortinet FortiClientEMS SQL injection", CVSS: 9.3, Service: "http",
		Signatures: []string{"fctuid"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Fortinet FortiClient EMS: a SQL injection in the FCTUID-handling stored procedure allows unauthenticated RCE via xp_cmdshell — a CISA-KEV exploit.",
	},
	{
		ID: "CVE-2024-36991", Name: "Splunk Enterprise path traversal", CVSS: 7.5, Service: "http",
		Signatures: []string{"/en-us/modules/messaging/", "/modules/messaging/c:../"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Splunk Enterprise on Windows: a path traversal in the messaging endpoint discloses arbitrary files (including the user database) to an unauthenticated attacker.",
	},
	{
		ID: "CVE-2023-50386", Name: "Apache Solr backup/restore RCE", CVSS: 8.8, Service: "http",
		Signatures: []string{"/solr/admin/configs?action=upload", "replication?command=restore"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Apache Solr: a config-set upload followed by backup/restore loads an attacker-supplied JAR/class, achieving remote code execution.",
	},
	{
		ID: "CVE-2025-24813", Name: "Apache Tomcat partial-PUT RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"content-range: bytes", "/uploads/4."},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Apache Tomcat: a partial PUT writing a session file under a path-equivalence flaw enables deserialization RCE when file-based session persistence is enabled.",
	},

	// Advisory-only (handshake/binary; advertised + version-emulated, the
	// attempt recognized structurally by the handler):
	{
		ID: "CVE-2025-32433", Name: "Erlang/OTP SSH pre-auth RCE", CVSS: 10.0, Service: "ssh",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Erlang/OTP SSH daemon processes connection-protocol messages before authentication, allowing an unauthenticated attacker to run arbitrary code — a critical pre-auth RCE in OT/embedded gear.",
	},
	{
		ID: "CVE-2024-45519", Name: "Zimbra postjournal RCE", CVSS: 9.8, Service: "smtp_recv",
		Technique: "T1190", Tactic: "initial-access",
		Description: "Zimbra Collaboration: the postjournal service passes SMTP recipient data to a shell, allowing unauthenticated command execution via a crafted message — exploited in the wild.",
	},

	// --- POP3 / IMAP mail-retrieval (plaintext + implicit-TLS variants).
	// These are flagged by the in-handler protocol-misimplementation detectors
	// (STARTTLS plaintext injection, pre-auth credential/literal overflow), not
	// by request signatures, so the records are advisory + enrichment for the
	// cve:<id> events the detectors raise and for vuln-banner emulation.
	{
		ID: "CVE-2019-11500", Name: "Dovecot pre-auth OOB write", CVSS: 9.8, Service: "imap",
		Technique: "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-787"},
		CPE:         "cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*",
		Description: "Dovecot before 2.3.7.2 / 2.2.36.4: a NUL byte inside an IMAP (or ManageSieve) literal is mishandled, writing out of bounds pre-authentication — remotely exploitable for crash or code execution.",
	},
	{
		ID: "CVE-2011-1430", Name: "Dovecot STARTTLS command injection", CVSS: 6.8, Service: "imap",
		Technique: "T1557", Tactic: "credential-access",
		CWE:         []string{"CWE-74"},
		CPE:         "cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*",
		Description: "Dovecot before 2.0.13: plaintext commands pipelined after the STARTTLS/STLS command are retained across the TLS handshake and executed in the encrypted session — a man-in-the-middle command-injection / response-injection flaw affecting IMAP, POP3 and ManageSieve.",
	},
	{
		ID: "CVE-2003-0264", Name: "SLMail POP3 PASS buffer overflow", CVSS: 7.5, Service: "pop3",
		Technique: "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-120"},
		Description: "Seattle Lab Mail (SLMail) 5.5 POP3 server: an overlong PASS argument overflows a fixed stack buffer, allowing remote code execution — the archetypal POP3 credential-field overflow probe.",
	},

	// --- third wave: cloud/AI-infra + CMS + 2025 web exploits ---
	{
		ID: "CVE-2024-8190", Name: "Ivanti CSA command injection", CVSS: 7.2, Service: "http",
		Signatures: []string{"/gsb/datetime.php"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Ivanti Cloud Services Appliance: OS command injection via the TIMEZONE field of datetime.php — a CISA-KEV exploit chained for appliance takeover.",
	},
	{
		ID: "CVE-2024-8963", Name: "Ivanti CSA path traversal", CVSS: 9.4, Service: "http",
		Signatures: []string{"/client/index.php%3f.php", "/client/index.php?a.php"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Ivanti Cloud Services Appliance: a path-traversal lets an unauthenticated attacker reach restricted admin endpoints; chained with CVE-2024-8190 for RCE.",
	},
	{
		ID: "CVE-2024-50603", Name: "Aviatrix Controller RCE", CVSS: 10.0, Service: "http",
		Signatures: []string{"list_flightpath_destination_instances", "flightpath_destination"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Aviatrix Controller: unsanitized parameters in the flightpath API are passed to a shell, allowing unauthenticated remote code execution on the cloud network controller.",
	},
	{
		ID: "CVE-2023-48022", Name: "Ray jobs API RCE (ShadowRay)", CVSS: 9.8, Service: "http",
		Signatures: []string{"/api/job_submission/jobs", "\"entrypoint\":"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Ray (anyscale) cluster job-submission API has no authentication, so anyone who can reach the dashboard can submit an arbitrary entrypoint command — actively abused to hijack AI/GPU clusters (ShadowRay).",
	},
	{
		ID: "CVE-2024-27564", Name: "ChatGPT pictureproxy SSRF", CVSS: 6.5, Service: "http",
		Signatures: []string{"pictureproxy.php?url=", "/flreey/chatgpt"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "A widely-deployed ChatGPT PHP front-end has an SSRF in pictureproxy.php's url parameter — heavily scanned for internal-service / cloud-metadata pivoting.",
	},
	{
		ID: "CVE-2025-29927", Name: "Next.js middleware auth bypass", CVSS: 9.1, Service: "http",
		Signatures: []string{"x-middleware-subrequest"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Next.js: supplying the internal x-middleware-subrequest header skips middleware execution, bypassing authentication/authorization gates — mass-scanned after disclosure.",
	},
	{
		ID: "CVE-2025-32432", Name: "Craft CMS RCE", CVSS: 10.0, Service: "http",
		Signatures: []string{"conditions/render", "configobject"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "Craft CMS: a crafted conditions/render request with an attacker-controlled configObject leads to unauthenticated remote code execution; exploited in the wild.",
	},
	{
		ID: "CVE-2024-9047", Name: "WordPress File Upload arbitrary file read", CVSS: 8.8, Service: "http",
		Signatures: []string{"wfu_file_downloader.php"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "WordPress WP File Upload plugin: wfu_file_downloader.php allows an unauthenticated attacker to read/delete arbitrary files via path traversal.",
	},
	{
		ID: "CVE-2024-10924", Name: "WordPress Really Simple Security auth bypass", CVSS: 9.8, Service: "http",
		Signatures: []string{"reallysimplessl/v1/two_fa", "rest_route=/reallysimplessl"},
		Technique:  "T1190", Tactic: "initial-access",
		Description: "WordPress Really Simple Security 2FA REST route can be invoked with an attacker-chosen user_id to authenticate as any user (including admin) — a mass-exploitable account takeover.",
	},

	// Advisory-only (protocol/DoS/MITM; advertised + version-emulated, the
	// attempt recognized structurally by the handler rather than a payload string):
	{
		ID: "CVE-2025-24472", Name: "FortiOS/FortiProxy auth bypass", CVSS: 8.1, Service: "fortinet",
		Technique: "T1190", Tactic: "initial-access",
		Description: "FortiOS / FortiProxy authentication bypass via a crafted CSF proxy request, granting super-admin on the firewall — a CISA-KEV edge-device exploit.",
	},
	{
		ID: "CVE-2023-44487", Name: "HTTP/2 Rapid Reset DoS", CVSS: 7.5, Service: "http",
		Technique: "T1499", Tactic: "impact",
		Description: "HTTP/2 Rapid Reset: an attacker opens and immediately RST_STREAM-cancels a flood of streams, exhausting server resources — the record-setting 2023 DDoS technique.",
	},
	// HTTP/2 frame / HPACK resource-exhaustion family (detected by the h2c handler
	// from frame shape, not a request-payload signature).
	{
		ID: "CVE-2016-6581", Name: "HTTP/2 HPACK Bomb", CVSS: 7.5, Service: "http",
		Technique: "T1499", Tactic: "impact",
		Description: "HPACK header-compression bomb: a tiny HEADERS block that references a large dynamic-table entry many times decompresses to gigabytes, exhausting server memory (Benfield, 2016).",
	},
	{
		ID: "CVE-2016-8740", Name: "Apache mod_http2 CONTINUATION memory exhaustion", CVSS: 7.5, Service: "http",
		Technique: "T1499", Tactic: "impact",
		Description: "Apache httpd mod_http2 did not bound the HTTP/2 header block accumulated across CONTINUATION frames, so an unbounded run of CONTINUATION frames exhausts server memory.",
	},
	{
		ID: "CVE-2016-1546", Name: "Apache mod_http2 worker-thread starvation", CVSS: 5.9, Service: "http",
		Technique: "T1499", Tactic: "impact",
		Description: "Apache httpd mod_http2 lets a single HTTP/2 connection hold many half-open request streams, starving the worker-thread pool and denying service to other clients.",
	},
	{
		ID: "CVE-2025-53020", Name: "Apache mod_http2 memory exhaustion (HTTP/2 bomb)", CVSS: 7.5, Service: "http",
		Technique: "T1499", Tactic: "impact",
		Description: "Apache httpd mod_http2 unbounded memory growth from HTTP/2 header amplification / late-processed streams (the HPACK-bomb family, ~4000x amplification); fixed in 2.4.64.",
	},
	{
		ID: "CVE-2026-49975", Name: "HTTP/2 Bomb DoS", CVSS: 7.5, Service: "http",
		Technique: "T1499", Tactic: "impact",
		Description: "HTTP/2 Bomb: thousands of near-empty HPACK headers (per-entry bookkeeping amplification, the decoded-size limit never fires) combined with a zero-window Slowloris hold pin server memory to exhaustion across nginx/Apache/IIS/Envoy/Pingora (Codex/Calif, 2026).",
	},
	{
		ID: "CVE-2024-3596", Name: "Blast-RADIUS MD5 forgery (MITM)", CVSS: 9.0, Service: "radius",
		Technique: "T1557", Tactic: "credential-access",
		Description: "RADIUS/UDP Access-Request integrity relies on MD5; a man-in-the-middle can forge a valid Access-Accept (Blast-RADIUS), bypassing authentication across the AAA fabric.",
	},

	// --- fourth wave (2.8): more enterprise-web exploits ---
	{
		ID: "CVE-2022-41040", Name: "Exchange ProxyNotShell SSRF", CVSS: 8.8, Service: "http",
		Signatures: []string{"/autodiscover/autodiscover.json?@", "autodiscover.json?@"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-918"},
		Description: "Microsoft Exchange ProxyNotShell: an Autodiscover SSRF (chained with CVE-2022-41082) reaches the PowerShell backend for authenticated RCE — exploited in the wild.",
	},
	{
		ID: "CVE-2023-7028", Name: "GitLab password-reset account takeover", CVSS: 10.0, Service: "http",
		Signatures: []string{"user[email][]=", "/users/password", "user%5bemail%5d%5b%5d="},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-640"},
		Description: "GitLab CE/EE: a password-reset request accepting an array of e-mail addresses delivers the reset link to an attacker-controlled address, enabling account takeover (incl. admins).",
	},
	{
		ID: "CVE-2022-47966", Name: "Zoho ManageEngine SAML RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"samlresponse=", "/samlresponse", "/samllogin"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-94"},
		Description: "Zoho ManageEngine (ADSelfService Plus and ~24 products): an outdated Apache xmlsec lets a crafted SAMLResponse trigger unauthenticated remote code execution.",
	},
	{
		ID: "CVE-2023-50164", Name: "Apache Struts2 file-upload path traversal", CVSS: 9.8, Service: "http",
		Technique: "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-22"},
		Description: "Apache Struts2 file-upload parameter manipulation lets an attacker traverse paths and upload a webshell to a web-reachable directory — unauthenticated remote code execution.",
	},
	{
		ID: "CVE-2024-9474", Name: "PAN-OS management privilege escalation", CVSS: 7.2, Service: "http",
		Technique: "T1068", Tactic: "privilege-escalation",
		CWE:         []string{"CWE-77"},
		Description: "Palo Alto PAN-OS web management: an authenticated admin (or one obtained via the CVE-2024-0012 auth bypass) can run commands as root — chained for full appliance takeover in the wild.",
	},

	// --- fifth wave (2.8): more 2024 edge / enterprise-app exploits ---
	{
		ID: "CVE-2024-55956", Name: "Cleo Harmony/VLTrader unauth RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/synchronization", "autorun", "import autorun"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-94"},
		Description: "Cleo Harmony / VLTrader / LexiCom: an unauthenticated request to the Synchronization endpoint writes and auto-runs a file, giving remote code execution — mass-exploited by Cl0p in late 2024.",
	},
	{
		ID: "CVE-2024-29824", Name: "Ivanti EPM SQL injection RCE", CVSS: 9.6, Service: "http",
		Signatures: []string{"/wsstatusevents/eventhandler.asmx", "recordgoodapp"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-89"},
		Description: "Ivanti Endpoint Manager: an unauthenticated SQL injection in the EventHandler SOAP endpoint reaches xp_cmdshell for remote code execution.",
	},
	{
		ID: "CVE-2024-45195", Name: "Apache OFBiz auth bypass RCE", CVSS: 7.5, Service: "http",
		Signatures: []string{"/webtools/control/", "viewbizdetails", "forgotpassword/viewbizdetails"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-863"},
		Description: "Apache OFBiz: a view-state/authorization confusion lets an unauthenticated attacker reach screen-rendering endpoints and chain to remote code execution.",
	},
	{
		ID: "CVE-2024-20767", Name: "Adobe ColdFusion arbitrary file read", CVSS: 7.4, Service: "http",
		Signatures: []string{"/cf_scripts/scripts/ajax/", "/cfide/adminapi/"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-862"},
		Description: "Adobe ColdFusion: improper access control on the admin CFIDE endpoints allows unauthenticated arbitrary file read (and write in some configs).",
	},
	{
		ID: "CVE-2024-40711", Name: "Veeam Backup & Replication deserialization RCE", CVSS: 9.8, Service: "http",
		Technique: "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-502"},
		Description: "Veeam Backup & Replication: unsafe deserialization in the backup service enables unauthenticated remote code execution — abused by ransomware affiliates for domain-wide impact.",
	},
	{
		ID: "CVE-2024-29849", Name: "Veeam Enterprise Manager auth bypass", CVSS: 9.8, Service: "http",
		Technique: "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-287"},
		Description: "Veeam Backup Enterprise Manager: an unauthenticated attacker can log in as any user via a crafted VMware SSO token, fully bypassing authentication.",
	},
	{
		ID: "CVE-2024-7593", Name: "Ivanti vTM auth bypass", CVSS: 9.8, Service: "http",
		Technique: "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-287"},
		Description: "Ivanti Virtual Traffic Manager: an incorrect authentication-algorithm implementation in the admin panel lets a remote attacker create an administrator account.",
	},
	{
		ID: "CVE-2024-48887", Name: "FortiSwitch unverified admin password change", CVSS: 9.3, Service: "fortinet",
		Technique: "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-640"},
		Description: "Fortinet FortiSwitch GUI: an unverified password-change endpoint lets a remote unauthenticated attacker set the administrator password and take over the switch.",
	},
	// --- CVEs for the newly-added Lua appliance/framework personas. Detectable
	// over plain http too (the http handler runs MatchPayload), so a probe lands
	// a cve:<id> event with the CWE + ATT&CK technique even without the persona.
	{
		ID: "CVE-2023-26360", Name: "Adobe ColdFusion arbitrary read / deserialization", CVSS: 8.6, Service: "http",
		Signatures: []string{"/cf_scripts/scripts/ajax/ckeditor/", "/cfide/administrator/", "_cfclient="},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-94", "CWE-284"},
		Description: "Adobe ColdFusion improper access control allowing arbitrary file read and unsafe deserialization → RCE (exploited in the wild).",
	},
	{
		ID: "CVE-2023-32315", Name: "Openfire admin console auth bypass", CVSS: 7.5, Service: "http",
		Signatures: []string{"/setup/setup-/", "%u002e%u002e", "/setup/setup-/../../"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-22", "CWE-287"},
		Description: "Ignite Realtime Openfire admin console path-traversal auth bypass reaching authenticated pages → plugin-upload RCE.",
	},
	{
		ID: "CVE-2022-27593", Name: "QNAP Photo Station externally-controlled reference (DeadBolt)", CVSS: 7.5, Service: "http",
		Signatures: []string{"/photo/p/api/", "/photo/slideshow.php", "externalref="},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-610"},
		Description: "QNAP Photo Station externally-controlled reference let attackers plant files — the vector behind the DeadBolt ransomware campaign against QNAP NAS.",
	},
	{
		// SLP amplification (UDP 427) — advisory/banner-emulation only (no string
		// signature; the slp handler flags the SrvRqst amplification probe).
		ID: "CVE-2023-29552", Name: "SLP reflection/amplification (SLPDoS)", CVSS: 8.6, Service: "slp",
		Technique: "T1498.002", Tactic: "impact",
		CWE:         []string{"CWE-400", "CWE-406"},
		Description: "Service Location Protocol allows an unauthenticated attacker to register services and abuse the spoofable UDP responder for a >2200x reflective-amplification DoS.",
	},

	// ===================================================================
	// Batch: 40 web/http/https/smtp/ftp exploit-attempt emulations. Each
	// carries a high-signal request substring so the http / smtp_recv / ftp
	// handlers flag a live cve:<id> attempt (http records also match https,
	// the implicit-TLS mail variants inherit smtp_recv). Detection only.
	// ===================================================================

	// --- Application servers (Tomcat / WebLogic / JBoss / ActiveMQ) ---
	{
		ID: "CVE-2017-12617", Name: "Apache Tomcat JSP upload via PUT", CVSS: 8.1, Service: "http",
		Signatures: []string{".jsp/", ".jsp::$data"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-434"},
		Description: "Apache Tomcat with HTTP PUT enabled (readonly=false) lets an attacker upload a JSP via a trailing-slash/NTFS-ADS name bypass → RCE.",
	},
	{
		ID: "CVE-2016-3088", Name: "Apache ActiveMQ Fileserver upload RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/fileserver/"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-22", "CWE-434"},
		Description: "ActiveMQ Fileserver web app allows PUT/MOVE of a JSP webshell into an executable path → RCE.",
	},
	{
		ID: "CVE-2010-0738", Name: "JBoss JMX console authentication bypass", CVSS: 7.5, Service: "http",
		Signatures: []string{"/jmx-console/htmladaptor"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-287"},
		Description: "JBoss AS jmx-console only protected GET/POST, so a verb-tampering request reaches the JMX HtmlAdaptor and deploys a WAR → RCE.",
	},
	{
		ID: "CVE-2017-9805", Name: "Apache Struts2 REST XStream deserialization", CVSS: 8.1, Service: "http",
		Signatures: []string{"jdk.nashorn.internal.objects.nativestring"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-502"},
		Description: "Struts2 REST plugin deserializes attacker XML via XStream (S2-052) → RCE.",
	},
	{
		ID: "CVE-2021-2109", Name: "Oracle WebLogic Server JNDI RCE", CVSS: 7.2, Service: "http",
		Signatures: []string{"/console/consolejndi.portal"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-94"},
		Description: "WebLogic admin console JNDI binding lets an authenticated attacker trigger a remote JNDI lookup → RCE.",
	},
	{
		ID: "CVE-2020-9484", Name: "Apache Tomcat session persistence deserialization", CVSS: 7.0, Service: "http",
		Signatures: []string{"jsessionid=../", "jsessionid=..%2f"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-502"},
		Description: "Tomcat with a FileStore PersistentManager deserializes a session file chosen via a path-traversal JSESSIONID → RCE.",
	},
	{
		ID: "CVE-2010-1871", Name: "JBoss Seam framework EL injection RCE", CVSS: 7.5, Service: "http",
		Signatures: []string{"actionoutcome="},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-94"},
		Description: "JBoss Seam evaluates the actionOutcome parameter as JBoss EL, allowing arbitrary method invocation → RCE.",
	},

	// --- Java web frameworks (Spring / Confluence / Druid / Jenkins) ---
	{
		ID: "CVE-2022-22963", Name: "Spring Cloud Function SpEL injection RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"spring.cloud.function.routing-expression"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-94"},
		Description: "Spring Cloud Function evaluates the spring.cloud.function.routing-expression header as SpEL → RCE.",
	},
	{
		ID: "CVE-2018-1273", Name: "Spring Data Commons SpEL injection RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"t(java.lang.runtime).getruntime()"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-94"},
		Description: "Spring Data Commons binds request properties through SpEL, allowing a crafted property name to execute code.",
	},
	{
		ID: "CVE-2019-3396", Name: "Atlassian Confluence Widget Connector SSTI", CVSS: 9.8, Service: "http",
		Signatures: []string{"/rest/tinymce/1/macro/preview"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-91"},
		Description: "Confluence Widget Connector macro allows server-side template injection / path traversal via Velocity → file read + RCE.",
	},
	{
		ID: "CVE-2021-25646", Name: "Apache Druid embedded JavaScript RCE", CVSS: 8.8, Service: "http",
		Signatures: []string{"/druid/indexer/v1/sampler"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-94"},
		Description: "Apache Druid lets an authenticated user enable and submit JavaScript in a sampler/parser task → RCE.",
	},
	{
		ID: "CVE-2018-1000861", Name: "Jenkins Stapler reflection RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/securityrealm/user/admin/descriptorbyname"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-502"},
		Description: "Jenkins Stapler web framework allows invoking arbitrary methods via crafted URLs, chained with Groovy sandbox bypass → RCE.",
	},
	{
		ID: "CVE-2019-1003000", Name: "Jenkins Script Security sandbox bypass RCE", CVSS: 8.8, Service: "http",
		Signatures: []string{"checkscriptcompile"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-94"},
		Description: "Jenkins Script Security / Pipeline AST checks let a Groovy script escape the sandbox at compile time → RCE.",
	},
	{
		ID: "CVE-2019-7609", Name: "Kibana Timelion prototype-pollution RCE", CVSS: 10.0, Service: "http",
		Signatures: []string{"/api/timelion/run"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-94"},
		Description: "Kibana Timelion visualization allows a JavaScript prototype-pollution payload → arbitrary code execution on the host.",
	},

	// --- PHP CMS / web apps (Drupal / Joomla / vBulletin / WordPress-stack) ---
	{
		ID: "CVE-2014-3704", Name: "Drupalgeddon SQL injection", CVSS: 9.8, Service: "http",
		Signatures: []string{"name[0;", "name[0%20;"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-89"},
		Description: "Drupal 7 core database API array-key SQL injection in the login form → auth bypass / RCE.",
	},
	{
		ID: "CVE-2018-7602", Name: "Drupalgeddon2 (variant) RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"#post_render"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-94"},
		Description: "Drupal core Form API renders attacker-controlled #post_render / #lazy_builder callbacks → RCE.",
	},
	{
		ID: "CVE-2015-8562", Name: "Joomla! PHP object injection RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"jdatabasedrivermysqli"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-502"},
		Description: "Joomla! deserializes a crafted User-Agent/X-Forwarded-For stored in the session → PHP object injection → RCE.",
	},
	{
		ID: "CVE-2019-16759", Name: "vBulletin pre-auth widget RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"widgetconfig[code]"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-94"},
		Description: "vBulletin evaluates the widgetConfig[code] parameter of the widget render endpoint as PHP → unauthenticated RCE.",
	},
	{
		ID: "CVE-2023-23752", Name: "Joomla! unauthorized config disclosure", CVSS: 5.3, Service: "http",
		Signatures: []string{"/api/index.php/v1/config/application?public=true"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-285"},
		Description: "Joomla! Web Services API improper access control discloses configuration including database credentials.",
	},
	{
		ID: "CVE-2022-42889", Name: "Apache Commons Text interpolation RCE (Text4Shell)", CVSS: 9.8, Service: "http",
		Signatures: []string{"${script:javascript:", "${prefixloader", "${url:utf-8:"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-94"},
		Description: "Apache Commons Text StringSubstitutor default interpolators (script/url/dns) evaluate attacker input → RCE.",
	},

	// --- HTTP servers / appliances / IoT web ---
	{
		ID: "CVE-2017-7269", Name: "Microsoft IIS 6.0 WebDAV ScStoragePathFromUrl overflow", CVSS: 9.8, Service: "http",
		Signatures: []string{"<locktoken:write1>"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-119"},
		Description: "IIS 6.0 WebDAV buffer overflow via an overlong If header in PROPFIND → RCE.",
	},
	{
		ID: "CVE-2015-1635", Name: "Microsoft HTTP.sys remote code execution (MS15-034)", CVSS: 10.0, Service: "http",
		Signatures: []string{"bytes=0-18446744073709551615"},
		Technique:  "T1499", Tactic: "impact",
		CWE:         []string{"CWE-190"},
		Description: "HTTP.sys integer overflow parsing a crafted Range header → BSOD / potential RCE.",
	},
	{
		ID: "CVE-2020-0618", Name: "Microsoft SQL Server Reporting Services deserialization RCE", CVSS: 8.8, Service: "http",
		Signatures: []string{"/reportserver/pages/reportviewer.aspx"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-502"},
		Description: "SSRS ReportViewer deserializes an attacker-supplied ViewState/NavigationCorrector payload → RCE.",
	},
	{
		ID: "CVE-2021-43798", Name: "Grafana plugin path traversal", CVSS: 7.5, Service: "http",
		Signatures: []string{"/public/plugins/alertlist/..", "/public/plugins/graph/.."},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-22"},
		Description: "Grafana plugin asset endpoint allows path traversal to read arbitrary files (e.g. grafana.ini, /etc/passwd).",
	},
	{
		ID: "CVE-2020-25078", Name: "D-Link IP camera admin credential disclosure", CVSS: 7.5, Service: "http",
		Signatures: []string{"/config/getuser?index="},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-200"},
		Description: "D-Link DCS cameras expose /config/getuser, disclosing the administrator username/password without authentication.",
	},
	{
		ID: "CVE-2021-35394", Name: "Realtek Jungle SDK command injection", CVSS: 9.8, Service: "http",
		Signatures: []string{"/goform/formsyscmd", "formwsc", "formsyscmd"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-78"},
		Description: "Realtek Jungle SDK web management (UDPServer/formSysCmd) command injection — a Mirai-class mass-exploited SOHO bug.",
	},

	// --- Management / monitoring / SSRF ---
	{
		ID: "CVE-2022-46169", Name: "Cacti unauthenticated command injection", CVSS: 9.8, Service: "http",
		Signatures: []string{"/remote_agent.php"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-78"},
		Description: "Cacti remote_agent.php auth bypass + command injection via the poller hostname → unauthenticated RCE.",
	},
	{
		ID: "CVE-2019-15107", Name: "Webmin password_change.cgi RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/password_change.cgi"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-78"},
		Description: "Webmin password_change.cgi passes the old-password field to a shell → unauthenticated RCE (backdoored release).",
	},
	{
		ID: "CVE-2023-38646", Name: "Metabase pre-auth H2 JDBC RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/api/setup/validate"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-94"},
		Description: "Metabase setup-token validation lets an unauthenticated attacker supply an H2 JDBC connection string with INIT SQL → RCE.",
	},
	{
		ID: "CVE-2021-21975", Name: "VMware vRealize Operations SSRF", CVSS: 7.5, Service: "http",
		Signatures: []string{"/casa/nodes/thumbprints"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-918"},
		Description: "vRealize Operations Manager API SSRF (casa/nodes/thumbprints) used to steal admin credentials.",
	},
	{
		ID: "CVE-2019-11580", Name: "Atlassian Crowd pdkinstall plugin RCE", CVSS: 9.8, Service: "http",
		Signatures: []string{"/admin/uploadplugin.action"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-434"},
		Description: "Atlassian Crowd left the pdkinstall development plugin enabled, allowing upload of a malicious plugin → RCE.",
	},
	{
		ID: "CVE-2018-19518", Name: "PHP imap_open mailbox argument-injection RCE", CVSS: 8.8, Service: "http",
		Signatures: []string{"-oproxycommand"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-88"},
		Description: "PHP imap_open() passes the mailbox string to rsh/ssh; an -oProxyCommand argument injects a shell command (webmail RCE).",
	},

	// --- SMTP (smtp_recv; implicit-TLS smtps inherits) ---
	{
		ID: "CVE-2020-7247", Name: "OpenSMTPD MAIL FROM command injection RCE", CVSS: 9.8, Service: "smtp_recv",
		Signatures: []string{"mail from:<;"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-78"},
		Description: "OpenSMTPD smtp_mailaddr local-part validation flaw lets a shell command in MAIL FROM run as root.",
	},
	{
		ID: "CVE-2019-10149", Name: "Exim deliver_message RCE (Return of the WIZard)", CVSS: 9.8, Service: "smtp_recv",
		Signatures: []string{"${run{"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-78"},
		Description: "Exim expands an ${run{...}} expression in a crafted RCPT TO local-part → command execution as root.",
	},
	{
		ID: "CVE-2021-41277", Name: "Metabase GeoJSON local file inclusion / SSRF", CVSS: 10.0, Service: "http",
		Signatures: []string{"/api/geojson?url="},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-918"},
		Description: "Metabase custom GeoJSON map endpoint fetches an attacker-supplied URL/path, enabling local file read and SSRF.",
	},

	// --- FTP (ftp control channel) ---
	{
		ID: "CVE-2015-3306", Name: "ProFTPD mod_copy SITE CPFR/CPTO RCE", CVSS: 10.0, Service: "ftp",
		Signatures: []string{"site cpfr"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-22"},
		Description: "ProFTPD mod_copy lets an unauthenticated client copy files (SITE CPFR/CPTO), e.g. a webshell into the web root → RCE.",
	},
	{
		ID: "CVE-2019-12815", Name: "ProFTPD mod_copy arbitrary file copy", CVSS: 9.8, Service: "ftp",
		Signatures: []string{"site cpto"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-22"},
		Description: "ProFTPD mod_copy permits arbitrary file copy without write permission via SITE CPTO → data disclosure / RCE.",
	},
	{
		ID: "CVE-2011-2523", Name: "vsftpd 2.3.4 backdoor", CVSS: 9.8, Service: "ftp",
		Signatures: []string{":)"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-78"},
		Description: "Backdoored vsftpd 2.3.4: a username containing the ':)' smiley opens a root shell on TCP 6200.",
	},
	{
		ID: "CVE-2000-0573", Name: "wu-ftpd SITE EXEC format-string RCE", CVSS: 10.0, Service: "ftp",
		Signatures: []string{"site exec"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-134"},
		Description: "wu-ftpd SITE EXEC passes user input as a format string → remote root code execution.",
	},
	{
		ID: "CVE-2010-3867", Name: "ProFTPD mod_site_misc path traversal", CVSS: 7.5, Service: "ftp",
		Signatures: []string{"site symlink", "site mkdir ../"},
		Technique:  "T1190", Tactic: "initial-access",
		CWE:         []string{"CWE-22"},
		Description: "ProFTPD mod_site_misc SITE SYMLINK/MKDIR allow directory traversal to create/link files outside the FTP root.",
	},

	// ===================================================================
	// Batch: 75 additional HTTP/HTTPS web-application exploit emulations.
	// All Service "http" (also matches https). High-signal path / header /
	// body signatures; detection only.
	// ===================================================================
	{ID: "CVE-2010-5326", Name: "SAP NetWeaver Invoker Servlet auth bypass RCE", CVSS: 10.0, Service: "http", Signatures: []string{"/ctc/servlet/com.sap.ctc.util"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "SAP NetWeaver Invoker Servlet allows unauthenticated invocation of ConfigServlet → command execution."},
	{ID: "CVE-2014-6287", Name: "Rejetto HTTP File Server (HFS) RCE", CVSS: 9.8, Service: "http", Signatures: []string{"{.exec|", "%00{.exec"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "Rejetto HFS findMacroMarker null-byte macro injection → remote command execution."},
	{ID: "CVE-2015-7501", Name: "Apache Commons Collections deserialization RCE", CVSS: 9.8, Service: "http", Signatures: []string{"invokertransformer", "instantiatetransformer"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, Description: "Java deserialization of a Commons-Collections InvokerTransformer gadget chain → RCE (JBoss/Jenkins/WebLogic)."},
	{ID: "CVE-2016-3081", Name: "Apache Struts2 Dynamic Method Invocation OGNL RCE", CVSS: 9.8, Service: "http", Signatures: []string{"#_memberaccess", "method:#_member"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "Struts2 S2-032: DMI lets an attacker run OGNL via the method: prefix → RCE."},
	{ID: "CVE-2016-4977", Name: "Spring Security OAuth SpEL injection RCE", CVSS: 8.8, Service: "http", Signatures: []string{"response_type=${", "response_type=%24%7b"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-917"}, Description: "Spring Security OAuth whitelabel approval page evaluates the response_type parameter as SpEL → RCE."},
	{ID: "CVE-2017-1000028", Name: "Oracle GlassFish directory traversal", CVSS: 7.5, Service: "http", Signatures: []string{"%c0%ae%c0%ae", "/theme/meta-inf/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "GlassFish Server overlong-UTF-8 path traversal reads arbitrary files."},
	{ID: "CVE-2017-12629", Name: "Apache Solr XXE / RCE", CVSS: 9.8, Service: "http", Signatures: []string{"{!xmlparser", "!xmlparser%20"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-611"}, Description: "Apache Solr query-time XML parser XXE (and RunExecutableListener RCE)."},
	{ID: "CVE-2017-16894", Name: "Laravel debug-mode .env exposure", CVSS: 7.5, Service: "http", Signatures: []string{"/.env"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-200"}, Description: "Laravel apps with debug/env left exposed leak .env (DB creds, APP_KEY) — a mass-scanned path."},
	{ID: "CVE-2017-7525", Name: "Jackson-databind deserialization RCE (TemplatesImpl)", CVSS: 9.8, Service: "http", Signatures: []string{"templatesimpl", "com.sun.org.apache.xalan"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, Description: "jackson-databind polymorphic typing deserializes a TemplatesImpl gadget → RCE."},
	{ID: "CVE-2017-9248", Name: "Telerik UI DialogHandler crypto weakness RCE", CVSS: 9.8, Service: "http", Signatures: []string{"telerik.web.ui.dialoghandler.aspx"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, Description: "Telerik UI for ASP.NET weak Telerik.Web.UI key → DialogHandler/AsyncUpload deserialization RCE."},
	{ID: "CVE-2018-1271", Name: "Spring MVC Windows directory traversal", CVSS: 5.9, Service: "http", Signatures: []string{"/static/..%5c", "/spring-mvc-showcase/resources/..%5c"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "Spring MVC serving static resources from the filesystem on Windows allows ..\\ traversal."},
	{ID: "CVE-2018-13382", Name: "Fortinet FortiOS SSL-VPN 'magic' auth bypass", CVSS: 7.5, Service: "http", Signatures: []string{"/remote/logincheck", "magic=", "&reportclient"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, Description: "FortiOS SSL-VPN magic-parameter lets an attacker change any user's password without authentication."},
	{ID: "CVE-2018-2894", Name: "Oracle WebLogic WLS Web Services Test Page upload RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/ws_utc/resources/setting", "/ws_utc/config.do"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-434"}, Description: "WebLogic ws_utc test page allows unauthenticated file upload to a web-reachable dir → RCE."},
	{ID: "CVE-2018-9995", Name: "DVR/NVR credential disclosure via Cookie", CVSS: 9.8, Service: "http", Signatures: []string{"device.rsp?opt=user&cmd=list"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-200"}, Description: "TBK and OEM DVRs return the admin credentials for a crafted Cookie on device.rsp."},
	{ID: "CVE-2019-0232", Name: "Apache Tomcat CGIServlet RCE (Windows)", CVSS: 8.1, Service: "http", Signatures: []string{"?&c%2b", ".bat?&c"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Tomcat CGIServlet on Windows passes the query string to the command shell → RCE."},
	{ID: "CVE-2019-10758", Name: "mongo-express server-side JS injection RCE", CVSS: 9.8, Service: "http", Signatures: []string{"this.constructor.constructor"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "mongo-express evaluates user input as JS (checkValid) → RCE."},
	{ID: "CVE-2019-12384", Name: "Jackson-databind logback JNDI deserialization RCE", CVSS: 9.8, Service: "http", Signatures: []string{"drivermanagerconnectionsource", "ch.qos.logback.core.db"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, Description: "jackson-databind logback DriverManagerConnectionSource gadget → JDBC/JNDI RCE."},
	{ID: "CVE-2019-15642", Name: "rConfig search.crud.php unauthenticated RCE", CVSS: 9.8, Service: "http", Signatures: []string{"search.crud.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "rConfig search.crud.php passes input to a shell → unauthenticated RCE."},
	{ID: "CVE-2019-1653", Name: "Cisco RV320/RV325 config disclosure", CVSS: 7.5, Service: "http", Signatures: []string{"/cgi-bin/config.exp"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-200"}, Description: "Cisco RV320/RV325 routers leak the full device configuration (incl. hashed creds) without auth."},
	{ID: "CVE-2019-16662", Name: "rConfig ajaxServerSettingsChk RCE", CVSS: 9.8, Service: "http", Signatures: []string{"ajaxservertesting.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "rConfig ajaxServerSettingsChk.php command injection → unauthenticated RCE."},
	{ID: "CVE-2019-17558", Name: "Apache Solr Velocity template RCE", CVSS: 8.5, Service: "http", Signatures: []string{"params.resource.loader.enabled", "wt=velocity"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "Apache Solr VelocityResponseWriter SSTI when params resource loader is enabled → RCE."},
	{ID: "CVE-2019-2729", Name: "Oracle WebLogic wls9-async XMLDecoder RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/_async/asyncresponseservice"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, Description: "WebLogic wls9-async XMLDecoder deserialization of a crafted SOAP body → unauthenticated RCE."},
	{ID: "CVE-2019-3398", Name: "Atlassian Confluence download path traversal", CVSS: 8.8, Service: "http", Signatures: []string{"/download/temp/..", "/pages/downloadallattachments.action"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "Confluence attachment download path traversal allows writing files outside the intended dir → RCE."},
	{ID: "CVE-2019-6340", Name: "Drupal core REST unserialize RCE", CVSS: 8.1, Service: "http", Signatures: []string{"_format=hal_json"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, Description: "Drupal 8 core REST module deserializes attacker data on certain entity endpoints → RCE."},
	{ID: "CVE-2019-7238", Name: "Sonatype Nexus Repository 3 RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/service/extdirect"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, Description: "Nexus Repository Manager 3 missing access control + EL injection on the Ext.Direct endpoint → RCE."},
	{ID: "CVE-2020-0688", Name: "Microsoft Exchange ECP ViewState deserialization RCE", CVSS: 8.8, Service: "http", Signatures: []string{"b97b4e27", "__viewstategenerator=b97b"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, Description: "Exchange ships a static ASP.NET validationKey; a forged ViewState on /ecp deserializes → SYSTEM RCE."},
	{ID: "CVE-2020-17530", Name: "Apache Struts2 forced OGNL evaluation RCE (S2-061)", CVSS: 9.8, Service: "http", Signatures: []string{"(#context[", "%{(#context"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-917"}, Description: "Struts2 forced double-evaluation of a tag attribute as OGNL → RCE."},
	{ID: "CVE-2020-25213", Name: "WordPress File Manager plugin upload RCE", CVSS: 9.8, Service: "http", Signatures: []string{"wp-file-manager/lib/php/connector.minimal.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-434"}, Description: "WP File Manager elFinder connector allows unauthenticated upload of a PHP webshell → RCE."},
	{ID: "CVE-2020-3580", Name: "Cisco ASA/FTD WebVPN reflected XSS", CVSS: 6.1, Service: "http", Signatures: []string{"/+cscou+/logon.html?a="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-79"}, Description: "Cisco ASA/FTD WebVPN logon page reflects unsanitized input → XSS (credential theft)."},
	{ID: "CVE-2020-5410", Name: "Spring Cloud Config Server path traversal", CVSS: 8.6, Service: "http", Signatures: []string{"%252f..%252f..%252f"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "Spring Cloud Config Server getResource directory traversal via double-encoded sequences."},
	{ID: "CVE-2020-6207", Name: "SAP Solution Manager EEM missing auth RCE", CVSS: 10.0, Service: "http", Signatures: []string{"/eemadminservice/eemadmin"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-306"}, Description: "SAP Solution Manager Eem servlet lacks authentication → agent command execution on connected hosts."},
	{ID: "CVE-2020-7796", Name: "Zimbra Collaboration autosaveDraft SSRF", CVSS: 7.5, Service: "http", Signatures: []string{"/h/autosavedraft"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-918"}, Description: "Zimbra ZmMailMsg autosaveDraft allows unauthenticated XXE/SSRF."},
	{ID: "CVE-2020-8515", Name: "DrayTek Vigor unauthenticated command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/cgi-bin/mainfunction.cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "DrayTek Vigor routers inject shell commands via the keyPath/rtick parameters → RCE (botnet target)."},
	{ID: "CVE-2020-9546", Name: "Jackson-databind commons-dbcp deserialization RCE", CVSS: 9.8, Service: "http", Signatures: []string{"basicdatasource", "org.apache.commons.dbcp2"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, Description: "jackson-databind shaded commons-dbcp BasicDataSource gadget → RCE."},
	{ID: "CVE-2021-21311", Name: "Adminer server-side request forgery", CVSS: 7.2, Service: "http", Signatures: []string{"elastic://", "driver=elastic"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-918"}, Description: "Adminer Elasticsearch/ClickHouse drivers can be pointed at internal hosts → SSRF / cloud-metadata theft."},
	{ID: "CVE-2021-21315", Name: "Node.js systeminformation command injection", CVSS: 7.8, Service: "http", Signatures: []string{"/api/getservices?name[]=", "getservices?name[]=$("}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "systeminformation passes the services parameter to a shell → command injection."},
	{ID: "CVE-2021-21978", Name: "VMware View Planner logupload upload RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/logupload", "logmetadatadictionary"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-434"}, Description: "VMware View Planner logupload web app allows unauthenticated file upload → RCE."},
	{ID: "CVE-2021-22986", Name: "F5 BIG-IP iControl REST SSRF → RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/mgmt/shared/authn/login"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-918"}, Description: "F5 iControl REST unauthenticated SSRF to the local mcp socket → token creation + RCE."},
	{ID: "CVE-2021-26085", Name: "Atlassian Confluence pre-auth file read", CVSS: 5.3, Service: "http", Signatures: []string{"/_/;/web-inf/classes", "/_/;/web-inf/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "Confluence resource-disclosure path traversal reads WEB-INF files without authentication."},
	{ID: "CVE-2021-26119", Name: "Smarty template engine SSTI RCE", CVSS: 8.8, Service: "http", Signatures: []string{"{php}", "{$smarty.template_object"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "Smarty allows {php} / static-method access in templates → sandbox escape RCE (Prestashop/etc.)."},
	{ID: "CVE-2021-27905", Name: "Apache Solr replication SSRF", CVSS: 8.6, Service: "http", Signatures: []string{"command=fetchindex", "masterurl="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-918"}, Description: "Apache Solr ReplicationHandler fetchindex masterUrl/leaderUrl SSRF."},
	{ID: "CVE-2021-3019", Name: "Lanproxy directory traversal", CVSS: 7.5, Service: "http", Signatures: []string{"/../conf/config.properties"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "Lanproxy path traversal discloses config.properties (backend credentials)."},
	{ID: "CVE-2021-31755", Name: "Tenda AC11 router stack overflow RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/goform/setusbunload", "/goform/wifimulti"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-787"}, Description: "Tenda AC11 goform endpoints stack overflow → remote code execution (botnet target)."},
	{ID: "CVE-2021-31805", Name: "Apache Struts2 OGNL double-evaluation RCE (S2-062)", CVSS: 9.8, Service: "http", Signatures: []string{"%{(#dm=@ognl", "@ognl.ognlcontext@default_member_access"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-917"}, Description: "Struts2 forced OGNL evaluation of tag attributes (S2-061 bypass) → RCE."},
	{ID: "CVE-2021-34523", Name: "Microsoft Exchange ProxyShell privilege escalation", CVSS: 9.8, Service: "http", Signatures: []string{"x-rps-cat=", "/powershell?x-rps-cat"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, Description: "Exchange PowerShell backend trusts the X-Rps-CAT token (ProxyShell chain) → SYSTEM RCE."},
	{ID: "CVE-2021-3577", Name: "Geutebruck IP camera command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/uapi-cgi/certmngr.cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Geutebruck cameras inject shell commands via the certmngr.cgi parameters → RCE."},
	{ID: "CVE-2021-36260", Name: "Hikvision IP camera command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/sdk/weblanguage"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Hikvision web SDK weblanguage element command injection → unauthenticated RCE (Mirai-class)."},
	{ID: "CVE-2021-39226", Name: "Grafana snapshot authentication bypass", CVSS: 7.3, Service: "http", Signatures: []string{"/dashboard/snapshot/", "/api/snapshots/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-862"}, Description: "Grafana snapshot endpoints are reachable unauthenticated, exposing dashboards / enabling enumeration."},
	{ID: "CVE-2021-40438", Name: "Apache HTTP Server mod_proxy SSRF", CVSS: 9.0, Service: "http", Signatures: []string{"/?unix:"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-918"}, Description: "Apache mod_proxy forwards a request to an attacker-chosen origin via a crafted unix: URI → SSRF."},
	{ID: "CVE-2022-0540", Name: "Atlassian Jira Seraph authentication bypass", CVSS: 9.8, Service: "http", Signatures: []string{"serverinfoaction.jspa", ";/admin"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, Description: "Jira/Confluence Seraph path-based auth bypass reaches privileged WebWork actions."},
	{ID: "CVE-2022-24112", Name: "Apache APISIX batch-requests admin RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/apisix/batch-requests"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "APISIX batch-requests plugin bypasses the admin IP restriction → route with Lua filter → RCE."},
	{ID: "CVE-2022-26138", Name: "Atlassian Confluence Questions hardcoded credential", CVSS: 9.8, Service: "http", Signatures: []string{"disabledsystemuser"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-798"}, Description: "Confluence Questions add-on creates a disabledsystemuser account with a public hardcoded password."},
	{ID: "CVE-2022-29078", Name: "EJS template engine SSTI RCE", CVSS: 9.8, Service: "http", Signatures: []string{"settings[view options][outputfunctionname]", "outputfunctionname"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "EJS renders attacker-controlled outputFunctionName as code via Express settings pollution → RCE."},
	{ID: "CVE-2022-31656", Name: "VMware Workspace ONE Access authentication bypass", CVSS: 9.8, Service: "http", Signatures: []string{"/saas/auth/login/embeddedauthbroker/callback"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, Description: "VMware WS1 Access/Identity Manager local-user auth bypass → admin (chained to RCE)."},
	{ID: "CVE-2022-31814", Name: "pfSense pfBlockerNG unauth RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/pfblockerng/www/", "pfblockerng/www/index.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "pfBlockerNG reflects the Host header into a shell command → unauthenticated RCE."},
	{ID: "CVE-2022-33891", Name: "Apache Spark UI command injection", CVSS: 8.8, Service: "http", Signatures: []string{"doas=%60", "?doas="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Apache Spark UI ACL doAs parameter is passed to a shell when impersonation is enabled → RCE."},
	{ID: "CVE-2022-35914", Name: "GLPI htmLawed test-page command injection", CVSS: 9.8, Service: "http", Signatures: []string{"htmlawedtest.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "GLPI bundled htmLawed test page evaluates the hexdec callback → PHP command injection."},
	{ID: "CVE-2022-40127", Name: "Apache Airflow example DAG command injection", CVSS: 8.8, Service: "http", Signatures: []string{"example_bash_operator", "/dagruns"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Airflow example_bash_operator runs an attacker-supplied bash_command via the DAG-run conf."},
	{ID: "CVE-2022-47986", Name: "IBM Aspera Faspex YAML deserialization RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/aspera/faspex/external_deliveries"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, Description: "Aspera Faspex deserializes a crafted YAML in the package-relay API → unauthenticated RCE."},
	{ID: "CVE-2023-20887", Name: "VMware Aria Operations for Networks command injection", CVSS: 9.8, Service: "http", Signatures: []string{"resttosaasservlet"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-77"}, Description: "VMware Aria Ops for Networks (vRNI) Apache Thrift endpoint command injection → RCE."},
	{ID: "CVE-2023-25157", Name: "GeoServer OGC filter SQL injection", CVSS: 9.8, Service: "http", Signatures: []string{"strendswith(", "strstartswith("}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-89"}, Description: "GeoServer evaluates OGC filter functions (strEndsWith/PropertyName) into SQL → injection."},
	{ID: "CVE-2023-26469", Name: "Jorani language path traversal / SSTI", CVSS: 8.8, Service: "http", Signatures: []string{"/session/language?language="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "Jorani session language parameter path traversal → CodeIgniter template RCE."},
	{ID: "CVE-2023-35036", Name: "Progress MOVEit Transfer SQL injection (guest access)", CVSS: 9.1, Service: "http", Signatures: []string{"guestaccess.aspx"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-89"}, Description: "MOVEit Transfer guestaccess.aspx SQL injection (post-CVE-2023-34362 variant)."},
	{ID: "CVE-2023-36845", Name: "Juniper Junos J-Web PHP external variable injection RCE", CVSS: 9.8, Service: "http", Signatures: []string{"webauth_operation.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "Junos J-Web allows setting PHPRC via a multipart upload → arbitrary code execution."},
	{ID: "CVE-2023-36934", Name: "Progress MOVEit Transfer SQL injection", CVSS: 9.8, Service: "http", Signatures: []string{"/moveitisapi/moveitisapi.dll"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-89"}, Description: "MOVEit Transfer MOVEitISAPI unauthenticated SQL injection."},
	{ID: "CVE-2023-41892", Name: "Craft CMS unauthenticated RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/index.php?p=admin/actions/conditions/render"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "Craft CMS conditions/render endpoint instantiates an attacker-chosen class → RCE."},
	{ID: "CVE-2023-43177", Name: "CrushFTP unauthenticated mass-assignment RCE", CVSS: 9.8, Service: "http", Signatures: []string{"looking_glass"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, Description: "CrushFTP AS2 header session injection (Looking_Glass) allows unauthenticated access → RCE."},
	{ID: "CVE-2023-46214", Name: "Splunk Enterprise XSLT upload RCE", CVSS: 8.0, Service: "http", Signatures: []string{"/services/admin/lookup-table-files"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "Splunk allows an authenticated user to upload a malicious XSLT executed during search export → RCE."},
	{ID: "CVE-2023-49070", Name: "Apache OFBiz XML-RPC deserialization RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/webtools/control/xmlrpc"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, Description: "Apache OFBiz retains the XML-RPC endpoint vulnerable to a deserialization gadget → RCE."},
	{ID: "CVE-2024-1212", Name: "Progress Kemp LoadMaster unauthenticated command injection", CVSS: 10.0, Service: "http", Signatures: []string{"/access/set?param=enableapi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Kemp LoadMaster management API command injection without authentication → RCE."},
	{ID: "CVE-2024-25641", Name: "Cacti package import arbitrary PHP write RCE", CVSS: 9.1, Service: "http", Signatures: []string{"/package_import.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "Cacti package_import.php writes attacker PHP from a crafted package → authenticated RCE."},
	{ID: "CVE-2024-27199", Name: "JetBrains TeamCity path traversal auth bypass", CVSS: 7.3, Service: "http", Signatures: []string{"/res/../admin/", "/.well-known/acme-challenge/../"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "TeamCity path traversal reaches authenticated admin endpoints without authentication."},
	{ID: "CVE-2024-27954", Name: "WordPress Automatic plugin file download / SSRF", CVSS: 9.3, Service: "http", Signatures: []string{"wp_automatic=download", "?wp_automatic="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-918"}, Description: "WP Automatic plugin downloader fetches an attacker URL / arbitrary file → SSRF + file disclosure."},
	{ID: "CVE-2024-2879", Name: "WordPress LayerSlider SQL injection", CVSS: 9.8, Service: "http", Signatures: []string{"/wp-json/ls/v1/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-89"}, Description: "WordPress LayerSlider REST endpoint unauthenticated SQL injection."},
	{ID: "CVE-2024-4956", Name: "Sonatype Nexus Repository path traversal", CVSS: 7.5, Service: "http", Signatures: []string{"%2f%2f%2f%2f%2f%2f%2f", "/%2f%2f%2f%2f%2f%2f%2f.."}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "Nexus Repository 3 unauthenticated path traversal reads arbitrary files."},

	// ===================================================================
	// Batch: 75 more HTTP/HTTPS exploit emulations — routers/IoT, CMS/plugins,
	// Java/enterprise apps, webmail. Service "http" (https inherits); the router
	// signatures are the device's unique exploit endpoint (a probe to it is the
	// attack). Detection only.
	// ===================================================================
	// --- Routers / IoT / cameras (Mirai-class mass-exploited endpoints) ---
	{ID: "CVE-2018-10562", Name: "Dasan/Zhone GPON router command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/gponform/diag_form", "dest_host="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "GPON home routers run shell commands from the diag_Form dest_host field → RCE (massive botnet target)."},
	{ID: "CVE-2017-17215", Name: "Huawei HG532 router command injection", CVSS: 8.8, Service: "http", Signatures: []string{"/ctrlt/deviceupgrade_1"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Huawei HG532 UPnP DeviceUpgrade injects shell commands via NewStatusURL → RCE (Mirai/Satori)."},
	{ID: "CVE-2014-8361", Name: "Realtek SDK miniigd UPnP command injection", CVSS: 9.8, Service: "http", Signatures: []string{"picsdesc.xml", "newinternalclient"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Realtek SDK miniigd SOAP NewInternalClient command injection → RCE (countless OEM routers)."},
	{ID: "CVE-2016-6277", Name: "Netgear R7000/R6400 command injection", CVSS: 8.1, Service: "http", Signatures: []string{"/cgi-bin/;"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Netgear routers execute a command appended after /cgi-bin/; → unauthenticated RCE."},
	{ID: "CVE-2017-5521", Name: "Netgear password-recovery disclosure", CVSS: 8.1, Service: "http", Signatures: []string{"passwordrecovered.cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-200"}, Description: "Netgear routers disclose the admin password via passwordrecovered.cgi without authentication."},
	{ID: "CVE-2015-2051", Name: "D-Link HNAP SOAPAction command injection", CVSS: 9.8, Service: "http", Signatures: []string{"getdevicesettings"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "D-Link DIR routers inject shell commands via the HNAP GetDeviceSettings SOAPAction header → RCE."},
	{ID: "CVE-2019-10891", Name: "D-Link DIR-806 hedwig.cgi command injection", CVSS: 9.8, Service: "http", Signatures: []string{"hedwig.cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "D-Link DIR-806 hedwig.cgi command injection → RCE."},
	{ID: "CVE-2019-16920", Name: "D-Link apply_sec.cgi command injection", CVSS: 9.8, Service: "http", Signatures: []string{"apply_sec.cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "D-Link DIR routers unauthenticated RCE via apply_sec.cgi."},
	{ID: "CVE-2022-26258", Name: "D-Link DIR-820L remote command execution", CVSS: 9.8, Service: "http", Signatures: []string{"/lan.asp"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "D-Link DIR-820L command injection via the /lan.asp settings handler → RCE."},
	{ID: "CVE-2020-9377", Name: "D-Link DIR-610 command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/command.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "D-Link DIR-610 /command.php remote command execution."},
	{ID: "CVE-2024-33112", Name: "D-Link DNS-320 account_mgr.cgi command injection", CVSS: 9.8, Service: "http", Signatures: []string{"account_mgr.cgi?cmd=cgi_user_add"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "D-Link DNS-320 NAS account_mgr.cgi command injection → RCE."},
	{ID: "CVE-2020-8958", Name: "Guangzhou/ONU GPON ONT command injection", CVSS: 7.2, Service: "http", Signatures: []string{"/boaform/admin/formping", "/boaform/admin/formtracert"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Guangzhou ONU GPON ONTs inject shell commands via the boaform ping/tracert forms → RCE."},
	{ID: "CVE-2017-18368", Name: "ZyXEL P660HN-T1A viewlog.asp command injection", CVSS: 9.8, Service: "http", Signatures: []string{"viewlog.asp"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "ZyXEL P660HN viewlog.asp command injection → RCE (Gafgyt/Mirai)."},
	// ---- TR-069 (CWMP) / TR-369 (USP) / UPnP CPE-management exposure. The
	// connection-request port 7547 and the UPnP IGD control plane are mass-
	// scanned; these are the headline takeover primitives. (Realtek miniigd
	// CVE-2014-8361 + Huawei HG532 CVE-2017-17215 above are also UPnP SOAP RCE,
	// matched via the http service the upnp handler additionally scans.) ----
	{ID: "CVE-2016-10372", Name: "Eir D1000 / TR-064 SetNTPServers RCE (CWMP 7547)", CVSS: 9.8, Service: "tr069", Signatures: []string{"setntpservers", "newntpserver1"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Eir D1000 / Zyxel CPEs run shell commands from the TR-064 SetNTPServers NewNTPServer1 parameter, reachable on the TR-069 port 7547 → RCE (the Nov-2016 Deutsche Telekom / Mirai outage)."},
	{ID: "CVE-2014-9222", Name: "Misfortune Cookie (RomPager)", CVSS: 9.8, Service: "tr069", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-787"}, Description: "AllegroSoft RomPager <4.34 — the embedded HTTP server fronting TR-069 on millions of CPEs — lets a crafted Cookie header corrupt heap state and act as any session → device takeover."},
	{ID: "CVE-2020-12695", Name: "CallStranger (UPnP SUBSCRIBE)", CVSS: 7.5, Service: "upnp", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-918"}, Description: "UPnP devices honor a SUBSCRIBE Callback header pointing at an arbitrary host, giving an attacker SSRF, data exfiltration past DLP, and a reflected/amplified DDoS source."},
	{ID: "CVE-2012-5958", Name: "libupnp SSDP stack overflow (Unplug. Don't Play.)", CVSS: 10.0, Service: "ssdp", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-120"}, Description: "The Portable SDK for UPnP (libupnp) unique_service_name() stack buffer overflow in SSDP parsing → RCE across tens of millions of devices."},
	// ---- Enterprise / SP network gear (advertised as decoys on the matching
	// router/firewall archetypes; the web ones also detect the exploit path). ----
	{ID: "CVE-2022-20821", Name: "Cisco IOS XR open Redis (health check)", CVSS: 6.5, Service: "redis", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-306"}, Description: "Cisco IOS XR (NCS 540/560/5500) left the health-check Redis instance bound to a routable port, allowing unauthenticated read/write (exploited in the wild)."},
	{ID: "CVE-2023-30799", Name: "MikroTik RouterOS Winbox privilege escalation (FOISted)", CVSS: 9.1, Service: "http", Technique: "T1068", Tactic: "privilege-escalation", CWE: []string{"CWE-269"}, Description: "MikroTik RouterOS escalates an admin to super-admin via Winbox/API → arbitrary code execution on the router."},
	{ID: "CVE-2024-40766", Name: "SonicWall SonicOS improper access control", CVSS: 9.3, Service: "https", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-284"}, Description: "SonicWall SonicOS management / SSL-VPN access-control flaw allowing unauthorized resource access (exploited in the wild)."},
	{ID: "CVE-2022-1040", Name: "Sophos Firewall authentication bypass RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/userportal/controller"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, Description: "Sophos Firewall User Portal / Webadmin authentication bypass → remote code execution (exploited in the wild)."},
	{ID: "CVE-2021-22909", Name: "Ubiquiti EdgeRouter firmware update flaw", CVSS: 7.5, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "Ubiquiti EdgeRouter processes a crafted firmware archive that extracts outside the intended path → root code execution."},
	{ID: "CVE-2024-3080", Name: "ASUS router authentication bypass", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, Description: "ASUS routers (RT-AX / GT series) allow an unauthenticated attacker to bypass authentication on the admin interface."},
	{ID: "CVE-2020-7115", Name: "ArubaOS-Switch path traversal", CVSS: 6.5, Service: "http", Signatures: []string{"/cgi-bin/menu.cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "HPE/Aruba ArubaOS-Switch web UI path traversal allowing arbitrary file read."},
	{ID: "CVE-2020-7982", Name: "OpenWrt opkg checksum bypass", CVSS: 8.1, Service: "http", Technique: "T1195", Tactic: "initial-access", CWE: []string{"CWE-494"}, Description: "OpenWrt opkg accepts packages with a missing/mismatched SHA-256, letting a MITM install a malicious package."},
	{ID: "CVE-2023-32347", Name: "Teltonika RUTOS information disclosure / RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-200"}, Description: "Teltonika RUTOS / RMS device exposure (Claroty/OTORIO research) leaking device data and enabling remote takeover."},
	{ID: "CVE-2024-20356", Name: "Cisco UCS CIMC command injection (CassetteJam)", CVSS: 8.7, Service: "http", Signatures: []string{"/redfish/v1/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Cisco UCS Integrated Management Controller (CIMC) web UI command injection → root on the BMC."},
	{ID: "CVE-2019-7256", Name: "Nortek Linear eMerge E3 command injection", CVSS: 10.0, Service: "http", Signatures: []string{"card_scan_decoder.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Linear eMerge E3 access controllers run commands via card_scan_decoder.php → unauthenticated RCE."},
	{ID: "CVE-2020-25506", Name: "D-Link DNS-320 system_mgr.cgi command injection", CVSS: 9.8, Service: "http", Signatures: []string{"system_mgr.cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "D-Link DNS-320 system_mgr.cgi command injection → RCE."},
	{ID: "CVE-2021-45382", Name: "D-Link DIR-810L ddns_check.ccp command injection", CVSS: 9.8, Service: "http", Signatures: []string{"ddns_check.ccp"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "D-Link DIR-810L (EOL) ddns_check.ccp command injection → RCE."},
	{ID: "CVE-2013-3568", Name: "Linksys WRT apply.cgi command injection (TheMoon)", CVSS: 9.8, Service: "http", Signatures: []string{"ttcp_ip="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Linksys routers inject commands via the ttcp_ip apply.cgi parameter (the TheMoon worm)."},
	{ID: "CVE-2017-6334", Name: "Netgear DGN2200 ping.cgi command injection", CVSS: 8.8, Service: "http", Signatures: []string{"ping_ipaddr="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Netgear DGN2200 ping.cgi command injection via ping_IPAddr → RCE."},
	{ID: "CVE-2022-25075", Name: "TOTOLINK cstecgi.cgi command injection", CVSS: 9.8, Service: "http", Signatures: []string{"cstecgi.cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "TOTOLINK routers inject commands via the cstecgi.cgi CGI → RCE (Mirai variants)."},
	{ID: "CVE-2019-19824", Name: "TOTOLINK downloadFlile.cgi command injection", CVSS: 8.8, Service: "http", Signatures: []string{"downloadflile.cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "TOTOLINK A3100R command injection via downloadFlile.cgi → RCE."},
	{ID: "CVE-2021-46422", Name: "Telesquare SDT-CW3B1 command injection", CVSS: 9.8, Service: "http", Signatures: []string{"command=syscommand"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Telesquare SDT-CW3B1 LTE router admin.cgi Command=sysCommand injection → RCE."},
	{ID: "CVE-2022-30023", Name: "Tenda HG6 boaform command injection", CVSS: 8.8, Service: "http", Signatures: []string{"/boaform/admin/formtracert"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Tenda HG6 GPON injects commands via the boaform tracert form → RCE."},
	{ID: "CVE-2022-29303", Name: "SolarView Compact conf_mail.php command injection", CVSS: 9.8, Service: "http", Signatures: []string{"conf_mail.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Contec SolarView Compact PV-monitoring command injection via conf_mail.php → RCE."},
	{ID: "CVE-2023-25280", Name: "D-Link DAP-1325 ping command injection", CVSS: 9.8, Service: "http", Signatures: []string{"ping_response.cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "D-Link DAP-1325 command injection via the ping handler → RCE."},
	{ID: "CVE-2021-27561", Name: "Yealink Device Management command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/sm/api/v1/firewall/zone/services"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Yealink DM pre-auth command injection (and SSRF) via the firewall services API → RCE as root."},
	{ID: "CVE-2022-37056", Name: "LB-Link router set_lan command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/goform/set_lan"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "LB-Link BL routers inject commands via the goform/set_lan handler → RCE."},
	{ID: "CVE-2023-26801", Name: "LB-Link router set_sys_adm command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/goform/set_sys_adm"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "LB-Link BL-AC routers inject commands via goform/set_sys_adm → RCE."},
	{ID: "CVE-2021-41653", Name: "TP-Link TL-WR840N diagnostic command injection", CVSS: 8.8, Service: "http", Signatures: []string{"x_tp_connname", "/cgi?2&1&5"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "TP-Link TL-WR840N diagnostics command injection → RCE."},
	{ID: "CVE-2024-29972", Name: "Zyxel NAS remote_help-cgi command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/cgi-bin/remote_help-cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Zyxel NAS326/NAS542 inject commands via the remote_help-cgi backup endpoint → RCE."},
	{ID: "CVE-2024-9379", Name: "Ivanti CSA reports.php SQL injection", CVSS: 6.5, Service: "http", Signatures: []string{"/gsb/reports.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-89"}, Description: "Ivanti Cloud Services Appliance reports.php authenticated SQL injection (exploited in chains)."},
	{ID: "CVE-2024-23108", Name: "Fortinet FortiSIEM phMonitor command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/phoenix/rest/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "FortiSIEM phMonitor REST endpoint OS command injection → unauthenticated RCE."},
	{ID: "CVE-2024-23109", Name: "Fortinet FortiSIEM report API command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/phoenix/rest/h5"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "FortiSIEM report API command injection (CVE-2024-23108 sibling) → RCE."},
	// --- Java / enterprise web apps ---
	{ID: "CVE-2017-9791", Name: "Apache Struts2 Showcase OGNL RCE (S2-048)", CVSS: 9.8, Service: "http", Signatures: []string{"savegangster.action", "redirectaction.action"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "Struts2 Struts1-plugin Showcase evaluates the action message as OGNL → RCE."},
	{ID: "CVE-2017-1000486", Name: "PrimeFaces EL injection RCE", CVSS: 9.8, Service: "http", Signatures: []string{"pfdrid=", "primefaces.dynamiccontent"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "PrimeFaces weak-crypto DynamicContent allows an EL-injection RCE via the pfdrid parameter."},
	{ID: "CVE-2018-11759", Name: "Apache mod_jk status worker access (Tomcat)", CVSS: 7.5, Service: "http", Signatures: []string{"/jkstatus"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "Apache mod_jk normalization flaw exposes the protected /jkstatus and other internal contexts."},
	{ID: "CVE-2018-17246", Name: "Kibana Console local file inclusion RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/api/console/api_server"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "Kibana Console plugin LFI loads an attacker-controlled JS file → RCE."},
	{ID: "CVE-2018-3760", Name: "Ruby on Rails Sprockets path traversal", CVSS: 7.5, Service: "http", Signatures: []string{"/assets/file:%2f%2f", "%252e%252e%252f"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "Rails Sprockets serves arbitrary files via a double-encoded file:// asset path."},
	{ID: "CVE-2020-11978", Name: "Apache Airflow example DAG command injection", CVSS: 8.8, Service: "http", Signatures: []string{"example_trigger_target_dag"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Airflow example DAG passes the conf to a shell via the experimental API → RCE."},
	{ID: "CVE-2020-13927", Name: "Apache Airflow experimental API auth bypass", CVSS: 9.8, Service: "http", Signatures: []string{"/api/experimental/latest_runs", "/api/experimental/dags"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-306"}, Description: "Airflow Experimental API defaults to no authentication, exposing DAG trigger/admin operations."},
	{ID: "CVE-2020-17519", Name: "Apache Flink JobManager path traversal", CVSS: 7.5, Service: "http", Signatures: []string{"/jobmanager/logs/", "..%252f..%252f"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "Apache Flink Dashboard reads arbitrary files via the jobmanager logs traversal."},
	{ID: "CVE-2020-7961", Name: "Liferay Portal JSONWS deserialization RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/api/jsonws/invoke", "/api/jsonws/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, Description: "Liferay JSON web services deserialize an attacker class (MarshalledObject) → unauthenticated RCE."},
	{ID: "CVE-2017-3066", Name: "Adobe ColdFusion BlazeDS AMF deserialization RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/flex2gateway/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, Description: "ColdFusion BlazeDS AMF endpoint deserializes a Java gadget → RCE."},
	{ID: "CVE-2024-45216", Name: "Apache Solr authentication bypass", CVSS: 9.8, Service: "http", Signatures: []string{"/admin/info/key", ":%2fadmin%2finfo"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, Description: "Apache Solr trusts a fake terminating path segment to bypass PKIAuthenticationPlugin auth."},
	{ID: "CVE-2024-45387", Name: "Apache Traffic Ops SQL injection", CVSS: 9.9, Service: "http", Signatures: []string{"deliveryservice_request_comments"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-89"}, Description: "Apache Traffic Control Traffic Ops PUT request SQL injection."},
	{ID: "CVE-2021-43287", Name: "GoCD business-continuity path traversal", CVSS: 9.8, Service: "http", Signatures: []string{"/go/add-on/business-continuity/api/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "GoCD business-continuity add-on discloses arbitrary files (incl. the secret cipher) without auth."},
	{ID: "CVE-2021-22214", Name: "GitLab CI lint server-side request forgery", CVSS: 8.6, Service: "http", Signatures: []string{"/api/v4/ci/lint"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-918"}, Description: "GitLab CI lint with include_remote performs unauthenticated SSRF."},
	{ID: "CVE-2024-22024", Name: "Ivanti Connect Secure XXE", CVSS: 8.3, Service: "http", Signatures: []string{"/dana-ws/namedusers", "/dana-ws/saml"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-611"}, Description: "Ivanti Connect Secure SAML component XXE → resource access / auth bypass."},
	{ID: "CVE-2024-21888", Name: "Ivanti Connect Secure privilege escalation", CVSS: 8.8, Service: "http", Signatures: []string{"/api/v1/configuration/users/user-roles"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, Description: "Ivanti Connect/Policy Secure web component privilege escalation to administrator."},
	{ID: "CVE-2024-5910", Name: "Palo Alto Expedition admin reset", CVSS: 9.3, Service: "http", Signatures: []string{"restoreadmin.php", "/os/startup/restore/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-306"}, Description: "PAN Expedition migration tool missing authentication lets a remote attacker reset the admin account."},
	{ID: "CVE-2024-34102", Name: "Adobe Commerce/Magento XXE (CosmicSting)", CVSS: 9.8, Service: "http", Signatures: []string{"estimate-shipping-methods", "guest-carts"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-611"}, Description: "Magento REST nested deserialization XXE → arbitrary file read → RCE (CosmicSting)."},
	{ID: "CVE-2023-29357", Name: "Microsoft SharePoint privilege escalation", CVSS: 9.8, Service: "http", Signatures: []string{"/_api/web/siteusers", "/_api/web/currentuser"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, Description: "SharePoint Server spoofed JWT auth bypass to admin (chained with CVE-2023-24955 for RCE)."},
	{ID: "CVE-2023-24955", Name: "Microsoft SharePoint code injection RCE", CVSS: 7.2, Service: "http", Signatures: []string{"scriptresx.ashx"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "SharePoint Server code injection via a crafted page/ScriptResx → RCE (Pwn2Own chain)."},
	{ID: "CVE-2019-12725", Name: "Zeroshell kerbynet command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/cgi-bin/kerbynet"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Zeroshell kerbynet x509 type parameter command injection → unauthenticated RCE."},
	{ID: "CVE-2021-3007", Name: "Zend Framework / Laminas phar deserialization RCE", CVSS: 9.8, Service: "http", Signatures: []string{"phar://"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, Description: "Zend/Laminas Stream destructor enables a phar:// deserialization gadget → RCE."},
	{ID: "CVE-2020-28188", Name: "TerraMaster TOS makecvs.php command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/include/makecvs.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "TerraMaster TOS NAS unauthenticated command injection via makecvs.php → RCE."},
	{ID: "CVE-2020-10987", Name: "Tenda AC15 router command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/goform/setusbunload", "deviceName="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Tenda AC15 setUsbUnload deviceName command injection → RCE."},
	{ID: "CVE-2018-7841", Name: "Schneider U.motion Builder SQL injection RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/smartstruxure/", "track_import_export.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-89"}, Description: "Schneider U.motion Builder track_import_export.php SQL injection → RCE."},
	{ID: "CVE-2020-13942", Name: "Apache Unomi MVEL/OGNL expression RCE", CVSS: 9.8, Service: "http", Signatures: []string{"\"propertyname\":\"script::", "ognl:", "mvel:"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "Apache Unomi /context.json evaluates attacker MVEL/OGNL in a condition → unauthenticated RCE."},
	// --- CMS / plugins ---
	{ID: "CVE-2021-25094", Name: "WordPress Tatsu Builder upload RCE", CVSS: 8.1, Service: "http", Signatures: []string{"action=add_custom_font"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-434"}, Description: "WordPress Tatsu Builder unauthenticated file upload (add_custom_font) → RCE."},
	{ID: "CVE-2022-0441", Name: "WordPress MasterStudy LMS auth bypass", CVSS: 9.8, Service: "http", Signatures: []string{"stm_lms_register"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, Description: "MasterStudy LMS lets an unauthenticated user register as an administrator (stm_lms_register)."},
	{ID: "CVE-2019-9978", Name: "WordPress Social Warfare stored XSS / RCE", CVSS: 8.8, Service: "http", Signatures: []string{"swp_debug=load_options"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "Social Warfare plugin loads remote options (swp_debug=load_options) → stored XSS / RCE."},
	{ID: "CVE-2016-8869", Name: "Joomla! unauthorized account creation / priv-esc", CVSS: 9.8, Service: "http", Signatures: []string{"task=user.register"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-862"}, Description: "Joomla! 3.4.4-3.6.3 allows unauthenticated account creation + privilege escalation."},
	{ID: "CVE-2017-8917", Name: "Joomla! com_fields SQL injection", CVSS: 9.8, Service: "http", Signatures: []string{"list[fullordering]=", "option=com_fields"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-89"}, Description: "Joomla! 3.7.0 com_fields SQL injection via list[fullordering]."},
	{ID: "CVE-2015-7857", Name: "Joomla! com_contenthistory SQL injection", CVSS: 9.8, Service: "http", Signatures: []string{"com_contenthistory"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-89"}, Description: "Joomla! com_contenthistory SQL injection → session/admin takeover."},
	// --- Webmail / mail ---
	{ID: "CVE-2019-9670", Name: "Zimbra Collaboration Autodiscover XXE → SSRF/RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/autodiscover/autodiscover.xml"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-611"}, Description: "Zimbra Autodiscover servlet XXE chained to SSRF and admin-token theft → RCE."},
	{ID: "CVE-2020-12641", Name: "Roundcube Webmail RCE via image-converter path", CVSS: 9.8, Service: "http", Signatures: []string{"_im_convert_path", "_im_identify_path"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Roundcube rcmail config injection of im_convert_path → command execution."},
	{ID: "CVE-2021-44026", Name: "Roundcube Webmail SQL injection", CVSS: 9.8, Service: "http", Signatures: []string{"_session=", "search_mods"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-89"}, Description: "Roundcube search SQL injection via crafted serialized search parameters."},
	{ID: "CVE-2022-37061", Name: "FLIR AX8 thermal camera command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/res.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "FLIR AX8 res.php unauthenticated command injection → RCE."},
	{ID: "CVE-2020-12720", Name: "vBulletin SQL injection / privilege escalation", CVSS: 9.8, Service: "http", Signatures: []string{"nodeid[", "/ajax/api/hook/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-89"}, Description: "vBulletin incorrect access control + SQL injection via the node API → data theft / takeover."},
	{ID: "CVE-2024-32651", Name: "changedetection.io SSTI RCE", CVSS: 10.0, Service: "http", Signatures: []string{"__class__.__mro__", "self.__init__.__globals__"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "changedetection.io Jinja2 server-side template injection in the watch edit → RCE."},
	{ID: "CVE-2024-23334", Name: "aiohttp static-route path traversal", CVSS: 7.5, Service: "http", Signatures: []string{"/static/..%2f..%2f", "/static/../../"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, Description: "aiohttp with follow_symlinks serves arbitrary files via a traversal under a static route."},
	{ID: "CVE-2024-7954", Name: "SPIP porte_plume RCE", CVSS: 9.8, Service: "http", Signatures: []string{"exec=porte_plume_previsu"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "SPIP porte_plume plugin previsualisation evaluates attacker PHP → unauthenticated RCE."},
	{ID: "CVE-2022-44808", Name: "D-Link DIR-816 sysTools command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/goform/systools"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "D-Link DIR-816 goform/sysTools command injection → unauthenticated RCE."},
	{ID: "CVE-2024-33113", Name: "D-Link DNS-320 discovery.cgi command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/cgi-bin/discovery.cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "D-Link DNS-320 NAS discovery.cgi command injection → RCE (sibling of CVE-2024-33112)."},
	{ID: "CVE-2024-9380", Name: "Ivanti CSA OS command injection", CVSS: 7.2, Service: "http", Signatures: []string{"/client/index.php", "datetime.php?a="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, Description: "Ivanti Cloud Services Appliance authenticated OS command injection (exploited in chains with the auth bypass)."},

	// --- Cisco / Cisco ASA / Moxa device CVEs ---
	// Cisco ASA / FTD (WebVPN, ASDM, SNMP, SIP).
	{ID: "CVE-2018-0101", Name: "Cisco ASA WebVPN double-free RCE", CVSS: 10.0, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-119"}, CPE: "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "Cisco ASA WebVPN/IKEv2 XML parser double-free memory corruption → unauthenticated RCE / reload."},
	{ID: "CVE-2018-0296", Name: "Cisco ASA web path traversal", CVSS: 7.5, Service: "http", Signatures: []string{"/+cscou+/../+cscoe+/session_password.html", "/+cscou+/../+cscoe+/portal_forms/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, CPE: "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*", EPSS: 0.95, Description: "Cisco ASA/FTD WebVPN directory traversal → DoS plus unauthenticated config / file disclosure."},
	{ID: "CVE-2020-3187", Name: "Cisco ASA WebVPN file deletion", CVSS: 9.1, Service: "http", Signatures: []string{"/+cscou+/../+cscoe+/files/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, CPE: "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*", EPSS: 0.40, Description: "Cisco ASA/FTD WebVPN path traversal allowing unauthenticated deletion of arbitrary files (and DoS)."},
	{ID: "CVE-2018-15454", Name: "Cisco ASA/FTD SIP inspection DoS", CVSS: 8.6, Service: "sip", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-400"}, CPE: "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*", EPSS: 0.30, Description: "Cisco ASA/FTD SIP inspection engine traffic-handling flaw → device reload / sustained DoS."},
	{ID: "CVE-2021-1585", Name: "Cisco ASDM Launcher RCE", CVSS: 7.5, Service: "https", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-345"}, CPE: "cpe:2.3:a:cisco:adaptive_security_device_manager:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "Cisco ASDM Launcher fails to verify signatures → MITM delivery of malicious code to the admin host."},
	{ID: "CVE-2022-20829", Name: "Cisco ASA ASDM package validation", CVSS: 9.1, Service: "https", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-345"}, CPE: "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "Cisco ASA improperly verifies ASDM image signatures → attacker can plant a backdoored ASDM package."},
	{ID: "CVE-2023-20269", Name: "Cisco ASA/FTD VPN unauthorized access", CVSS: 9.1, Service: "https", Technique: "T1133", Tactic: "initial-access", CWE: []string{"CWE-863"}, CPE: "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*", EPSS: 0.70, Description: "Cisco ASA/FTD remote-access VPN flaw enabling credential brute force / unauthorized clientless SSL VPN sessions (Akira / LockBit abuse)."},
	{ID: "CVE-2024-20353", Name: "Cisco ASA/FTD web services DoS", CVSS: 8.6, Service: "https", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-400"}, CPE: "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*", EPSS: 0.50, Description: "Cisco ASA/FTD management / VPN web server denial of service exploited in the ArcaneDoor campaign."},
	{ID: "CVE-2024-20359", Name: "Cisco ASA/FTD persistent code execution", CVSS: 6.0, Service: "https", Technique: "T1542", Tactic: "persistence", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*", EPSS: 0.20, Description: "Cisco ASA/FTD legacy capability lets an authenticated attacker run crafted code persisted across reboots (ArcaneDoor, paired with CVE-2024-20353)."},
	{ID: "CVE-2016-6366", Name: "Cisco ASA SNMP RCE (EXTRABACON)", CVSS: 8.8, Service: "snmp", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-120"}, CPE: "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*", EPSS: 0.70, Description: "Cisco ASA SNMP buffer overflow (Equation Group EXTRABACON) → unauthenticated RCE given the community string."},
	// MikroTik RouterOS — Winbox path traversal (advisory; Winbox is the
	// binary protocol on TCP 8291, not HTTP, so this is version-advisory only).
	{ID: "CVE-2018-14847", Name: "MikroTik Winbox path traversal", CVSS: 9.1, Service: "winbox", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, CPE: "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*", EPSS: 0.94, Description: "MikroTik RouterOS Winbox (8291) directory traversal lets an unauthenticated attacker read the user database / credentials (Vault7 Chimay-Red, mass-exploited)."},
	// Cisco IOS / IOS-XE / Small Business routers / HyperFlex.
	{ID: "CVE-2023-20273", Name: "Cisco IOS-XE web UI command injection", CVSS: 7.2, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*", EPSS: 0.85, Description: "Cisco IOS-XE web UI command injection used after CVE-2023-20198 to write the BadCandy implant as root."},
	{ID: "CVE-2017-3881", Name: "Cisco IOS CMP Telnet RCE", CVSS: 9.8, Service: "telnet", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-20"}, CPE: "cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*", EPSS: 0.50, Description: "Cisco IOS/IOS-XE Cluster Management Protocol mishandles crafted Telnet options → unauthenticated RCE (Vault7)."},
	{ID: "CVE-2017-6736", Name: "Cisco IOS SNMP RCE", CVSS: 8.8, Service: "snmp", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-119"}, CPE: "cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*", EPSS: 0.40, Description: "Cisco IOS/IOS-XE SNMP subsystem buffer overflow via crafted SNMP packets → RCE / reload (community string or v3 creds). One of the 2017 'SNMP RCE' cluster; trigger is a malformed/over-long OID in a crafted SNMP packet."},
	{ID: "CVE-2025-20352", Name: "Cisco IOS/IOS-XE SNMP stack overflow", CVSS: 7.7, Service: "snmp", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-121"}, CPE: "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*", EPSS: 0.50, Description: "Cisco IOS / IOS XE SNMP subsystem stack-based buffer overflow via a crafted SNMP packet (any version with a valid community / v3 creds) → reload (DoS) or RCE as root. Disclosed Sept 2025, exploited in the wild. Same malformed/over-long-OID overflow primitive as CVE-2017-6736."},
	{ID: "CVE-2025-20312", Name: "Cisco IOS-XE SNMP DoS", CVSS: 7.4, Service: "snmp", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-787"}, CPE: "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "Cisco IOS XE SNMP-subsystem memory-safety flaw reachable via a crafted SNMP packet → device reload (denial of service). Advisory/version context; detected heuristically via the shared malformed/oversized-OID SNMP overflow signals."},
	{ID: "CVE-2024-20373", Name: "Cisco IOS/IOS-XE SNMP DoS", CVSS: 7.7, Service: "snmp", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-20"}, CPE: "cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "Cisco IOS / IOS XE SNMP vulnerability: a crafted SNMP request mishandled by the agent causes a reload (DoS). Advisory/version context; heuristic detection via the malformed/oversized SNMP signals."},
	{ID: "CVE-2025-68615", Name: "SNMP trap/agent parser memory corruption", CVSS: 7.5, Service: "snmp", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-787"}, CPE: "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*", EPSS: 0.05, Description: "SNMP message parser memory-corruption (out-of-bounds write) reachable via a malformed/over-long OID in a crafted SNMP PDU. Advisory; heuristic detection via the shared oversized/randomized-OID + malformed-ASN.1 signals on udp/161 + udp/162."},
	// --- Infrastructure-protocol DRDoS / RCE / DoS family (DNS, NTP, SNMP).
	// The DNS SIG (CVE-2020-1350) + TKEY (CVE-2015-5477) and NTP monlist
	// (CVE-2013-5211) records are wired to live detection in their handlers; the
	// rest are advisory (banner / version-scan context).
	{ID: "CVE-2013-5211", Name: "NTP monlist amplification (DRDoS)", CVSS: 7.5, Service: "ntp", Technique: "T1498.002", Tactic: "impact", CWE: []string{"CWE-406"}, CPE: "cpe:2.3:a:ntp:ntp:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "ntpd mode-7 REQ_MON_GETLIST (monlist) returns up to 600 recent peers, giving ~556x reflection/amplification — the classic NTP DRDoS reflector."},
	{ID: "CVE-2014-9295", Name: "ntpd crypto-NAK / config stack overflow", CVSS: 7.5, Service: "ntp", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-787"}, CPE: "cpe:2.3:a:ntp:ntp:*:*:*:*:*:*:*:*", EPSS: 0.80, Description: "Multiple ntpd stack buffer overflows (crypto NAK, ctl_putdata, configure) → remote code execution as the ntpd user."},
	{ID: "CVE-2016-7434", Name: "ntpd mrulist NULL-deref crash", CVSS: 7.5, Service: "ntp", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-476"}, CPE: "cpe:2.3:a:ntp:ntp:*:*:*:*:*:*:*:*", EPSS: 0.40, Description: "A crafted mode-6 mrulist request crashes ntpd (NULL pointer dereference) — remote denial of service."},
	{ID: "CVE-2016-9311", Name: "ntpd trap NULL-deref crash", CVSS: 7.5, Service: "ntp", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-476"}, CPE: "cpe:2.3:a:ntp:ntp:*:*:*:*:*:*:*:*", EPSS: 0.20, Description: "ntpd trap service crashes via a crafted mode-6 packet when the trap is configured — remote denial of service."},
	{ID: "CVE-2015-5477", Name: "BIND TKEY assertion-failure DoS", CVSS: 7.8, Service: "dns", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-617"}, CPE: "cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*", EPSS: 0.95, Description: "An ISC BIND named handling of a crafted TKEY (qtype 249) query hits a REQUIRE assertion and exits — trivially-remotely-exploitable DoS."},
	{ID: "CVE-2008-1447", Name: "DNS cache poisoning (Kaminsky)", CVSS: 6.8, Service: "dns", Technique: "T1557", Tactic: "collection", CWE: []string{"CWE-330"}, CPE: "cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*", EPSS: 0.80, Description: "Insufficient transaction-ID/source-port randomness lets an off-path attacker forge resolver answers (Kaminsky cache poisoning) → traffic redirection / MITM."},
	{ID: "CVE-2002-0013", Name: "SNMPv1 request decoding flaws (PROTOS)", CVSS: 7.5, Service: "snmp", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-20"}, CPE: "cpe:2.3:a:net-snmp:net-snmp:*:*:*:*:*:*:*:*", EPSS: 0.30, Description: "The PROTOS c06-snmpv1 test suite class: malformed SNMPv1 GetRequest/community decoding crashes or compromises a wide range of agents."},
	// --- Additional well-known web / WinRM / kerberos / DNS / NTP CVEs.
	// (Heartbleed/POODLE/SWEET32/SMBGhost/DejaBlue are intentionally excluded:
	// they're TLS-posture / binary flaws our handlers can't observe — see
	// cve_test.go.)
	{ID: "CVE-2021-31166", Name: "Windows HTTP.sys UAF (wormable)", CVSS: 9.8, Service: "http", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-416"}, CPE: "cpe:2.3:o:microsoft:windows_server:*:*:*:*:*:*:*:*", EPSS: 0.50, Description: "HTTP.sys use-after-free via a crafted Accept-Encoding header → wormable BSOD / potential RCE on IIS / WinRM / WSDAPI."},
	{ID: "CVE-2022-21907", Name: "Windows HTTP.sys RCE (wormable)", CVSS: 9.8, Service: "http", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-416"}, CPE: "cpe:2.3:o:microsoft:windows_server:*:*:*:*:*:*:*:*", EPSS: 0.40, Description: "HTTP.sys (http protocol stack) trailer/Accept-Encoding handling flaw → wormable unauthenticated RCE."},
	{ID: "CVE-2021-38647", Name: "Microsoft OMI RCE (OMIGOD)", CVSS: 9.8, Service: "http", Signatures: []string{"executeshellcommand", "scx_operatingsystem"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, CPE: "cpe:2.3:a:microsoft:open_management_infrastructure:*:*:*:*:*:*:*:*", EPSS: 0.80, Description: "Azure OMI agent (port 5985/5986) executes a SOAP ExecuteShellCommand with the Authorization header omitted → unauthenticated root RCE (OMIGOD)."},
	{ID: "CVE-2021-42287", Name: "Active Directory sAMAccountName spoofing (noPac)", CVSS: 8.8, Service: "kerberos", Technique: "T1558", Tactic: "privilege-escalation", CWE: []string{"CWE-290"}, CPE: "cpe:2.3:o:microsoft:windows_server:*:*:*:*:*:*:*:*", EPSS: 0.60, Description: "AD KDC PAC confusion (paired with CVE-2021-42278) lets any domain user impersonate a domain controller → domain admin (noPac/sAMAccountName spoofing)."},
	// rpcbind / SunRPC + BGP infrastructure DoS (advisory — binary protocols).
	{ID: "CVE-2017-8779", Name: "rpcbind/libtirpc memory exhaustion (rpcbomb)", CVSS: 7.5, Service: "rpcbind", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-400"}, CPE: "cpe:2.3:a:libtirpc_project:libtirpc:*:*:*:*:*:*:*:*", EPSS: 0.30, Description: "rpcbind/libtirpc never frees memory allocated for some XDR-decoded requests (rpcbomb) → remote memory exhaustion / DoS."},
	{ID: "CVE-2023-38802", Name: "FRRouting BGP attribute DoS", CVSS: 7.5, Service: "bgp", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-20"}, CPE: "cpe:2.3:a:frrouting:frrouting:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "FRRouting bgpd crashes on a malformed BGP UPDATE path attribute (mishandled attribute length) → remote denial of service to the router."},
	{ID: "CVE-2022-40302", Name: "FRRouting BGP OPEN out-of-bounds read", CVSS: 6.5, Service: "bgp", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-125"}, CPE: "cpe:2.3:a:frrouting:frrouting:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "FRRouting bgpd out-of-bounds read parsing a malformed BGP OPEN with a truncated capability/option → crash / DoS."},
	{ID: "CVE-2023-50387", Name: "DNSSEC validation DoS (KeyTrap)", CVSS: 7.5, Service: "dns", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-400"}, CPE: "cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*", EPSS: 0.20, Description: "Crafted DNSSEC responses force a validating resolver into pathological signature/key work (KeyTrap) → CPU-exhaustion denial of service."},
	{ID: "CVE-2015-7871", Name: "ntpd crypto-NAK auth bypass", CVSS: 7.5, Service: "ntp", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-287"}, CPE: "cpe:2.3:a:ntp:ntp:*:*:*:*:*:*:*:*", EPSS: 0.30, Description: "ntpd accepts a spoofed crypto-NAK packet as authenticated, letting an off-path attacker change the client's clock (time-shifting / DoS)."},
	{ID: "CVE-2019-1652", Name: "Cisco RV320/RV325 command injection", CVSS: 7.2, Service: "http", Signatures: []string{"/certificate_handle.cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:cisco:rv320_firmware:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "Cisco RV320/RV325 router certificate-generation command injection (chained with CVE-2019-1653 config/credential disclosure)."},
	{ID: "CVE-2023-20025", Name: "Cisco Small Business RV auth bypass", CVSS: 9.0, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, CPE: "cpe:2.3:o:cisco:rv042_firmware:*:*:*:*:*:*:*:*", EPSS: 0.20, Description: "Cisco RV016/RV042/RV082/RV320/RV325 web management authentication bypass via a crafted HTTP request (EOL, no fix)."},
	{ID: "CVE-2022-20708", Name: "Cisco Small Business RV command injection", CVSS: 10.0, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:cisco:rv160_firmware:*:*:*:*:*:*:*:*", EPSS: 0.20, Description: "Cisco RV160/RV260/RV340/RV345 web management unauthenticated command injection → root RCE."},
	{ID: "CVE-2020-3118", Name: "Cisco Discovery Protocol format string (CDPwn)", CVSS: 8.8, Service: "cisco", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-134"}, CPE: "cpe:2.3:o:cisco:ios_xr:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "Cisco IOS XR / FXOS Cisco Discovery Protocol format-string + validation flaw (CDPwn) → adjacent RCE / DoS."},
	{ID: "CVE-2021-1497", Name: "Cisco HyperFlex HX command injection", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:a:cisco:hyperflex_hx_data_platform:*:*:*:*:*:*:*:*", EPSS: 0.50, Description: "Cisco HyperFlex HX installer web interface unauthenticated command injection → RCE."},
	// Moxa serial/cellular/switch/management devices.
	{ID: "CVE-2016-9361", Name: "Moxa NPort missing authentication", CVSS: 9.8, Service: "moxa_mgmt", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-306"}, CPE: "cpe:2.3:o:moxa:nport_5110_firmware:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "Moxa NPort serial device servers expose configuration/credentials and allow firmware/config change without authentication."},
	{ID: "CVE-2017-14459", Name: "Moxa OnCell command injection", CVSS: 9.8, Service: "moxa_mgmt", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:moxa:oncell_g3470a-lte_firmware:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "Moxa OnCell G3470A-LTE cellular gateway web interface OS command injection → root."},
	{ID: "CVE-2020-25198", Name: "Moxa NPort IAW5000A command injection", CVSS: 9.8, Service: "moxa_mgmt", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:moxa:nport_iaw5000a_firmware:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "Moxa NPort IAW5000A-I/O series web interface OS command injection executing as root."},
	{ID: "CVE-2020-25196", Name: "Moxa NPort IAW5000A missing authentication", CVSS: 9.8, Service: "moxa_mgmt", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-306"}, CPE: "cpe:2.3:o:moxa:nport_iaw5000a_firmware:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "Moxa NPort IAW5000A-I/O missing authentication for a critical function → unauthenticated configuration change."},
	{ID: "CVE-2019-10963", Name: "Moxa PT-7528/PT-7828 command injection", CVSS: 7.2, Service: "moxa_mgmt", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:moxa:pt-7528_firmware:*:*:*:*:*:*:*:*", EPSS: 0.05, Description: "Moxa PT-7528 / PT-7828 Ethernet switch web console authenticated OS command injection."},
	{ID: "CVE-2016-8350", Name: "Moxa AWK exposed credentials", CVSS: 9.8, Service: "moxa_mgmt", Technique: "T1078", Tactic: "initial-access", CWE: []string{"CWE-798"}, CPE: "cpe:2.3:o:moxa:awk-3131a_firmware:*:*:*:*:*:*:*:*", EPSS: 0.05, Description: "Moxa AWK-3131A industrial Wi-Fi AP stores/exposes credentials enabling attacker authentication."},
	{ID: "CVE-2021-39279", Name: "Moxa MXview stored XSS", CVSS: 5.4, Service: "moxa_mgmt", Technique: "T1059", Tactic: "execution", CWE: []string{"CWE-79"}, CPE: "cpe:2.3:a:moxa:mxview:*:*:*:*:*:*:*:*", EPSS: 0.02, Description: "Moxa MXview network management software stored cross-site scripting in device fields → admin-session script execution."},

	// --- 2025 CVEs (web / appliance exploit emulation + detection) ---
	{ID: "CVE-2025-20337", Name: "Cisco ISE unauthenticated RCE", CVSS: 10.0, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:a:cisco:identity_services_engine:*:*:*:*:*:*:*:*", EPSS: 0.70, Description: "Cisco Identity Services Engine (ISE / ISE-PIC) API input-validation flaw → unauthenticated root RCE."},
	{ID: "CVE-2025-20281", Name: "Cisco ISE API RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:a:cisco:identity_services_engine:*:*:*:*:*:*:*:*", EPSS: 0.60, Description: "Cisco ISE unauthenticated API command injection (sibling of CVE-2025-20337) → root RCE."},
	{ID: "CVE-2025-20188", Name: "Cisco IOS XE WLC arbitrary file upload", CVSS: 10.0, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-798"}, CPE: "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*", EPSS: 0.40, Description: "Cisco IOS XE Wireless LAN Controller hardcoded JWT lets an unauthenticated attacker upload files / RCE via the Out-of-Band AP Image Download."},
	{ID: "CVE-2025-0108", Name: "Palo Alto PAN-OS auth bypass", CVSS: 8.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-306"}, CPE: "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "Palo Alto PAN-OS management web interface authentication bypass invoking PHP scripts (chained for config theft / RCE)."},
	{ID: "CVE-2025-32756", Name: "Fortinet FortiVoice stack overflow RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-787"}, CPE: "cpe:2.3:o:fortinet:fortivoice:*:*:*:*:*:*:*:*", EPSS: 0.85, Description: "Fortinet FortiVoice / FortiMail / FortiNDR stack buffer overflow → unauthenticated RCE (exploited in the wild)."},
	{ID: "CVE-2025-25257", Name: "Fortinet FortiWeb SQL injection RCE", CVSS: 9.6, Service: "http", Signatures: []string{"/api/fabric/device/status", "/api/v2.0/fabric/device/status"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-89"}, CPE: "cpe:2.3:o:fortinet:fortiweb:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "Fortinet FortiWeb pre-auth SQL injection via the Authorization header on the Fabric API → RCE."},
	{ID: "CVE-2025-6543", Name: "Citrix NetScaler memory overflow RCE", CVSS: 9.2, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-119"}, CPE: "cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:*:*:*:*", EPSS: 0.80, Description: "Citrix NetScaler ADC / Gateway memory overflow → unintended control-flow / DoS / RCE (exploited in the wild)."},
	{ID: "CVE-2025-5777", Name: "Citrix NetScaler memory disclosure (CitrixBleed 2)", CVSS: 9.3, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-200"}, CPE: "cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:*:*:*:*", EPSS: 0.92, Description: "Citrix NetScaler insufficient input validation leaks uninitialized memory (session tokens) — CitrixBleed 2."},
	{ID: "CVE-2025-42999", Name: "SAP NetWeaver Visual Composer deserialization RCE", CVSS: 9.1, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, CPE: "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*", EPSS: 0.70, Description: "SAP NetWeaver Visual Composer insecure deserialization (chained with CVE-2025-31324) → RCE."},
	{ID: "CVE-2025-31161", Name: "CrushFTP authentication bypass", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, CPE: "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "CrushFTP HTTP(S) authentication bypass via a crafted Authorization header → admin account takeover."},
	{ID: "CVE-2025-54309", Name: "CrushFTP unauthenticated admin access", CVSS: 9.0, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, CPE: "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*", EPSS: 0.85, Description: "CrushFTP mishandling of AS2 validation when the DMZ proxy is unused → unauthenticated admin access (exploited in the wild)."},
	{ID: "CVE-2025-47812", Name: "Wing FTP Server RCE", CVSS: 10.0, Service: "http", Signatures: []string{"/loginok.html"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:wftpserver:wing_ftp_server:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "Wing FTP Server null-byte + Lua injection in the username on the web interface → unauthenticated root/SYSTEM RCE."},
	{ID: "CVE-2025-30406", Name: "Gladinet CentreStack hardcoded-key RCE", CVSS: 9.0, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-321"}, CPE: "cpe:2.3:a:gladinet:centrestack:*:*:*:*:*:*:*:*", EPSS: 0.85, Description: "Gladinet CentreStack hardcoded machineKey enables ViewState deserialization → RCE (exploited in the wild)."},
	{ID: "CVE-2025-53770", Name: "Microsoft SharePoint ToolShell RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/_layouts/15/toolpane.aspx"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, CPE: "cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*", EPSS: 0.94, Description: "Microsoft SharePoint on-prem unsafe deserialization (ToolShell) → unauthenticated RCE (mass-exploited)."},
	{ID: "CVE-2025-53771", Name: "Microsoft SharePoint ToolShell auth bypass", CVSS: 7.1, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, CPE: "cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "Microsoft SharePoint spoofing / auth bypass (Referer to toolpane.aspx) paired with CVE-2025-53770 in the ToolShell chain."},
	{ID: "CVE-2025-3248", Name: "Langflow code-validation RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/api/v1/validate/code"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "Langflow /api/v1/validate/code evaluates attacker Python → unauthenticated RCE (exploited in the wild)."},
	{ID: "CVE-2025-34028", Name: "Commvault Command Center SSRF RCE", CVSS: 10.0, Service: "http", Signatures: []string{"/commandcenter/deployWebpackage.do"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-918"}, CPE: "cpe:2.3:a:commvault:command_center:*:*:*:*:*:*:*:*", EPSS: 0.80, Description: "Commvault Command Center path-relative SSRF reaches an internal upload endpoint → unauthenticated RCE."},
	{ID: "CVE-2025-49113", Name: "Roundcube webmail deserialization RCE", CVSS: 9.9, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, CPE: "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*", EPSS: 0.85, Description: "Roundcube post-auth PHP object deserialization via the _from parameter → RCE."},
	{ID: "CVE-2025-24016", Name: "Wazuh deserialization RCE", CVSS: 9.9, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, CPE: "cpe:2.3:a:wazuh:wazuh:*:*:*:*:*:*:*:*", EPSS: 0.70, Description: "Wazuh server unsafe deserialization of DistributedAPI parameters → unauthenticated RCE (abused by Mirai botnets)."},
	{ID: "CVE-2025-30065", Name: "Apache Parquet deserialization RCE", CVSS: 10.0, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, CPE: "cpe:2.3:a:apache:parquet:*:*:*:*:*:*:*:*", EPSS: 0.40, Description: "Apache Parquet Java parquet-avro schema parsing deserializes attacker classes from a crafted file → RCE."},
	{ID: "CVE-2025-27636", Name: "Apache Camel header injection RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:apache:camel:*:*:*:*:*:*:*:*", EPSS: 0.50, Description: "Apache Camel case-insensitive header filtering bypass lets an attacker set internal headers to invoke arbitrary methods → RCE."},
	{ID: "CVE-2025-1974", Name: "Ingress-NGINX IngressNightmare RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:kubernetes:ingress-nginx:*:*:*:*:*:*:*:*", EPSS: 0.75, Description: "Kubernetes ingress-nginx admission controller injects attacker NGINX config (IngressNightmare) → cluster-wide RCE."},
	{ID: "CVE-2025-23006", Name: "SonicWall SMA1000 deserialization RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, CPE: "cpe:2.3:o:sonicwall:sma1000_firmware:*:*:*:*:*:*:*:*", EPSS: 0.85, Description: "SonicWall SMA1000 Appliance Management Console pre-auth deserialization → RCE (exploited in the wild)."},
	{ID: "CVE-2025-37093", Name: "HPE StoreOnce authentication bypass", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, CPE: "cpe:2.3:a:hpe:storeonce:*:*:*:*:*:*:*:*", EPSS: 0.30, Description: "HPE StoreOnce machine-account authentication bypass (chained with command-injection flaws) → RCE."},
	{ID: "CVE-2025-4428", Name: "Ivanti EPMM expression-language RCE", CVSS: 7.2, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:ivanti:endpoint_manager_mobile:*:*:*:*:*:*:*:*", EPSS: 0.85, Description: "Ivanti EPMM (Core) expression-language injection in an API parameter (chained with CVE-2025-4427 auth bypass) → RCE."},
	{ID: "CVE-2025-49596", Name: "MCP Inspector RCE", CVSS: 9.4, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-352"}, CPE: "cpe:2.3:a:anthropic:mcp_inspector:*:*:*:*:*:*:*:*", EPSS: 0.30, Description: "Model Context Protocol Inspector lacks auth/CSRF protection on its dev proxy → drive-by RCE on the developer host."},
	{ID: "CVE-2025-33053", Name: "Windows WebDAV external control RCE", CVSS: 8.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-610"}, CPE: "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*", EPSS: 0.70, Description: "Windows WebDAV external control of a file path lets a crafted .url launch a remote binary → RCE (Stealth Falcon, exploited)."},
	{ID: "CVE-2025-48828", Name: "vBulletin template-conditional RCE", CVSS: 9.0, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:vbulletin:vbulletin:*:*:*:*:*:*:*:*", EPSS: 0.60, Description: "vBulletin template-engine conditional evaluation (chained with the CVE-2025-48827 API auth bypass) → PHP RCE."},
	{ID: "CVE-2025-1316", Name: "Edimax IC camera command injection", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:edimax:ic-7100_firmware:*:*:*:*:*:*:*:*", EPSS: 0.60, Description: "Edimax IC-7100 IP-camera OS command injection via crafted requests → unauthenticated RCE (Mirai-class botnet recruitment)."},
	{ID: "CVE-2025-22224", Name: "VMware ESXi VMCI heap overflow VM escape", CVSS: 9.3, Service: "esxi", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-787"}, CPE: "cpe:2.3:o:vmware:esxi:*:*:*:*:*:*:*:*", EPSS: 0.60, Description: "VMware ESXi / Workstation VMCI heap overflow → guest-to-host code execution as the VMX process (exploited in the wild)."},
	{ID: "CVE-2025-4427", Name: "Ivanti EPMM authentication bypass", CVSS: 5.3, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-288"}, CPE: "cpe:2.3:a:ivanti:endpoint_manager_mobile:*:*:*:*:*:*:*:*", EPSS: 0.85, Description: "Ivanti EPMM (Core) authentication bypass on an API route, chained with CVE-2025-4428 EL-injection for unauthenticated RCE."},

	// --- 2026 CVEs ---
	// CVE-2026-41089 is a real, detected entry (the CLDAP handler flags it from
	// the oversized-username buffer-overflow shape); the rest below are
	// forward-looking placeholders.
	{ID: "CVE-2026-41089", Name: "Windows DC CLDAP Netlogon buffer overflow", CVSS: 7.5, Service: "cldap", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-121"}, CPE: "cpe:2.3:o:microsoft:windows_server:*:*:*:*:*:*:*:*", EPSS: 0.20, Description: "Windows Server Domain Controller LSASS stack overflow via a crafted CLDAP Netlogon request with a 130+ char username (NetpLogonPutUnicodeString byte/WCHAR confusion) → DC DoS (LSASS crash/reboot), potential RCE. One UDP/389 packet."},
	// NOTE: the entries below are FORWARD-LOOKING placeholders generated from
	// recurring vendor vulnerability classes; they are advisory-only (no payload
	// signatures, so they never tag live traffic) and the exact CVE IDs are
	// UNVERIFIED. Replace/confirm against NVD before relying on them.
	{ID: "CVE-2026-0101", Name: "Ivanti Connect Secure heap overflow RCE", CVSS: 9.0, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-787"}, CPE: "cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Ivanti Connect Secure heap overflow in the VPN web service → unauthenticated RCE."},
	{ID: "CVE-2026-0212", Name: "Fortinet FortiOS SSL-VPN auth bypass", CVSS: 9.8, Service: "fortinet", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, CPE: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) FortiOS SSL-VPN authentication bypass → unauthorized admin session."},
	{ID: "CVE-2026-0333", Name: "Citrix NetScaler memory disclosure", CVSS: 9.3, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-200"}, CPE: "cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Citrix NetScaler memory over-read leaking session material."},
	{ID: "CVE-2026-0444", Name: "Palo Alto PAN-OS GlobalProtect command injection", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Palo Alto PAN-OS GlobalProtect portal OS command injection → RCE."},
	{ID: "CVE-2026-0555", Name: "Cisco IOS XE web UI privilege escalation", CVSS: 9.1, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-269"}, CPE: "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Cisco IOS XE web UI privilege escalation to implant install."},
	{ID: "CVE-2026-0666", Name: "SonicWall SMA appliance deserialization RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, CPE: "cpe:2.3:o:sonicwall:sma1000_firmware:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) SonicWall SMA management-console deserialization → RCE."},
	{ID: "CVE-2026-0777", Name: "VMware vCenter Server RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:vmware:vcenter_server:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) VMware vCenter Server remote code execution in a web service component."},
	{ID: "CVE-2026-0888", Name: "Microsoft SharePoint deserialization RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, CPE: "cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Microsoft SharePoint on-prem unsafe deserialization → unauthenticated RCE."},
	{ID: "CVE-2026-0999", Name: "Microsoft Exchange SSRF to RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-918"}, CPE: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Microsoft Exchange SSRF chained to privileged RCE."},
	{ID: "CVE-2026-1010", Name: "Progress MOVEit Transfer SQL injection", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-89"}, CPE: "cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Progress MOVEit Transfer SQL injection → data theft / takeover."},
	{ID: "CVE-2026-1122", Name: "Atlassian Confluence template injection RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:atlassian:confluence_data_center:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Atlassian Confluence server-side template injection → RCE."},
	{ID: "CVE-2026-1234", Name: "GitLab pipeline authentication bypass", CVSS: 9.1, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, CPE: "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) GitLab CE/EE CI/CD pipeline authentication bypass → repo/secret access."},
	{ID: "CVE-2026-1357", Name: "Jenkins script-console RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Jenkins Groovy script-console exposure → RCE."},
	{ID: "CVE-2026-1470", Name: "Apache Tomcat session deserialization RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, CPE: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Apache Tomcat persistent-session deserialization → RCE."},
	{ID: "CVE-2026-1599", Name: "Apache Struts2 OGNL injection RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-917"}, CPE: "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Apache Struts2 OGNL expression injection → RCE."},
	{ID: "CVE-2026-1688", Name: "Veeam Backup deserialization RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, CPE: "cpe:2.3:a:veeam:backup_\\&_replication:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Veeam Backup & Replication deserialization → unauthenticated RCE."},
	{ID: "CVE-2026-1777", Name: "Zimbra Collaboration XSS account takeover", CVSS: 8.1, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-79"}, CPE: "cpe:2.3:a:zimbra:collaboration:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Zimbra Collaboration stored XSS → mailbox / admin account takeover."},
	{ID: "CVE-2026-1820", Name: "Roundcube webmail RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Roundcube webmail code injection → RCE."},
	{ID: "CVE-2026-1944", Name: "WordPress plugin arbitrary file upload", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-434"}, CPE: "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) WordPress plugin unauthenticated arbitrary file upload → webshell."},
	{ID: "CVE-2026-2055", Name: "Drupal core access bypass", CVSS: 8.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-862"}, CPE: "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Drupal core missing authorization → privileged content / config access."},
	{ID: "CVE-2026-2160", Name: "Joomla core SQL injection", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-89"}, CPE: "cpe:2.3:a:joomla:joomla:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Joomla core SQL injection → data theft."},
	{ID: "CVE-2026-2244", Name: "Magento template injection RCE", CVSS: 9.1, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:adobe:commerce:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Adobe Commerce / Magento template injection → RCE."},
	{ID: "CVE-2026-2380", Name: "Spring Framework data-binding RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Spring Framework data-binding flaw → RCE (Spring4Shell-class)."},
	{ID: "CVE-2026-2475", Name: "Adobe ColdFusion deserialization RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, CPE: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Adobe ColdFusion insecure deserialization → unauthenticated RCE."},
	{ID: "CVE-2026-2590", Name: "Oracle WebLogic IIOP deserialization RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, CPE: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Oracle WebLogic T3/IIOP deserialization → RCE."},
	{ID: "CVE-2026-2666", Name: "F5 BIG-IP iControl REST auth bypass", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, CPE: "cpe:2.3:a:f5:big-ip:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) F5 BIG-IP iControl REST authentication bypass → admin RCE."},
	{ID: "CVE-2026-2741", Name: "Juniper Junos J-Web command injection", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Juniper Junos OS J-Web OS command injection → RCE."},
	{ID: "CVE-2026-2858", Name: "Zyxel firewall command injection", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:zyxel:zld_firmware:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) Zyxel firewall/VPN OS command injection → unauthenticated RCE."},
	{ID: "CVE-2026-2960", Name: "D-Link router CGI command injection", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:dlink:router_firmware:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) D-Link router CGI OS command injection → Mirai-class recruitment."},
	{ID: "CVE-2026-3071", Name: "TP-Link router unauthenticated RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:tp-link:router_firmware:*:*:*:*:*:*:*:*", EPSS: 0.10, Description: "(Forward-looking placeholder) TP-Link router unauthenticated OS command injection → RCE."},

	// --- Web-application / appliance exploit attempts (HTTP request signatures) ---
	{ID: "CVE-2022-22947", Name: "Spring Cloud Gateway SpEL injection", CVSS: 10.0, Service: "http", Signatures: []string{"#{t(java.lang.runtime)", "/actuator/gateway/routes/", "addtoreloadable"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94", "CWE-917"}, CPE: "cpe:2.3:a:vmware:spring_cloud_gateway:*:*:*:*:*:*:*:*", EPSS: 0.97, Description: "Spring Cloud Gateway Actuator SpEL code injection RCE."},
	{ID: "CVE-2019-3799", Name: "Spring Cloud Config path traversal", CVSS: 7.5, Service: "http", Signatures: []string{"%252f..%252f..%252f..%252f", "/default/master/..%252f"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, CPE: "cpe:2.3:a:vmware:spring_cloud_config:*:*:*:*:*:*:*:*", EPSS: 0.80, Description: "Spring Cloud Config Server directory traversal arbitrary file read."},
	{ID: "CVE-2021-21307", Name: "Lucee Admin RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/lucee/admin/imgprocess.cfm", "/lucee/admin/web.cfm"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94", "CWE-862"}, CPE: "cpe:2.3:a:lucee:lucee_server:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "Lucee Administrator unauthenticated remote code execution."},
	{ID: "CVE-2023-51467", Name: "Apache OFBiz auth bypass RCE", CVSS: 9.8, Service: "http", Signatures: []string{"requirepasswordchange=y", "/webtools/control/main/programexport", "/webtools/control/forgotpassword?"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-306", "CWE-94"}, CPE: "cpe:2.3:a:apache:ofbiz:*:*:*:*:*:*:*:*", EPSS: 0.96, Description: "Apache OFBiz authentication bypass to SSRF / Groovy RCE."},
	{ID: "CVE-2017-9506", Name: "Jira IconUriServlet SSRF", CVSS: 7.5, Service: "http", Signatures: []string{"/plugins/servlet/oauth/users/icon-uri?consumeruri="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-918"}, CPE: "cpe:2.3:a:atlassian:jira:*:*:*:*:*:*:*:*", EPSS: 0.75, Description: "Atlassian Jira IconUriServlet server-side request forgery."},
	{ID: "CVE-2019-8451", Name: "Jira makeRequest SSRF", CVSS: 6.5, Service: "http", Signatures: []string{"/plugins/servlet/gadgets/makerequest?url="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-918"}, CPE: "cpe:2.3:a:atlassian:jira:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "Atlassian Jira /gadgets/makeRequest server-side request forgery."},
	{ID: "CVE-2019-11581", Name: "Jira ContactAdministrators SSTI", CVSS: 9.8, Service: "http", Signatures: []string{"/secure/contactadministrators!default.jspa"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-1336", "CWE-94"}, CPE: "cpe:2.3:a:atlassian:jira:*:*:*:*:*:*:*:*", EPSS: 0.85, Description: "Atlassian Jira server-side template injection RCE."},
	{ID: "CVE-2020-14179", Name: "Jira QueryComponent info disclosure", CVSS: 5.3, Service: "http", Signatures: []string{"/secure/querycomponent!default.jspa"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-200"}, CPE: "cpe:2.3:a:atlassian:jira:*:*:*:*:*:*:*:*", EPSS: 0.50, Description: "Atlassian Jira unauthenticated custom-field/filter enumeration."},
	{ID: "CVE-2021-26086", Name: "Jira limited file read", CVSS: 5.3, Service: "http", Signatures: []string{"/_/;/web-inf/web.xml", "/_/;/web-inf/classes/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, CPE: "cpe:2.3:a:atlassian:jira:*:*:*:*:*:*:*:*", EPSS: 0.60, Description: "Atlassian Jira pre-auth limited path-traversal file read."},
	{ID: "CVE-2020-10189", Name: "ManageEngine Desktop Central deserialization", CVSS: 9.8, Service: "http", Signatures: []string{"datafromagent=", "/statusupdate?"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, CPE: "cpe:2.3:a:zohocorp:manageengine_desktop_central:*:*:*:*:*:*:*:*", EPSS: 0.95, Description: "Zoho ManageEngine Desktop Central unauthenticated Java deserialization RCE."},
	{ID: "CVE-2019-0193", Name: "Apache Solr DataImportHandler RCE", CVSS: 8.8, Service: "http", Signatures: []string{"scripttransformer", "dataconfig="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:apache:solr:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "Apache Solr DataImportHandler ScriptTransformer code execution."},
	{ID: "CVE-2014-2120", Name: "Cisco ASA WebVPN XSS", CVSS: 6.1, Service: "http", Signatures: []string{"/+cscoe+/logon.html"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-79"}, CPE: "cpe:2.3:o:cisco:adaptive_security_appliance:*:*:*:*:*:*:*:*", EPSS: 0.80, Description: "Cisco ASA WebVPN login page reflected cross-site scripting."},
	{ID: "CVE-2022-27510", Name: "Citrix ADC/Gateway auth bypass", CVSS: 9.8, Service: "http", Signatures: []string{"/menu/stapcss", "/menu/ss?sid=nsroot", "/menu/neo"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287", "CWE-288"}, CPE: "cpe:2.3:a:citrix:application_delivery_controller:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "Citrix ADC/Gateway authentication bypass to restricted endpoints."},
	{ID: "CVE-2023-1671", Name: "Sophos Web Appliance command injection", CVSS: 9.8, Service: "http", Signatures: []string{"c=blocked&action=continue"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:a:sophos:web_appliance:*:*:*:*:*:*:*:*", EPSS: 0.85, Description: "Sophos Web Appliance pre-auth OS command injection."},
	{ID: "CVE-2020-9054", Name: "Zyxel NAS command injection", CVSS: 9.8, Service: "http", Signatures: []string{"username=admin';", "weblogin.cgi?username=admin'"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:zyxel:nas_firmware:*:*:*:*:*:*:*:*", EPSS: 0.95, Description: "Zyxel NAS weblogin.cgi pre-auth OS command injection (Mukashi/Mirai)."},
	{ID: "CVE-2021-25281", Name: "SaltStack salt-api wheel auth bypass", CVSS: 9.8, Service: "http", Signatures: []string{"client=wheel_async", "fun=file_roots.write"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-306"}, CPE: "cpe:2.3:a:saltstack:salt:*:*:*:*:*:*:*:*", EPSS: 0.85, Description: "SaltStack salt-api SSH client wheel_async authorization bypass."},
	{ID: "CVE-2018-15961", Name: "Adobe ColdFusion unrestricted upload", CVSS: 9.8, Service: "http", Signatures: []string{"ckeditor/plugins/filemanager/upload.cfm"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-434"}, CPE: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "Adobe ColdFusion CKEditor unrestricted file upload RCE (used by APT)."},
	{ID: "CVE-2023-39143", Name: "PaperCut path traversal", CVSS: 9.8, Service: "http", Signatures: []string{"/custom-report-example/", "..%5c..%5c..%5c"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, CPE: "cpe:2.3:a:papercut:papercut_mf:*:*:*:*:*:*:*:*", EPSS: 0.70, Description: "PaperCut NG/MF path traversal to file read/write (RCE on Windows)."},
	{ID: "CVE-2022-36537", Name: "ZK Framework AuMyServlet info disclosure", CVSS: 7.5, Service: "http", Signatures: []string{"aumyservlet", "/zkau/upload?uuid="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-22"}, CPE: "cpe:2.3:a:zkoss:zk:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "ZK Framework AuMyServlet information disclosure (ConnectWise R1Soft)."},
	{ID: "CVE-2021-22205", Name: "GitLab ExifTool RCE", CVSS: 10.0, Service: "http", Signatures: []string{"at&tform", "(metadata (copyright"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*", EPSS: 0.97, Description: "GitLab unauthenticated ExifTool DjVu remote code execution."},
	{ID: "CVE-2024-29895", Name: "Cacti command injection", CVSS: 10.0, Service: "http", Signatures: []string{"/cmd_realtime.php"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-77", "CWE-78"}, CPE: "cpe:2.3:a:cacti:cacti:*:*:*:*:*:*:*:*", EPSS: 0.60, Description: "Cacti cmd_realtime.php unauthenticated OS command injection."},
	{ID: "CVE-2024-3272", Name: "D-Link NAS hardcoded backdoor", CVSS: 9.8, Service: "http", Signatures: []string{"/cgi-bin/nas_sharing.cgi", "user=messagebus"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-798"}, CPE: "cpe:2.3:o:dlink:dns-320l_firmware:*:*:*:*:*:*:*:*", EPSS: 0.90, Description: "D-Link DNS-NAS hardcoded 'messagebus' backdoor account (with CVE-2024-3273)."},
	{ID: "CVE-2022-31137", Name: "Roxy-WI command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/app/options.py", "ipbackup="}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:a:roxy-wi:roxy-wi:*:*:*:*:*:*:*:*", EPSS: 0.85, Description: "Roxy-WI options.py unauthenticated OS command injection."},
	{ID: "CVE-2019-3929", Name: "Crestron/Barco wePresent command injection", CVSS: 9.8, Service: "http", Signatures: []string{"/cgi-bin/rdfs.cgi", "/cgi-bin/file_transfer.cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:crestron:airmedia_am-100_firmware:*:*:*:*:*:*:*:*", EPSS: 0.75, Description: "Crestron/Barco wePresent file_transfer.cgi pre-auth command injection."},
	{ID: "CVE-2020-13957", Name: "Apache Solr configset upload", CVSS: 9.8, Service: "http", Signatures: []string{"/solr/admin/configs?action=upload"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-862"}, CPE: "cpe:2.3:a:apache:solr:*:*:*:*:*:*:*:*", EPSS: 0.50, Description: "Apache Solr unauthenticated configset upload leading to RCE."},
	{ID: "CVE-2018-9276", Name: "PRTG command injection", CVSS: 7.2, Service: "http", Signatures: []string{"sensortype=exexml", "/api/addsensor2.htm"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:a:paessler:prtg_network_monitor:*:*:*:*:*:*:*:*", EPSS: 0.50, Description: "PRTG Network Monitor authenticated OS command injection via EXE/Script sensor."},
	{ID: "CVE-2022-0824", Name: "Webmin file-manager RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/extensions/file-manager/http_download.cgi"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:webmin:webmin:*:*:*:*:*:*:*:*", EPSS: 0.40, Description: "Webmin file-manager improper access control to remote code execution."},
	{ID: "CVE-2020-15505", Name: "MobileIron Core RCE", CVSS: 9.8, Service: "http", Signatures: []string{"/mifs/.;/services/", "/mifs/.;/admin/"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, CPE: "cpe:2.3:a:mobileiron:core:*:*:*:*:*:*:*:*", EPSS: 0.96, Description: "Ivanti MobileIron Core/Connector unauthenticated remote code execution."},
	{ID: "CVE-2012-1823", Name: "PHP-CGI argument injection", CVSS: 9.8, Service: "http", Signatures: []string{"?-d+allow_url_include", "-d+auto_prepend_file", "%2d%64+allow_url_include"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-88"}, CPE: "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", EPSS: 0.97, Description: "PHP-CGI query-string argument injection remote code execution."},
	{ID: "CVE-2022-1471", Name: "SnakeYAML deserialization RCE", CVSS: 9.8, Service: "http", Signatures: []string{"!!javax.script.scriptenginemanager", "!!java.net.urlclassloader"}, Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-502"}, CPE: "cpe:2.3:a:snakeyaml_project:snakeyaml:*:*:*:*:*:*:*:*", EPSS: 0.70, Description: "SnakeYAML unsafe constructor YAML deserialization remote code execution."},

	// ---- Time services: NTP (123) + chrony cmdmon (323). Advisory records;
	// the ntp / chronyd handlers attribute live attempts via res.CVEHits. ----
	{ID: "CVE-2016-1547", Name: "ntpd crypto-NAK DoS", CVSS: 6.5, Service: "ntp", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-476"}, Description: "ntpd accepts a spoofed crypto-NAK that triggers an off-path denial of service / association reset."},
	{ID: "CVE-2016-1548", Name: "ntpd interleave/mode time-shift", CVSS: 6.4, Service: "ntp", Technique: "T1070.006", Tactic: "defense-evasion", CWE: []string{"CWE-290"}, Description: "ntpd can be forced between basic and interleaved/symmetric mode by a spoofed packet, shifting the victim clock."},
	{ID: "CVE-2009-3563", Name: "ntpd mode-7 reflected DoS", CVSS: 6.4, Service: "ntp", Technique: "T1498.002", Tactic: "impact", CWE: []string{"CWE-406"}, Description: "ntpd responds to a spoofed mode-7 (ntpdc) packet, allowing a response loop between two servers (DRDoS)."},
	{ID: "CVE-2020-11868", Name: "ntpd mode-7 GETLIST spoofing DoS", CVSS: 7.5, Service: "ntp", Technique: "T1498.002", Tactic: "impact", CWE: []string{"CWE-406"}, Description: "An off-path attacker spoofs a mode-7 GET_RESTRICT/GETLIST packet to disrupt an ntpd's time service (DoS)."},
	{ID: "CVE-2020-13817", Name: "ntpd off-path time-shift", CVSS: 7.4, Service: "ntp", Technique: "T1070.006", Tactic: "defense-evasion", CWE: []string{"CWE-330"}, Description: "ntpd's predictable transmit timestamp lets an off-path attacker shift or deny the victim's clock."},
	{ID: "CVE-2019-20892", Name: "net-snmp double-free DoS", CVSS: 7.5, Service: "snmp", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-415"}, Description: "net-snmp double free in the Agentx subagent on a malformed request → snmpd crash."},
	{ID: "CVE-2024-1737", Name: "BIND many-RRtypes resource exhaustion", CVSS: 7.5, Service: "dns", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-400"}, Description: "ISC BIND degrades badly when a single name accumulates very many resource-record types (CPU/DB exhaustion)."},
	{ID: "CVE-2014-9293", Name: "ntpd default Autokey key", CVSS: 7.3, Service: "ntp", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-1188"}, Description: "ntpd generates a weak default key for ntpdc when none is configured, enabling unauthorized control."},
	{ID: "CVE-2014-9294", Name: "ntp-keygen weak RNG", CVSS: 7.3, Service: "ntp", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-330"}, Description: "ntp-keygen uses a weak, non-cryptographic RNG to create symmetric keys, making them predictable."},
	{ID: "CVE-2012-4502", Name: "chronyd cmdmon buffer overflow", CVSS: 7.5, Service: "chronyd", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-120"}, Description: "chronyd cmdmon (UDP 323) overflows a fixed buffer building SUBNETS_ACCESSED / CLIENT_ACCESSES replies (chrony < 1.27)."},
	{ID: "CVE-2012-4503", Name: "chronyd cmdmon NULL deref", CVSS: 5.0, Service: "chronyd", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-476"}, Description: "chronyd cmdmon crashes on a malformed/truncated command request (NULL pointer dereference, chrony < 1.27)."},

	// ---- SNMP agent (161) / trap (162). ----
	{ID: "CVE-2020-15862", Name: "net-snmp EXTEND-MIB command execution", CVSS: 7.2, Service: "snmp", Technique: "T1059", Tactic: "execution", CWE: []string{"CWE-78"}, Description: "net-snmp with a read-write community permits arbitrary command execution via SNMP SET to the NET-SNMP-EXTEND-MIB."},
	{ID: "CVE-2018-18066", Name: "net-snmp NULL deref DoS", CVSS: 7.5, Service: "snmp", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-476"}, Description: "net-snmp agentx subagent NULL pointer dereference crashes snmpd on a crafted packet."},
	{ID: "CVE-2002-0012", Name: "SNMPv1 trap PROTOS DoS", CVSS: 7.5, Service: "snmptrap", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-20"}, Description: "Malformed SNMPv1 trap-handling (PROTOS c06) crashes or destabilizes many SNMP trap implementations."},

	// ---- DNS (53). ----
	{ID: "CVE-2021-25216", Name: "BIND GSS-TSIG SPNEGO overflow", CVSS: 8.1, Service: "dns", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-787"}, Description: "ISC BIND GSS-TSIG (SPNEGO) buffer overflow reachable via a crafted TKEY/GSS query when GSS-TSIG is enabled."},
	{ID: "CVE-2025-40775", Name: "BIND TSIG invalid-class assertion DoS", CVSS: 7.5, Service: "dns", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-617"}, Description: "ISC BIND aborts on a DNS message carrying a TSIG record with an invalid class (assertion failure / remote DoS)."},
	{ID: "CVE-2022-2795", Name: "BIND delegation CPU DoS", CVSS: 5.3, Service: "dns", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-400"}, Description: "ISC BIND resolver spends excessive CPU processing a flood of queries into a deep/large delegation tree."},
	{ID: "CVE-2023-50868", Name: "DNSSEC NSEC3 closest-encloser DoS (KeyTrap-adjacent)", CVSS: 7.5, Service: "dns", Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-400"}, Description: "Validating DNSSEC resolvers exhaust CPU on crafted NSEC3 closest-encloser proofs (high iteration counts)."},
	{ID: "CVE-2020-12662", Name: "Unbound NXNSAttack amplification", CVSS: 7.5, Service: "dns", Technique: "T1498.002", Tactic: "impact", CWE: []string{"CWE-406"}, Description: "Unbound performs large referral amplification (NXNSAttack) on queries into a delegation with many unresolved nameservers."},
	{ID: "CVE-2020-12667", Name: "Knot Resolver NXNSAttack amplification", CVSS: 7.5, Service: "dns", Technique: "T1498.002", Tactic: "impact", CWE: []string{"CWE-406"}, Description: "Knot Resolver referral amplification (NXNSAttack) via crafted delegations."},
	{ID: "CVE-2020-25681", Name: "dnsmasq DNSpooq heap overflow", CVSS: 8.1, Service: "dns", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-787"}, Description: "dnsmasq DNSSEC response handling heap buffer overflow (one of the DNSpooq set)."},
	{ID: "CVE-2020-25684", Name: "dnsmasq DNSpooq cache poisoning", CVSS: 4.0, Service: "dns", Technique: "T1557", Tactic: "credential-access", CWE: []string{"CWE-345"}, Description: "dnsmasq weak reply matching enables off-path DNS cache poisoning (DNSpooq)."},
	{ID: "CVE-2020-25705", Name: "SAD DNS side-channel poisoning", CVSS: 7.4, Service: "dns", Technique: "T1557", Tactic: "credential-access", CWE: []string{"CWE-330"}, Description: "ICMP rate-limit side channel lets an off-path attacker infer the UDP source port and poison the DNS cache (SAD DNS)."},

	// ---- SMB (445). ----
	// NOTE: SMBGhost (CVE-2020-0796) is intentionally NOT catalogued — it is not
	// substring-detectable; the smb handler attributes it structurally via
	// res.CVEHits (SMB 3.1.1 dialect + compression negotiate-context).
	{ID: "CVE-2020-1206", Name: "SMBleed (SMBv3 decompression info-leak)", CVSS: 9.1, Service: "smb", Technique: "T1210", Tactic: "lateral-movement", CWE: []string{"CWE-125"}, Description: "Windows SMBv3 decompression out-of-bounds read leaking kernel memory; chained with SMBGhost."},
	{ID: "CVE-2017-0143", Name: "EternalRomance/Synergy (MS17-010)", CVSS: 8.1, Service: "smb", Technique: "T1210", Tactic: "lateral-movement", CWE: []string{"CWE-20"}, Description: "Windows SMBv1 remote code execution (MS17-010 family — EternalRomance/EternalSynergy)."},
	{ID: "CVE-2017-0145", Name: "EternalChampion (MS17-010)", CVSS: 8.1, Service: "smb", Technique: "T1210", Tactic: "lateral-movement", CWE: []string{"CWE-20"}, Description: "Windows SMBv1 transaction race remote code execution (MS17-010 — EternalChampion)."},
	{ID: "CVE-2017-0146", Name: "MS17-010 SMBv1 RCE", CVSS: 8.1, Service: "smb", Technique: "T1210", Tactic: "lateral-movement", CWE: []string{"CWE-20"}, Description: "Windows SMBv1 remote code execution (MS17-010 set)."},
	{ID: "CVE-2017-0147", Name: "MS17-010 SMBv1 info disclosure", CVSS: 5.9, Service: "smb", Technique: "T1210", Tactic: "lateral-movement", CWE: []string{"CWE-125"}, Description: "Windows SMBv1 information disclosure (MS17-010 set)."},
	{ID: "CVE-2017-0148", Name: "MS17-010 SMBv1 RCE", CVSS: 8.1, Service: "smb", Technique: "T1210", Tactic: "lateral-movement", CWE: []string{"CWE-20"}, Description: "Windows SMBv1 remote code execution (MS17-010 set)."},
	{ID: "CVE-2021-36942", Name: "PetitPotam (MS-EFSRPC coerced auth)", CVSS: 7.5, Service: "smb", Technique: "T1187", Tactic: "credential-access", CWE: []string{"CWE-287"}, Description: "MS-EFSRPC EfsRpcOpenFileRaw coerces a host to authenticate to an attacker, enabling NTLM relay to AD CS (PetitPotam). NTLM MIC-stripping relay is catalogued as CVE-2019-1040 (dcerpc)."},
	{ID: "CVE-2022-37958", Name: "SPNEGO NEGOEX pre-auth RCE", CVSS: 8.1, Service: "smb", Technique: "T1210", Tactic: "lateral-movement", CWE: []string{"CWE-787"}, Description: "Windows SPNEGO NEGOEX heap overflow reachable pre-auth through any SPNEGO-negotiating protocol (SMB/RDP/SMTP/LDAP) — wormable."},
	{ID: "CVE-2016-3213", Name: "BadTunnel (WPAD over NetBIOS)", CVSS: 8.1, Service: "smb", Technique: "T1557", Tactic: "credential-access", CWE: []string{"CWE-358"}, Description: "Windows WPAD-over-NetBIOS name-resolution spoofing cross-network proxy hijack (BadTunnel)."},

	// ---- Telnet (23). ----
	{ID: "CVE-2011-4862", Name: "telnetd encrypt_keyid overflow", CVSS: 9.3, Service: "telnet", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-121"}, Description: "BSD/netkit telnetd stack buffer overflow in the ENCRYPT option key-id handling → pre-auth remote code execution."},
	{ID: "CVE-2020-10188", Name: "inetutils telnetd overflow", CVSS: 9.8, Service: "telnet", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-787"}, Description: "GNU inetutils telnetd netclear/option-buffer overflow → pre-auth remote code execution."},

	// ---- RDP (3389). ----
	{ID: "CVE-2019-1181", Name: "DejaBlue RDP pre-auth RCE", CVSS: 9.8, Service: "rdp", Technique: "T1210", Tactic: "lateral-movement", CWE: []string{"CWE-416"}, Description: "Windows RDP pre-auth remote code execution (DejaBlue set)."},
	{ID: "CVE-2019-1182", Name: "DejaBlue RDP pre-auth RCE", CVSS: 9.8, Service: "rdp", Technique: "T1210", Tactic: "lateral-movement", CWE: []string{"CWE-416"}, Description: "Windows RDP pre-auth remote code execution (DejaBlue set)."},
	{ID: "CVE-2018-0886", Name: "CredSSP remote code execution", CVSS: 8.1, Service: "rdp", Technique: "T1210", Tactic: "lateral-movement", CWE: []string{"CWE-347"}, Description: "CredSSP (RDP/WinRM) logical flaw allows a MITM to relay credentials and run code (Return of the AitM)."},
	{ID: "CVE-2020-0609", Name: "RD Gateway pre-auth RCE", CVSS: 9.8, Service: "rdp", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-787"}, Description: "Windows Remote Desktop Gateway (UDP 3391) pre-auth remote code execution."},
	{ID: "CVE-2020-0610", Name: "RD Gateway pre-auth RCE", CVSS: 9.8, Service: "rdp", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-787"}, Description: "Windows Remote Desktop Gateway (UDP 3391) pre-auth remote code execution."},
	{ID: "CVE-2019-0887", Name: "Reverse-RDP path traversal", CVSS: 7.5, Service: "rdp", Technique: "T1210", Tactic: "lateral-movement", CWE: []string{"CWE-22"}, Description: "Malicious RDP server escapes the client clipboard/drive redirection to write arbitrary client files (reverse RDP)."},

	// ---- FTP (21). ----
	{ID: "CVE-2010-4221", Name: "ProFTPD Telnet IAC overflow", CVSS: 10.0, Service: "ftp", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-121"}, Description: "ProFTPD command parser stack overflow on embedded Telnet IAC sequences → pre-auth remote code execution."},
	{ID: "CVE-2021-35211", Name: "SolarWinds Serv-U RCE", CVSS: 10.0, Service: "ftp", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-787"}, Description: "SolarWinds Serv-U memory-corruption remote code execution (exploited in the wild). Serv-U path traversal is catalogued as CVE-2024-28995 (http)."},
	{ID: "CVE-2011-3171", Name: "Pure-FTPd use-after-free", CVSS: 7.5, Service: "ftp", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-415"}, Description: "Pure-FTPd double-free / use-after-free reachable via crafted commands."},

	// ---- MySQL (3306). ----
	{ID: "CVE-2012-2122", Name: "MySQL/MariaDB auth bypass", CVSS: 5.1, Service: "mysql", Technique: "T1110", Tactic: "credential-access", CWE: []string{"CWE-307", "CWE-203"}, Description: "memcmp return-value flaw lets a repeated login with any password succeed ~1/256 of the time (auth bypass by brute force)."},
	{ID: "CVE-2016-6662", Name: "MySQL my.cnf injection RCE", CVSS: 7.2, Service: "mysql", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "An attacker with FILE/admin writes a malicious my.cnf (malloc_lib=) via INTO OUTFILE → code execution as the mysql user on restart."},
	{ID: "CVE-2016-6663", Name: "MySQL/MariaDB privilege escalation", CVSS: 4.4, Service: "mysql", Technique: "T1068", Tactic: "privilege-escalation", CWE: []string{"CWE-269"}, Description: "Race condition in CREATE/RENAME TABLE lets a low-privileged DB user escalate to the mysql system user."},

	// ---- PostgreSQL (5432). ----
	{ID: "CVE-2019-9193", Name: "PostgreSQL COPY FROM PROGRAM RCE", CVSS: 9.8, Service: "postgres", Technique: "T1059", Tactic: "execution", CWE: []string{"CWE-78"}, Description: "A superuser (or pg_execute_server_program member) runs arbitrary commands via COPY ... FROM PROGRAM (vendor-disputed as intended behavior)."},
	{ID: "CVE-2024-10979", Name: "PostgreSQL PL/Perl environment RCE", CVSS: 8.8, Service: "postgres", Technique: "T1059", Tactic: "execution", CWE: []string{"CWE-94"}, Description: "PL/Perl lets an unprivileged role change sensitive process environment variables (e.g. PATH) → arbitrary code/library execution."},
	{ID: "CVE-2018-1058", Name: "PostgreSQL search_path schema hijack", CVSS: 8.8, Service: "postgres", Technique: "T1574", Tactic: "privilege-escalation", CWE: []string{"CWE-426"}, Description: "A user can create objects in the public schema that a higher-privileged role later executes via an unqualified search_path."},
	{ID: "CVE-2024-10978", Name: "PostgreSQL SET ROLE privilege confusion", CVSS: 4.2, Service: "postgres", Technique: "T1078", Tactic: "privilege-escalation", CWE: []string{"CWE-285"}, Description: "Incorrect SET ROLE / SESSION AUTHORIZATION handling lets a user adopt the wrong identity for some settings."},

	// ---- Redis (6379). ----
	{ID: "CVE-2022-0543", Name: "Redis Lua sandbox escape RCE", CVSS: 10.0, Service: "redis", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-94"}, Description: "Debian/Ubuntu Redis Lua interpreter sandbox escape via package/loadlib → unauthenticated remote code execution (CISA KEV)."},
	{ID: "CVE-2024-31449", Name: "Redis Lua bit-library stack overflow RCE", CVSS: 7.0, Service: "redis", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-787"}, Description: "An authenticated user triggers a stack overflow in the Lua bit library via a crafted EVAL script → remote code execution."},

	// ---- MongoDB (27017). ----
	{ID: "CVE-2021-20329", Name: "MongoDB BSON type-confusion injection", CVSS: 6.5, Service: "mongodb", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-843"}, Description: "Improper BSON validation in some MongoDB drivers allows query injection via type confusion."},
	{ID: "CVE-2020-7921", Name: "MongoDB security-check bypass (JS)", CVSS: 4.9, Service: "mongodb", Technique: "T1059", Tactic: "execution", CWE: []string{"CWE-358"}, Description: "Improperly implemented security check lets server-side JavaScript run even when javascriptEnabled is set to false."},
	{ID: "CVE-2019-2389", Name: "MongoDB cached-credential auth bypass", CVSS: 7.7, Service: "mongodb", Technique: "T1078", Tactic: "credential-access", CWE: []string{"CWE-287"}, Description: "MongoDB reuses cached authorization after a user's privileges are revoked (LDAP/SASL), allowing continued access."},

	// ---- OT / remote-access / management / printer protocol deepening ----
	// (CUPS chain 2024-47176/47076/47175, Schneider UMAS 2018-7842/2021-22779,
	// Siemens 2019-10929 and Moxa 2016-9361 are already catalogued elsewhere.)
	{ID: "CVE-2000-0917", Name: "LPRng format-string RCE", CVSS: 10.0, Service: "lpd", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-134"}, Description: "LPRng use_syslog format-string vulnerability allows remote code execution via crafted LPD control data."},
	{ID: "CVE-2017-2741", Name: "HP LaserJet PJL path traversal / file access", CVSS: 7.5, Service: "pjl", Technique: "T1005", Tactic: "collection", CWE: []string{"CWE-22"}, Description: "HP printers expose the PJL filesystem (FSDOWNLOAD/FSUPLOAD), allowing remote read/write outside the intended directory."},
	{ID: "CVE-2013-4786", Name: "IPMI 2.0 RAKP password-hash disclosure", CVSS: 7.5, Service: "ipmi", Technique: "T1190", Tactic: "credential-access", CWE: []string{"CWE-200"}, Description: "The IPMI 2.0 RAKP protocol returns a salted password hash for any username to an unauthenticated client (offline-crackable)."},
	{ID: "CVE-2006-2369", Name: "RealVNC 4.1.1 authentication bypass", CVSS: 7.5, Service: "vnc", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, Description: "RealVNC 4.1.1 lets a client choose the 'None' security type even when the server requires a password — full auth bypass."},
	{ID: "CVE-2019-15681", Name: "LibVNCServer memory disclosure", CVSS: 7.5, Service: "vnc", Technique: "T1190", Tactic: "collection", CWE: []string{"CWE-200"}, Description: "LibVNCServer leaks server memory to a connecting client through an uninitialized-data read."},
	{ID: "CVE-2020-6998", Name: "Rockwell Logix stack overflow RCE", CVSS: 10.0, Service: "ethernetip", Technique: "T0843", Tactic: "execution", CWE: []string{"CWE-787"}, Description: "Allen-Bradley CompactLogix/ControlLogix CIP handling stack overflow allows remote code execution / PLC compromise."},
	{ID: "CVE-2013-2811", Name: "Triangle MicroWorks DNP3 outstation DoS", CVSS: 7.1, Service: "dnp3", Technique: "T0814", Tactic: "impact", CWE: []string{"CWE-20"}, Description: "Malformed DNP3 application fragments crash Triangle MicroWorks-based outstations/masters (widely OEM'd)."},
	{ID: "CVE-2022-29862", Name: "open62541 OPC-UA infinite loop DoS", CVSS: 7.5, Service: "opcua", Technique: "T0814", Tactic: "impact", CWE: []string{"CWE-835"}, Description: "open62541 enters an infinite loop on a crafted OPC-UA message, denying service to the server."},

	// ---- 25-protocol round: OT / remote / management / printer (advisory) ----
	{ID: "CVE-2017-2680", Name: "Siemens PROFINET-DCP DoS", CVSS: 7.5, Service: "profinet", Technique: "T0814", Tactic: "impact", CWE: []string{"CWE-400"}, Description: "Crafted PROFINET-DCP (layer-2) packets put affected Siemens devices into defect mode, requiring a manual restart (DoS)."},
	{ID: "CVE-2021-20587", Name: "Mitsubishi MELSEC iQ-R uncontrolled resource DoS", CVSS: 7.5, Service: "melsec", Technique: "T0814", Tactic: "impact", CWE: []string{"CWE-400"}, Description: "Malformed MELSEC communication packets exhaust resources on Mitsubishi MELSEC iQ-R CPUs, causing a denial of service."},
	{ID: "CVE-2019-18261", Name: "Omron PLC FINS missing authentication", CVSS: 7.5, Service: "fins", Technique: "T0859", Tactic: "lateral-movement", CWE: []string{"CWE-306"}, Description: "Omron CS/CJ/NJ controllers accept unauthenticated FINS commands, allowing read/write of PLC memory and run-state control."},
	{ID: "CVE-2023-42770", Name: "Red Lion Crimson authentication bypass", CVSS: 9.8, Service: "crimson", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, Description: "Red Lion controllers accept management protocol requests from an unauthenticated network client, bypassing authentication."},
	{ID: "CVE-2023-6448", Name: "Unitronics Vision hardcoded password", CVSS: 9.8, Service: "pcom", Technique: "T0859", Tactic: "initial-access", CWE: []string{"CWE-798"}, Description: "Unitronics Vision/Samba PLC/HMI ship a default administrative password (exploited in the wild against water/wastewater HMIs)."},
	{ID: "CVE-2011-3478", Name: "Symantec pcAnywhere remote code execution", CVSS: 9.8, Service: "pcanywhere", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-120"}, Description: "Symantec pcAnywhere awhost32 buffer overflow on a crafted login packet allows pre-auth remote code execution."},
	{ID: "CVE-2023-34329", Name: "AMI MegaRAC Redfish authentication bypass", CVSS: 8.2, Service: "redfish", Technique: "T1190", Tactic: "credential-access", CWE: []string{"CWE-290"}, Description: "AMI MegaRAC BMCs treat a request as internal when a Host/X-Server-Addr header is spoofed, bypassing Redfish authentication."},

	// ---- Round 3: a second CVE per protocol where a confident one exists ----
	{ID: "CVE-2017-12741", Name: "Siemens S7 crafted-packet DoS", CVSS: 7.5, Service: "s7comm_plus", Technique: "T0814", Tactic: "impact", CWE: []string{"CWE-400"}, Description: "A crafted packet to UDP/161 or TCP/102 puts affected Siemens S7 / SIMATIC devices into defect mode (manual restart required)."},
	{ID: "CVE-2023-3596", Name: "Rockwell 1756-EN2T major-fault DoS", CVSS: 8.6, Service: "ethernetip", Technique: "T0814", Tactic: "impact", CWE: []string{"CWE-20"}, Description: "A malformed CIP packet faults Allen-Bradley 1756-EN2T/EN3T communication modules, halting the controller (DoS)."},
	{ID: "CVE-2023-42769", Name: "Red Lion missing authentication", CVSS: 9.1, Service: "crimson", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-306"}, Description: "Red Lion controllers expose privileged management functionality to an unauthenticated network client."},
	{ID: "CVE-2018-7225", Name: "LibVNCServer out-of-bounds access", CVSS: 9.8, Service: "vnc", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-125"}, Description: "LibVNCServer rfbProcessClientNormalMessage mishandles a client message length, causing an out-of-bounds read/write."},
	{ID: "CVE-2022-40259", Name: "AMI MegaRAC Redfish command injection", CVSS: 9.9, Service: "redfish", Technique: "T1190", Tactic: "execution", CWE: []string{"CWE-78"}, Description: "AMI MegaRAC exposes a Redfish API operation that allows an authenticated low-privilege user to execute arbitrary commands."},
	{ID: "CVE-2013-4031", Name: "Supermicro IPMI/BMC authentication bypass", CVSS: 9.8, Service: "ipmi", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"}, Description: "Supermicro IPMI/BMC firmware contains an authentication flaw allowing unauthorized administrative access."},

	// ---- Deep-handler CVEs: protocols whose wire format we already parse
	// but didn't yet recognize the canonical exploit for. Intel AMT carries a
	// request signature (an empty HTTP Digest `response`); the rest are
	// detected in-handler from the parsed protocol and catalogued advisory-only. ----
	{ID: "CVE-2017-5689", Name: "Intel AMT digest-auth bypass", CVSS: 9.8, Service: "intel_amt",
		Signatures: []string{"response=\"\""},
		Technique:  "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"},
		Description: "Intel AMT/ISM/SBT web UI accepts an HTTP Digest auth with an empty `response` value (the firmware compares only the bytes the client sends), granting unauthenticated administrative access (INTEL-SA-00075)."},
	{ID: "CVE-2012-1675", Name: "Oracle TNS Poison (remote registration)", CVSS: 7.5, Service: "oracle_tns",
		Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-306"},
		Description: "The Oracle TNS listener accepts unauthenticated remote service registration (COMMAND=SERVICE_REGISTER_NSGR), letting an attacker register a rogue instance and divert/hijack database connections."},
	{ID: "CVE-2017-7650", Name: "Mosquitto pattern-ACL bypass", CVSS: 8.6, Service: "mqtt",
		Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-287"},
		Description: "Eclipse Mosquitto pattern-based ACLs are bypassed by a client whose username or client id is or contains the MQTT wildcard '#' or '+', granting access to topics it should not reach."},
	{ID: "CVE-2016-8704", Name: "memcached append/prepend integer overflow RCE", CVSS: 9.8, Service: "memcached",
		Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-190"},
		Description: "Integer overflow in memcached process_bin_append_prepend (binary-protocol APPEND/PREPEND) causes a heap overflow and remote code execution (Talos TALOS-2016-0219)."},
	{ID: "CVE-2016-8705", Name: "memcached update integer overflow RCE", CVSS: 9.8, Service: "memcached",
		Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-190"},
		Description: "Integer overflow in memcached process_bin_update (binary-protocol SET/ADD/REPLACE) causes a heap overflow and remote code execution (Talos TALOS-2016-0220)."},
	{ID: "CVE-2016-8706", Name: "memcached SASL-auth integer overflow RCE", CVSS: 9.8, Service: "memcached",
		Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-190"},
		Description: "Integer overflow in memcached process_bin_sasl_auth (binary-protocol SASL authentication) causes a heap overflow and remote code execution (Talos TALOS-2016-0221)."},

	// ---- Deep-handler CVEs, round 2: SSH supply-chain + Windows LDAP.
	// Advisory-only — these activate client-side or need the attacker's key,
	// so they drive vulnerable-version / patch-level emulation rather than an
	// inbound request signature. ----
	{ID: "CVE-2024-3094", Name: "XZ Utils / liblzma sshd backdoor", CVSS: 10.0, Service: "ssh",
		Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-506"},
		Description: "Malicious code in xz/liblzma 5.6.0/5.6.1 hooks OpenSSH's liblzma dependency and grants pre-auth RCE to whoever holds the attacker's Ed448 key (supply-chain backdoor). Exploitation needs that private key, so this drives vulnerable-build emulation, not request-signature detection."},
	{ID: "CVE-2024-49112", Name: "Windows LDAP integer-overflow RCE (LDAPBleed)", CVSS: 9.8, Service: "ldap",
		Technique: "T1203", Tactic: "execution", CWE: []string{"CWE-190"},
		Description: "A crafted CLDAP referral response triggers an integer overflow in the Windows LDAP client (the December-2024 'LDAPNightmare' pair). Client-side trigger — advertised here for an unpatched-Windows-DC fingerprint, not detected inbound."},
	{ID: "CVE-2024-49113", Name: "Windows LDAP DoS (LDAPNightmare)", CVSS: 7.5, Service: "ldap",
		Technique: "T1499", Tactic: "impact", CWE: []string{"CWE-190"},
		Description: "A crafted CLDAP referral response crashes LSASS on an unpatched Windows DC (SafeBreach PoC). Client-side trigger — advertised here for patch-level emulation, not detected inbound."},
}

// init normalizes every catalog signature to lowercase once, so
// MatchPayload (called on every request) only lowercases the payload.
// cveExtra carries the CWE / CPE / EPSS cross-references merged into the
// catalog at init. CWE (weakness class) and CPE (affected product) are
// stable; EPSS is a point-in-time snapshot (~2026-05) used only as a
// relative-priority hint — see docs/attribution.md. Entries omitted here
// simply leave those fields empty.
var cveExtra = map[string]struct {
	CWE  []string
	CPE  string
	EPSS float64
}{
	"CVE-2014-6271":  {[]string{"CWE-78"}, "cpe:2.3:a:gnu:bash:*", 0.94},
	"CVE-2017-0144":  {[]string{"CWE-20", "CWE-787"}, "cpe:2.3:o:microsoft:windows:*", 0.94},
	"CVE-2017-10271": {[]string{"CWE-502"}, "cpe:2.3:a:oracle:weblogic_server:*", 0.97},
	"CVE-2017-12615": {[]string{"CWE-434"}, "cpe:2.3:a:apache:tomcat:*", 0.97},
	"CVE-2017-5638":  {[]string{"CWE-1336", "CWE-20"}, "cpe:2.3:a:apache:struts:*", 0.97},
	"CVE-2017-7921":  {[]string{"CWE-287"}, "cpe:2.3:o:hikvision:firmware:*", 0.90},
	"CVE-2017-9841":  {[]string{"CWE-94"}, "cpe:2.3:a:phpunit:phpunit:*", 0.97},
	"CVE-2018-0171":  {[]string{"CWE-787"}, "cpe:2.3:o:cisco:ios:*", 0.90},
	"CVE-2018-10561": {[]string{"CWE-287"}, "cpe:2.3:o:dasannetworks:gpon_firmware:*", 0.97},
	"CVE-2018-13379": {[]string{"CWE-22"}, "cpe:2.3:o:fortinet:fortios:*", 0.97},
	"CVE-2018-15473": {[]string{"CWE-200"}, "cpe:2.3:a:openbsd:openssh:*", 0.55},
	// SSH (OpenSSH / libssh / SSH-1) catalog cross-references.
	"CVE-2008-0166":  {[]string{"CWE-330"}, "cpe:2.3:a:openssl:openssl:*", 0.50},
	"CVE-2016-0777":  {[]string{"CWE-200"}, "cpe:2.3:a:openbsd:openssh:*", 0.10},
	"CVE-2016-0778":  {[]string{"CWE-787"}, "cpe:2.3:a:openbsd:openssh:*", 0.05},
	"CVE-2016-6210":  {[]string{"CWE-203"}, "cpe:2.3:a:openbsd:openssh:*", 0.40},
	"CVE-2016-10009": {[]string{"CWE-426"}, "cpe:2.3:a:openbsd:openssh:*", 0.10},
	"CVE-2015-5600":  {[]string{"CWE-287"}, "cpe:2.3:a:openbsd:openssh:*", 0.30},
	"CVE-2010-4478":  {[]string{"CWE-287"}, "cpe:2.3:a:openbsd:openssh:*", 0.05},
	"CVE-2010-5107":  {[]string{"CWE-400"}, "cpe:2.3:a:openbsd:openssh:*", 0.10},
	"CVE-2017-15906": {[]string{"CWE-732"}, "cpe:2.3:a:openbsd:openssh:*", 0.10},
	"CVE-2018-20685": {[]string{"CWE-863"}, "cpe:2.3:a:openbsd:openssh:*", 0.30},
	"CVE-2019-6109":  {[]string{"CWE-116"}, "cpe:2.3:a:openbsd:openssh:*", 0.10},
	"CVE-2019-6110":  {[]string{"CWE-116"}, "cpe:2.3:a:openbsd:openssh:*", 0.10},
	"CVE-2019-6111":  {[]string{"CWE-22"}, "cpe:2.3:a:openbsd:openssh:*", 0.40},
	"CVE-2020-14145": {[]string{"CWE-203"}, "cpe:2.3:a:openbsd:openssh:*", 0.20},
	"CVE-2020-15778": {[]string{"CWE-78"}, "cpe:2.3:a:openbsd:openssh:*", 0.40},
	"CVE-2021-28041": {[]string{"CWE-415"}, "cpe:2.3:a:openbsd:openssh:*", 0.05},
	"CVE-2021-41617": {[]string{"CWE-732"}, "cpe:2.3:a:openbsd:openssh:*", 0.10},
	"CVE-2023-38408": {[]string{"CWE-426"}, "cpe:2.3:a:openbsd:openssh:*", 0.80},
	"CVE-2023-51385": {[]string{"CWE-78"}, "cpe:2.3:a:openbsd:openssh:*", 0.30},
	"CVE-2023-51384": {[]string{"CWE-287"}, "cpe:2.3:a:openbsd:openssh:*", 0.10},
	"CVE-2025-26465": {[]string{"CWE-300"}, "cpe:2.3:a:openbsd:openssh:*", 0.10},
	"CVE-2025-26466": {[]string{"CWE-770"}, "cpe:2.3:a:openbsd:openssh:*", 0.10},
	"CVE-2006-5051":  {[]string{"CWE-364"}, "cpe:2.3:a:openbsd:openssh:*", 0.20},
	"CVE-2003-0693":  {[]string{"CWE-787"}, "cpe:2.3:a:openbsd:openssh:*", 0.30},
	"CVE-2001-0144":  {[]string{"CWE-190"}, "cpe:2.3:a:ssh:ssh:*", 0.40},
	"CVE-2018-10933": {[]string{"CWE-287"}, "cpe:2.3:a:libssh:libssh:*", 0.90},
	"CVE-2023-2283":  {[]string{"CWE-287"}, "cpe:2.3:a:libssh:libssh:*", 0.30},
	"CVE-2021-3634":  {[]string{"CWE-787"}, "cpe:2.3:a:libssh:libssh:*", 0.10},
	"CVE-2002-0640":  {[]string{"CWE-787"}, "cpe:2.3:a:openbsd:openssh:*", 0.50},
	"CVE-2008-1657":  {[]string{"CWE-269"}, "cpe:2.3:a:openbsd:openssh:*", 0.10},
	"CVE-2018-7600":  {[]string{"CWE-20", "CWE-94"}, "cpe:2.3:a:drupal:drupal:*", 0.97},
	"CVE-2018-7842":  {[]string{"CWE-287", "CWE-294"}, "cpe:2.3:o:schneider-electric:modicon_m340_firmware:*", 0.20},
	"CVE-2018-12613": {[]string{"CWE-22", "CWE-98"}, "cpe:2.3:a:phpmyadmin:phpmyadmin:*", 0.97},
	"CVE-2009-1151":  {[]string{"CWE-94"}, "cpe:2.3:a:phpmyadmin:phpmyadmin:*", 0.90},
	"CVE-2018-20062": {[]string{"CWE-94"}, "cpe:2.3:a:thinkphp:thinkphp:*", 0.97},
	"CVE-2019-11043": {[]string{"CWE-787"}, "cpe:2.3:a:php:fpm:*", 0.96},
	"CVE-2019-0708":  {[]string{"CWE-416"}, "cpe:2.3:o:microsoft:windows:*", 0.95},
	"CVE-2019-11510": {[]string{"CWE-22"}, "cpe:2.3:a:pulsesecure:pulse_connect_secure:*", 0.97},
	"CVE-2019-18935": {[]string{"CWE-502"}, "cpe:2.3:a:telerik:ui_for_asp.net_ajax:*", 0.95},
	"CVE-2019-19781": {[]string{"CWE-22"}, "cpe:2.3:a:citrix:application_delivery_controller:*", 0.97},
	"CVE-2020-1472":  {[]string{"CWE-330"}, "cpe:2.3:o:microsoft:windows_server:*", 0.96},
	"CVE-2020-14882": {[]string{"CWE-22", "CWE-94"}, "cpe:2.3:a:oracle:weblogic_server:*", 0.97},
	"CVE-2020-15782": {[]string{"CWE-787", "CWE-119"}, "cpe:2.3:o:siemens:simatic_s7-1200_firmware:*", 0.20},
	"CVE-2020-5902":  {[]string{"CWE-22", "CWE-94"}, "cpe:2.3:a:f5:big-ip:*", 0.97},
	"CVE-2021-21972": {[]string{"CWE-22", "CWE-434"}, "cpe:2.3:a:vmware:vcenter_server:*", 0.97},
	"CVE-2021-22681": {[]string{"CWE-321"}, "cpe:2.3:o:rockwellautomation:studio_5000:*", 0.10},
	"CVE-2021-26084": {[]string{"CWE-917"}, "cpe:2.3:a:atlassian:confluence_server:*", 0.97},
	"CVE-2021-26855": {[]string{"CWE-918"}, "cpe:2.3:a:microsoft:exchange_server:*", 0.97},
	"CVE-2021-3129":  {[]string{"CWE-502"}, "cpe:2.3:a:laravel:laravel:*", 0.96},
	"CVE-2021-34473": {[]string{"CWE-918"}, "cpe:2.3:a:microsoft:exchange_server:*", 0.97},
	"CVE-2021-34527": {[]string{"CWE-269", "CWE-22"}, "cpe:2.3:o:microsoft:windows:*", 0.94},
	"CVE-2021-40539": {[]string{"CWE-287"}, "cpe:2.3:a:zohocorp:manageengine_adselfservice_plus:*", 0.95},
	"CVE-2021-41773": {[]string{"CWE-22"}, "cpe:2.3:a:apache:http_server:2.4.49", 0.97},
	"CVE-2021-42013": {[]string{"CWE-22"}, "cpe:2.3:a:apache:http_server:2.4.50", 0.97},
	"CVE-2021-42278": {[]string{"CWE-269"}, "cpe:2.3:o:microsoft:windows_server:*", 0.55},
	"CVE-2021-44228": {[]string{"CWE-502", "CWE-917", "CWE-20"}, "cpe:2.3:a:apache:log4j:*", 0.94},
	"CVE-2022-1026":  {[]string{"CWE-200", "CWE-22"}, "cpe:2.3:o:kyocera:command_center_rx:*", 0.20},
	"CVE-2022-1161":  {[]string{"CWE-94"}, "cpe:2.3:o:rockwellautomation:logix:*", 0.10},
	"CVE-2022-1388":  {[]string{"CWE-306"}, "cpe:2.3:a:f5:big-ip:*", 0.97},
	"CVE-2022-22965": {[]string{"CWE-94", "CWE-20"}, "cpe:2.3:a:vmware:spring_framework:*", 0.97},
	"CVE-2022-26134": {[]string{"CWE-917"}, "cpe:2.3:a:atlassian:confluence_server:*", 0.97},
	"CVE-2022-30190": {[]string{"CWE-94"}, "cpe:2.3:a:microsoft:windows:*", 0.97},
	"CVE-2022-40684": {[]string{"CWE-288"}, "cpe:2.3:o:fortinet:fortios:*", 0.97},
	"CVE-2023-20198": {[]string{"CWE-420", "CWE-269"}, "cpe:2.3:o:cisco:ios_xe:*", 0.94},
	"CVE-2023-22518": {[]string{"CWE-863"}, "cpe:2.3:a:atlassian:confluence_data_center:*", 0.94},
	"CVE-2023-26067": {[]string{"CWE-20"}, "cpe:2.3:o:lexmark:firmware:*", 0.50},
	"CVE-2023-34362": {[]string{"CWE-89"}, "cpe:2.3:a:progress:moveit_transfer:*", 0.94},
	"CVE-2023-3595":  {[]string{"CWE-787"}, "cpe:2.3:o:rockwellautomation:1756-en2t:*", 0.20},
	"CVE-2023-42793": {[]string{"CWE-288"}, "cpe:2.3:a:jetbrains:teamcity:*", 0.97},
	"CVE-2023-46604": {[]string{"CWE-502"}, "cpe:2.3:a:apache:activemq:*", 0.97},
	"CVE-2024-12510": {[]string{"CWE-522"}, "cpe:2.3:o:xerox:versalink_firmware:*", 0.10},
	"CVE-2024-21887": {[]string{"CWE-78"}, "cpe:2.3:a:ivanti:connect_secure:*", 0.97},
	"CVE-2024-3273":  {[]string{"CWE-78", "CWE-77"}, "cpe:2.3:o:dlink:dns-320_firmware:*", 0.94},
	"CVE-2024-3400":  {[]string{"CWE-78"}, "cpe:2.3:o:paloaltonetworks:pan-os:*", 0.95},
	"CVE-2024-4577":  {[]string{"CWE-78", "CWE-88"}, "cpe:2.3:a:php:php:*", 0.95},
	"CVE-2024-47076": {[]string{"CWE-20"}, "cpe:2.3:a:openprinting:libcupsfilters:*", 0.30},
	"CVE-2024-47175": {[]string{"CWE-20"}, "cpe:2.3:a:openprinting:libppd:*", 0.30},
	"CVE-2024-47176": {[]string{"CWE-20", "CWE-918"}, "cpe:2.3:a:openprinting:cups-browsed:*", 0.30},
	"CVE-2024-47177": {[]string{"CWE-78"}, "cpe:2.3:a:openprinting:cups-filters:*", 0.40},
	// --- additions ---
	"CVE-2023-35078": {[]string{"CWE-287"}, "cpe:2.3:a:ivanti:endpoint_manager_mobile:*", 0.96},
	"CVE-2023-38035": {[]string{"CWE-306"}, "cpe:2.3:a:ivanti:sentry:*", 0.85},
	"CVE-2024-1709":  {[]string{"CWE-288"}, "cpe:2.3:a:connectwise:screenconnect:*", 0.97},
	"CVE-2023-22515": {[]string{"CWE-863"}, "cpe:2.3:a:atlassian:confluence_data_center:*", 0.94},
	"CVE-2024-23897": {[]string{"CWE-22"}, "cpe:2.3:a:jenkins:jenkins:*", 0.94},
	"CVE-2024-27198": {[]string{"CWE-288"}, "cpe:2.3:a:jetbrains:teamcity:*", 0.94},
	"CVE-2022-22954": {[]string{"CWE-94", "CWE-1336"}, "cpe:2.3:a:vmware:workspace_one_access:*", 0.97},
	"CVE-2021-21985": {[]string{"CWE-94"}, "cpe:2.3:a:vmware:vcenter_server:*", 0.96},
	"CVE-2019-2725":  {[]string{"CWE-502"}, "cpe:2.3:a:oracle:weblogic_server:*", 0.96},
	"CVE-2023-46747": {[]string{"CWE-288"}, "cpe:2.3:a:f5:big-ip:*", 0.96},
	"CVE-2021-22005": {[]string{"CWE-434"}, "cpe:2.3:a:vmware:vcenter_server:*", 0.97},
	"CVE-2020-3452":  {[]string{"CWE-22"}, "cpe:2.3:o:cisco:adaptive_security_appliance:*", 0.96},
	"CVE-2022-29464": {[]string{"CWE-434"}, "cpe:2.3:a:wso2:api_manager:*", 0.95},
	"CVE-2021-35587": {[]string{"CWE-502"}, "cpe:2.3:a:oracle:access_manager:*", 0.85},
	"CVE-2024-21893": {[]string{"CWE-918"}, "cpe:2.3:a:ivanti:connect_secure:*", 0.96},
	"CVE-2023-3519":  {[]string{"CWE-787"}, "cpe:2.3:a:citrix:netscaler_application_delivery_controller:*", 0.94},
	"CVE-2022-27925": {[]string{"CWE-22"}, "cpe:2.3:a:zimbra:collaboration:*", 0.94},
	"CVE-2023-27350": {[]string{"CWE-284"}, "cpe:2.3:a:papercut:papercut_mf:*", 0.96},
	"CVE-2024-0204":  {[]string{"CWE-425"}, "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:*", 0.95},
	"CVE-2023-0669":  {[]string{"CWE-502"}, "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:*", 0.94},
	"CVE-2018-11776": {[]string{"CWE-1336", "CWE-20"}, "cpe:2.3:a:apache:struts:*", 0.97},
	"CVE-2017-12149": {[]string{"CWE-502"}, "cpe:2.3:a:redhat:jboss_enterprise_application_platform:*", 0.95},
	"CVE-2021-29441": {[]string{"CWE-290"}, "cpe:2.3:a:alibaba:nacos:*", 0.90},
	"CVE-2022-44877": {[]string{"CWE-78"}, "cpe:2.3:a:control-webpanel:webpanel:*", 0.96},
	"CVE-2015-1427":  {[]string{"CWE-94"}, "cpe:2.3:a:elastic:elasticsearch:*", 0.90},
	"CVE-2014-3120":  {[]string{"CWE-94"}, "cpe:2.3:a:elastic:elasticsearch:*", 0.85},
	"CVE-2023-4966":  {[]string{"CWE-119", "CWE-200"}, "cpe:2.3:a:citrix:netscaler_application_delivery_controller:*", 0.94},
	"CVE-2024-55591": {[]string{"CWE-288"}, "cpe:2.3:o:fortinet:fortios:*", 0.90},
	"CVE-2022-42475": {[]string{"CWE-787"}, "cpe:2.3:o:fortinet:fortios:*", 0.90},
	"CVE-2023-27997": {[]string{"CWE-787", "CWE-122"}, "cpe:2.3:o:fortinet:fortios:*", 0.85},
	"CVE-2025-0282":  {[]string{"CWE-121"}, "cpe:2.3:a:ivanti:connect_secure:*", 0.85},
	"CVE-2024-47575": {[]string{"CWE-306"}, "cpe:2.3:a:fortinet:fortimanager:*", 0.90},
	"CVE-2022-26809": {[]string{"CWE-787"}, "cpe:2.3:o:microsoft:windows:*", 0.50},
	"CVE-2019-1040":  {[]string{"CWE-345"}, "cpe:2.3:o:microsoft:windows:*", 0.30},
	"CVE-2020-1350":  {[]string{"CWE-787"}, "cpe:2.3:o:microsoft:windows_server:*", 0.50},
	"CVE-2016-10033": {[]string{"CWE-88"}, "cpe:2.3:a:phpmailer_project:phpmailer:*", 0.90},
	"CVE-2017-7494":  {[]string{"CWE-94"}, "cpe:2.3:a:samba:samba:*", 0.80},
	"CVE-2024-6387":  {[]string{"CWE-364"}, "cpe:2.3:a:openbsd:openssh:*", 0.40},
	"CVE-2021-21974": {[]string{"CWE-787"}, "cpe:2.3:o:vmware:esxi:*", 0.85},
	"CVE-2023-46805": {[]string{"CWE-287"}, "cpe:2.3:a:ivanti:connect_secure:*", 0.96},
	// --- OT / ICS control-protocol advisories ---
	"CVE-2021-22779": {[]string{"CWE-287", "CWE-863"}, "cpe:2.3:o:schneider-electric:modicon_m580_firmware:*", 0.10},
	"CVE-2018-7852":  {[]string{"CWE-20"}, "cpe:2.3:o:schneider-electric:modicon_m340_firmware:*", 0.03},
	"CVE-2016-2200":  {[]string{"CWE-20"}, "cpe:2.3:o:siemens:simatic_s7-1500_cpu_firmware:*", 0.05},
	"CVE-2019-10929": {[]string{"CWE-924", "CWE-300"}, "cpe:2.3:o:siemens:simatic_s7-1500_cpu_firmware:*", 0.02},
	"CVE-2022-31806": {[]string{"CWE-306", "CWE-1188"}, "cpe:2.3:a:codesys:control_runtime_system:*", 0.15},
	"CVE-2020-10245": {[]string{"CWE-787", "CWE-122"}, "cpe:2.3:a:codesys:codesys:*", 0.10},
	"CVE-2022-31802": {[]string{"CWE-287"}, "cpe:2.3:a:codesys:gateway_server:*", 0.10},
	"CVE-2021-27432": {[]string{"CWE-674"}, "cpe:2.3:a:opcfoundation:ua-.netstandard:*", 0.05},
	"CVE-2023-4346":  {[]string{"CWE-1390", "CWE-640"}, "cpe:2.3:o:knx:knx_devices:*", 0.02},
	"CVE-2015-5374":  {[]string{"CWE-20", "CWE-400"}, "cpe:2.3:o:siemens:en100_ethernet_module_firmware:*", 0.05},
	"CVE-2019-13524": {[]string{"CWE-20"}, "cpe:2.3:o:ge:pacsystems_rx3i_cpe310_firmware:*", 0.03},
	"CVE-2020-6986":  {[]string{"CWE-400"}, "cpe:2.3:o:omron:cj2m_cpu_firmware:*", 0.03},
	"CVE-2021-20591": {[]string{"CWE-300", "CWE-404"}, "cpe:2.3:o:mitsubishielectric:melsec_iq-r_series:*", 0.02},
	"CVE-2022-38138": {[]string{"CWE-824"}, "cpe:2.3:a:trianglemicroworks:tmw_iec_61850:*", 0.03},
	"CVE-2013-2783":  {[]string{"CWE-835", "CWE-20"}, "cpe:2.3:a:trianglemicroworks:scada_data_gateway:*", 0.04},
	"CVE-2017-16744": {[]string{"CWE-22"}, "cpe:2.3:a:tridium:niagara:*", 0.05},
	"CVE-2016-8367":  {[]string{"CWE-306"}, "cpe:2.3:o:phoenixcontact:ilc_151_eth_firmware:*", 0.05},
	"CVE-2010-2965":  {[]string{"CWE-489", "CWE-306"}, "cpe:2.3:o:windriver:vxworks:*", 0.10},
	"CVE-2019-12256": {[]string{"CWE-787"}, "cpe:2.3:o:windriver:vxworks:*", 0.10},
	"CVE-2019-12255": {[]string{"CWE-787"}, "cpe:2.3:o:windriver:vxworks:*", 0.10},
	"CVE-2020-16209": {[]string{"CWE-787", "CWE-120"}, "cpe:2.3:a:fieldcommgroup:hipserver:*", 0.08},
	"CVE-2025-58428": {[]string{"CWE-78"}, "cpe:2.3:o:veeder-root:tls4b_firmware:*", 0.05},
	"CVE-2018-8867":  {[]string{"CWE-20"}, "cpe:2.3:o:ge:pacsystems_rx3i_cpe330_firmware:*", 0.03},
	// TCP/IP-stack attacks (Teardrop / LAND / TCP-RST / sockstress). NVD tags
	// these OS network-stack DoS flaws to OS kernels; the decoy presents a Linux
	// TCP/IP stack, so linux_kernel is the representative affected product.
	"CVE-1999-0015":  {[]string{"CWE-400"}, "cpe:2.3:o:linux:linux_kernel:*", 0.02},
	"CVE-1999-0016":  {[]string{"CWE-400"}, "cpe:2.3:o:linux:linux_kernel:*", 0.02},
	"CVE-2004-0230":  {[]string{"CWE-400"}, "cpe:2.3:o:linux:linux_kernel:*", 0.04},
	"CVE-2008-4609":  {[]string{"CWE-400"}, "cpe:2.3:o:linux:linux_kernel:*", 0.05},
	"CVE-2016-5696":  {[]string{"CWE-203"}, "cpe:2.3:o:linux:linux_kernel:*", 0.04},
	"CVE-2018-5391":  {[]string{"CWE-400"}, "cpe:2.3:o:linux:linux_kernel:*", 0.05},
	"CVE-2019-11477": {[]string{"CWE-190", "CWE-400"}, "cpe:2.3:o:linux:linux_kernel:*", 0.06},
	"CVE-2020-11896": {[]string{"CWE-787"}, "cpe:2.3:o:treck:tcp_ip:*", 0.10},
	"CVE-2023-22527": {[]string{"CWE-917"}, "cpe:2.3:a:atlassian:confluence_data_center:*", 0.97},
	"CVE-2024-24919": {[]string{"CWE-200", "CWE-22"}, "cpe:2.3:o:checkpoint:gaia_os:*", 0.97},
	"CVE-2024-0012":  {[]string{"CWE-306"}, "cpe:2.3:o:paloaltonetworks:pan-os:*", 0.96},
	"CVE-2024-23692": {[]string{"CWE-94", "CWE-1336"}, "cpe:2.3:a:rejetto:http_file_server:2.3", 0.96},
	"CVE-2024-28995": {[]string{"CWE-22"}, "cpe:2.3:a:solarwinds:serv-u:*", 0.96},
	"CVE-2023-35082": {[]string{"CWE-287"}, "cpe:2.3:a:ivanti:endpoint_manager_mobile:*", 0.94},
	"CVE-2025-31324": {[]string{"CWE-434"}, "cpe:2.3:a:sap:netweaver_application_server_java:*", 0.94},
	"CVE-2024-36401": {[]string{"CWE-94"}, "cpe:2.3:a:osgeo:geoserver:*", 0.97},
	"CVE-2024-4885":  {[]string{"CWE-22"}, "cpe:2.3:a:progress:whatsup_gold:*", 0.94},
	"CVE-2024-38856": {[]string{"CWE-285", "CWE-94"}, "cpe:2.3:a:apache:ofbiz:*", 0.94},
	"CVE-2023-6553":  {[]string{"CWE-94"}, "cpe:2.3:a:migrate:backup_migration:*", 0.95},
	"CVE-2024-27956": {[]string{"CWE-89"}, "cpe:2.3:a:valvepress:automatic:*", 0.94},
	"CVE-2024-25600": {[]string{"CWE-94"}, "cpe:2.3:a:bricksbuilder:bricks:*", 0.95},
	"CVE-2023-34960": {[]string{"CWE-78"}, "cpe:2.3:a:chamilo:chamilo:*", 0.94},
	"CVE-2022-30525": {[]string{"CWE-78"}, "cpe:2.3:o:zyxel:usg_flex_firmware:*", 0.96},
	"CVE-2023-1389":  {[]string{"CWE-78"}, "cpe:2.3:o:tp-link:archer_ax21_firmware:*", 0.96},
	"CVE-2023-48795": {[]string{"CWE-222", "CWE-354"}, "cpe:2.3:a:openbsd:openssh:*", 0.30},
	"CVE-2024-21762": {[]string{"CWE-787"}, "cpe:2.3:o:fortinet:fortios:*", 0.95},
	"CVE-2025-22457": {[]string{"CWE-787"}, "cpe:2.3:a:ivanti:connect_secure:*", 0.94},
	"CVE-2024-10914": {[]string{"CWE-78"}, "cpe:2.3:o:dlink:dns-320_firmware:*", 0.93},
	"CVE-2024-3721":  {[]string{"CWE-78"}, "cpe:2.3:o:tbk:dvr4104_firmware:*", 0.94},
	"CVE-2024-7029":  {[]string{"CWE-78"}, "cpe:2.3:o:avtech:ip_camera_firmware:*", 0.93},
	"CVE-2024-0769":  {[]string{"CWE-22"}, "cpe:2.3:o:dlink:dir-859_firmware:*", 0.90},
	"CVE-2024-29973": {[]string{"CWE-78"}, "cpe:2.3:o:zyxel:nas326_firmware:*", 0.90},
	"CVE-2024-27348": {[]string{"CWE-94"}, "cpe:2.3:a:apache:hugegraph-server:*", 0.94},
	"CVE-2024-4040":  {[]string{"CWE-1336", "CWE-22"}, "cpe:2.3:a:crushftp:crushftp:*", 0.95},
	"CVE-2024-28000": {[]string{"CWE-640"}, "cpe:2.3:a:litespeedtech:litespeed_cache:*", 0.94},
	"CVE-2024-4358":  {[]string{"CWE-288"}, "cpe:2.3:a:progress:telerik_report_server:*", 0.94},
	"CVE-2024-9264":  {[]string{"CWE-94", "CWE-78"}, "cpe:2.3:a:grafana:grafana:*", 0.90},
	"CVE-2024-21683": {[]string{"CWE-94"}, "cpe:2.3:a:atlassian:confluence_data_center:*", 0.90},
	"CVE-2023-48788": {[]string{"CWE-89"}, "cpe:2.3:a:fortinet:forticlient_enterprise_management_server:*", 0.94},
	"CVE-2024-36991": {[]string{"CWE-22"}, "cpe:2.3:a:splunk:splunk:*", 0.94},
	"CVE-2023-50386": {[]string{"CWE-434", "CWE-94"}, "cpe:2.3:a:apache:solr:*", 0.85},
	"CVE-2025-24813": {[]string{"CWE-44", "CWE-502"}, "cpe:2.3:a:apache:tomcat:*", 0.92},
	"CVE-2025-32433": {[]string{"CWE-306"}, "cpe:2.3:a:erlang:otp:*", 0.94},
	"CVE-2024-45519": {[]string{"CWE-78"}, "cpe:2.3:a:zimbra:collaboration:*", 0.94},
	"CVE-2024-8190":  {[]string{"CWE-78"}, "cpe:2.3:a:ivanti:cloud_services_appliance:*", 0.94},
	"CVE-2024-8963":  {[]string{"CWE-22"}, "cpe:2.3:a:ivanti:cloud_services_appliance:*", 0.94},
	"CVE-2024-50603": {[]string{"CWE-78"}, "cpe:2.3:a:aviatrix:controller:*", 0.92},
	"CVE-2023-48022": {[]string{"CWE-306"}, "cpe:2.3:a:anyscale:ray:*", 0.90},
	"CVE-2024-27564": {[]string{"CWE-918"}, "cpe:2.3:a:openai:chatgpt:*", 0.90},
	"CVE-2025-29927": {[]string{"CWE-285"}, "cpe:2.3:a:vercel:next.js:*", 0.93},
	"CVE-2025-32432": {[]string{"CWE-94"}, "cpe:2.3:a:craftcms:craft_cms:*", 0.90},
	"CVE-2024-9047":  {[]string{"CWE-22"}, "cpe:2.3:a:iptanus:wordpress_file_upload:*", 0.85},
	"CVE-2024-10924": {[]string{"CWE-288"}, "cpe:2.3:a:really-simple-plugins:really_simple_security:*", 0.90},
	"CVE-2025-24472": {[]string{"CWE-288"}, "cpe:2.3:o:fortinet:fortios:*", 0.90},
	"CVE-2023-44487": {[]string{"CWE-400"}, "cpe:2.3:a:ietf:http:2.0", 0.80},
	"CVE-2016-6581":  {[]string{"CWE-400", "CWE-409"}, "cpe:2.3:a:ietf:http:2.0", 0.30},
	"CVE-2016-8740":  {[]string{"CWE-400", "CWE-770"}, "cpe:2.3:a:apache:http_server:*", 0.40},
	"CVE-2016-1546":  {[]string{"CWE-400"}, "cpe:2.3:a:apache:http_server:*", 0.20},
	"CVE-2025-53020": {[]string{"CWE-400", "CWE-770"}, "cpe:2.3:a:apache:http_server:*", 0.40},
	"CVE-2026-49975": {[]string{"CWE-400", "CWE-409", "CWE-770"}, "cpe:2.3:a:ietf:http:2.0", 0.50},
	"CVE-2024-3596":  {[]string{"CWE-924", "CWE-328"}, "cpe:2.3:a:ietf:radius:*", 0.30},
	// Deep-handler CVEs (intel_amt / oracle_tns / mqtt / memcached).
	"CVE-2017-5689": {[]string{"CWE-287"}, "cpe:2.3:o:intel:active_management_technology_firmware:*", 0.94},
	"CVE-2012-1675": {[]string{"CWE-306"}, "cpe:2.3:a:oracle:database_server:*", 0.15},
	"CVE-2017-7650": {[]string{"CWE-287"}, "cpe:2.3:a:eclipse:mosquitto:*", 0.05},
	"CVE-2016-8704": {[]string{"CWE-190"}, "cpe:2.3:a:memcached:memcached:*", 0.10},
	"CVE-2016-8705": {[]string{"CWE-190"}, "cpe:2.3:a:memcached:memcached:*", 0.10},
	"CVE-2016-8706": {[]string{"CWE-190"}, "cpe:2.3:a:memcached:memcached:*", 0.10},
	"CVE-2024-3094":  {[]string{"CWE-506"}, "cpe:2.3:a:tukaani:xz:*", 0.10},
	"CVE-2024-49112": {[]string{"CWE-190"}, "cpe:2.3:o:microsoft:windows_server:*", 0.30},
	"CVE-2024-49113": {[]string{"CWE-190"}, "cpe:2.3:o:microsoft:windows_server:*", 0.40},
}

func init() {
	for i := range catalog {
		for j, s := range catalog[i].Signatures {
			catalog[i].Signatures[j] = strings.ToLower(s)
		}
		if e, ok := cveExtra[catalog[i].ID]; ok {
			catalog[i].CWE = e.CWE
			catalog[i].CPE = e.CPE
			catalog[i].EPSS = e.EPSS
		}
	}
	// Build the lookup indexes once (the catalog never changes at runtime), so
	// the per-request MatchPayload / per-event Lookup / list paths don't rescan
	// or re-sort all ~500 records on every call.
	catalogByService = make(map[string][]Record, 64)
	catalogByID = make(map[string]Record, len(catalog))
	for _, r := range catalog {
		catalogByService[r.Service] = append(catalogByService[r.Service], r)
		catalogByID[r.ID] = r
	}
	catalogSorted = append([]Record(nil), catalog...)
	sort.Slice(catalogSorted, func(i, j int) bool { return catalogSorted[i].ID < catalogSorted[j].ID })
}

// catalog indexes built in init() (the catalog is immutable at runtime).
var (
	catalogByService map[string][]Record // record.Service → records
	catalogByID      map[string]Record   // record.ID → record
	catalogSorted    []Record            // catalog sorted by ID
)

// candidateServices returns the record services a listener handler can match,
// applying the service aliasing (https→http; implicit-TLS mail variants
// imaps/pop3s/smtps inherit their plaintext service's CVEs).
func candidateServices(handler string) []string {
	switch handler {
	case "https":
		return []string{"https", "http"}
	case "imaps":
		return []string{"imaps", "imap"}
	case "pop3s":
		return []string{"pop3s", "pop3"}
	case "smtps":
		return []string{"smtps", "smtp_recv"}
	}
	return []string{handler}
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
	for _, svc := range candidateServices(handler) {
		for _, r := range catalogByService[svc] {
			for _, sig := range r.Signatures { // sigs are already lowercase
				if strings.Contains(low, sig) {
					out = append(out, r)
					break
				}
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
	for _, svc := range candidateServices(handler) {
		out = append(out, catalogByService[svc]...)
	}
	return out
}

// All returns a copy of the full CVE catalog sorted by id. Records with
// no Signatures are advisory-only (banner / patch-level emulation); the
// rest are also recognized as live exploit attempts by MatchPayload.
// Used by `tarpit-honeypot list-cves`.
func All() []Record {
	// catalogSorted is built once in init(); return a copy so callers can't
	// mutate the cached order.
	return append([]Record(nil), catalogSorted...)
}

// Detectable reports whether a record carries exploit signatures (so
// MatchPayload can flag a live attempt) versus being advisory-only.
func (r Record) Detectable() bool { return len(r.Signatures) > 0 }

// Lookup returns the record for an exact CVE id (O(1) via the id index).
func Lookup(id string) (Record, bool) {
	r, ok := catalogByID[id]
	return r, ok
}
