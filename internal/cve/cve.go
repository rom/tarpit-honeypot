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
	// ---- Additional advisory-only records (binary/version/non-HTTP) ----
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
	"CVE-2018-7600":  {[]string{"CWE-20", "CWE-94"}, "cpe:2.3:a:drupal:drupal:*", 0.97},
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
