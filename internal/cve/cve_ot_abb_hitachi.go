package cve

// cveOTABBHitachi adds OT/ICS vulnerability simulations for ABB and Hitachi
// Energy products — two of the largest grid-automation and building-management
// vendors, and recurring targets of ICS scanning. The ABB Cylon Aspect building
// controllers are web-delivered (PHP on the device), so their unauthenticated
// command-injection endpoints carry a path signature that MatchPayload flags on
// the http handler; the deeper grid devices (Hitachi Energy MicroSCADA SYS600,
// RTU500, FOX61x; ABB Totalflow) are management/protocol issues represented
// advisory-only (banner / patch-level advertising via ForService). Sources:
// ABB and Hitachi Energy PSIRT advisories and the corresponding CISA ICS
// advisories. Detection + ATT&CK tagging only; nothing is executed.
var cveOTABBHitachi = []Record{
	// --- ABB Cylon Aspect (BMS/BAS controllers, web-delivered) ----------------
	{ID: "CVE-2023-0636", Name: "ABB Cylon Aspect networkDiagAjax.php command injection", CVSS: 9.8, Service: "http",
		Signatures: []string{"/networkdiagajax.php"},
		Technique:  "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:abb:aspect-enterprise_firmware:*:*:*:*:*:*:*:*", EPSS: 0.40,
		Description: "ABB Cylon Aspect (≤3.07.00) passes the networkDiagAjax.php 'host' parameter to an OS command, allowing command injection; ABB says auth is required but it is not consistently enforced."},
	{ID: "CVE-2024-48839", Name: "ABB Cylon Aspect servicesUpdate.php OS command injection", CVSS: 9.8, Service: "http",
		Signatures: []string{"/servicesupdate.php"},
		Technique:  "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:abb:aspect-enterprise_firmware:*:*:*:*:*:*:*:*", EPSS: 0.40,
		Description: "ABB Cylon Aspect building controllers (firmware ≤3.08.01) contain an unauthenticated blind OS command injection reachable via servicesUpdate.php."},
	{ID: "CVE-2024-48840", Name: "ABB Cylon Aspect deployStart.php command execution", CVSS: 9.8, Service: "http",
		Signatures: []string{"/deploystart.php"},
		Technique:  "T1190", Tactic: "initial-access", CWE: []string{"CWE-78"}, CPE: "cpe:2.3:o:abb:aspect-enterprise_firmware:*:*:*:*:*:*:*:*",
		Description: "ABB Cylon Aspect building controllers (firmware ≤3.08.02) allow unauthenticated command execution via the deployStart.php endpoint."},
	{ID: "CVE-2024-6209", Name: "ABB ASPECT unauthenticated file disclosure", CVSS: 7.5, Service: "http", Technique: "T1083", Tactic: "discovery", CWE: []string{"CWE-200"}, CPE: "cpe:2.3:o:abb:aspect-enterprise_firmware:*:*:*:*:*:*:*:*", Description: "ABB ASPECT building-management controllers expose sensitive device files to an unauthenticated attacker, leaking configuration/credential material used to deepen compromise."},
	{ID: "CVE-2025-53187", Name: "ABB ASPECT debug-code authentication bypass → RCE", CVSS: 9.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-489"}, CPE: "cpe:2.3:o:abb:aspect-enterprise_firmware:*:*:*:*:*:*:*:*", EPSS: 0.30, Description: "Debugging code left in production ABB ASPECT firmware provides an authentication bypass that an unauthenticated remote attacker chains into remote code execution (fixed in 3.08.04-s01)."},
	{ID: "CVE-2025-7679", Name: "ABB ASPECT missing authentication for critical function", CVSS: 8.1, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-306"}, CPE: "cpe:2.3:o:abb:aspect-enterprise_firmware:*:*:*:*:*:*:*:*", Description: "An ABB ASPECT building-controller function performs a security-critical action without authenticating the caller, letting a network attacker invoke it directly."},

	// --- ABB Totalflow (flow computer / RTU, TCP 9999) ------------------------
	{ID: "CVE-2022-0902", Name: "ABB Totalflow path traversal", CVSS: 8.1, Service: "totalflow", Technique: "T1083", Tactic: "discovery", CWE: []string{"CWE-22"}, CPE: "cpe:2.3:o:abb:rmc-100_firmware:*:*:*:*:*:*:*:*", Description: "ABB Totalflow flow computers and RTUs (RMC-100, XSeries, uFLO G5) contain a path-traversal flaw in their TCP/9999 protocol that lets an attacker read/write files outside the intended directory and tamper with the device."},

	// --- Hitachi Energy MicroSCADA / RTU500 / FOX61x --------------------------
	{ID: "CVE-2024-4872", Name: "Hitachi Energy MicroSCADA SYS600 query code injection", CVSS: 8.8, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-943"}, CPE: "cpe:2.3:a:hitachienergy:microscada_x_sys600:*:*:*:*:*:*:*:*", EPSS: 0.30, Description: "Hitachi Energy MicroSCADA Pro/X SYS600 fails to validate user-supplied queries, letting an authenticated attacker inject code toward persistent data (vendor: SQL injection) and compromise the SCADA server."},
	{ID: "CVE-2023-46143", Name: "Hitachi Energy RTU500 code-download integrity flaw", CVSS: 7.5, Service: "http", Technique: "T1190", Tactic: "initial-access", CWE: []string{"CWE-494"}, CPE: "cpe:2.3:o:hitachienergy:rtu500_firmware:*:*:*:*:*:*:*:*", Description: "Hitachi Energy RTU500 series CMU firmware does not verify the integrity of downloaded code, so an unauthenticated remote attacker can modify the applications running on the RTU."},
	{ID: "CVE-2023-1514", Name: "Hitachi Energy RTU500 scripting cert-validation bypass", CVSS: 5.9, Service: "http", Technique: "T1557", Tactic: "collection", CWE: []string{"CWE-295"}, CPE: "cpe:2.3:o:hitachienergy:rtu500_firmware:*:*:*:*:*:*:*:*", Description: "The RTU500 series scripting interface does not properly validate TLS certificates, allowing an adversary-in-the-middle to intercept or alter the scripting channel."},
	{ID: "CVE-2024-2461", Name: "Hitachi Energy FOX61x path traversal", CVSS: 4.9, Service: "http", Technique: "T1083", Tactic: "discovery", CWE: []string{"CWE-23"}, CPE: "cpe:2.3:o:hitachienergy:fox61x_firmware:*:*:*:*:*:*:*:*", Description: "A relative path-traversal flaw in Hitachi Energy FOX61x (R15A and prior, R15B, R16A, R16B ≤ Rev.E) lets an attacker reach files and directories outside the intended scope on the multiplexer management plane."},
}
