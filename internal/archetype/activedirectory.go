package archetype

import "crypto/tls"

// adArchetypes models a Windows Active Directory Domain Controller — the
// single highest-value target in most enterprise networks. The point of
// the archetype is the *protocol mix* a real DC exposes (Kerberos, LDAP
// + LDAPS, Global Catalog, SMB, DCE/RPC endpoint mapper, DNS, WinRM,
// AD Web Services) plus a believable, deliberately-behind patch level so
// a scanner fingerprints it as an exploitable DC.
//
// cliPrompt is the PowerShell prompt (DCs are managed via PowerShell /
// WinRM), which routes the interactive shell to the PowerShell command
// emulator. The DC presents as Server 2019 RTM so ZeroLogon /
// PrintNightmare / ProxyLogon-era CVEs line up with the build.
//
// Registered under several aliases ("active directory", "domain
// controller", "windows server 2019 ad") so operators can name it
// naturally in sensor.archetype.
var adArchetypes = map[string]*Profile{
	"active-directory": adProfile("active-directory"),
	// Aliases resolve to an equivalent profile (normalize() folds the
	// spaces/case in sensor.archetype).
	"domain-controller":           adProfile("domain-controller"),
	"windows-server-2019-ad":      adProfile("windows-server-2019-ad"),
	"windows-server-2019-dc":      adProfile("windows-server-2019-dc"),
	"windows-active-directory-dc": adProfile("windows-active-directory-dc"),
}

func adProfile(name string) *Profile {
	return &Profile{
		Name:        name,
		DisplayName: "Active Directory (Windows Server 2019 DC)",
		Family:      "windows",
		httpServer:  "Microsoft-IIS/10.0",
		smtpProduct: "Microsoft ESMTP MAIL Service",
		// PowerShell prompt -> drives the powershell command emulator.
		cliPrompt:    "PS C:\\Windows\\system32> ",
		httpTitle:    "IIS Windows Server",
		httpBodyHTML: iis10WelcomeHTML,
		snmpSysDescr: "Hardware: Intel64 Family 6 Model 85 Stepping 7 AT/AT COMPATIBLE - Software: Windows Version 10.0 (Build 17763 Multiprocessor Free)",
		// Microsoft enterprise OID; .1.1.3.1.2 = domain controller role.
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "DC01",
		snmpSysContact:  "Administrator@corp.local",
		snmpSysLocation: "HQ Datacenter Rack 3",
		icmpTTL:         128,
		// Server 2019 negotiates TLS 1.2 (LDAPS / WinRM-HTTPS); not 1.3
		// by default on RTM.
		tls: TLSPosture{MaxVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 53, Handler: "dns", Note: "AD-integrated DNS"},
			{Port: 88, Handler: "kerberos", Note: "Kerberos KDC"},
			{Port: 135, Handler: "dcerpc", Note: "RPC endpoint mapper"},
			{Port: 139, Handler: "raw", Note: "NetBIOS session"},
			{Port: 389, Handler: "ldap", Note: "LDAP"},
			{Port: 445, Handler: "smb", Note: "SMB / AD file replication"},
			{Port: 464, Handler: "raw", Note: "kpasswd"},
			{Port: 636, Handler: "https", Note: "LDAPS"},
			{Port: 3268, Handler: "ldap", Note: "Global Catalog"},
			{Port: 3269, Handler: "https", Note: "Global Catalog over SSL"},
			{Port: 3389, Handler: "rdp", Note: "Remote Desktop"},
			{Port: 5985, Handler: "winrm", Note: "WinRM / PowerShell Remoting"},
			{Port: 9389, Handler: "raw", Note: "AD Web Services (ADWS)"},
		},
		patchLevel: "Windows Server 2019 RTM (build 17763.107, pre-2020-08 rollup)",
		cveVulns: []string{
			"CVE-2020-1472",  // ZeroLogon (Netlogon)
			"CVE-2021-34527", // PrintNightmare (Print Spooler)
			"CVE-2021-26855", // ProxyLogon (when co-hosting Exchange)
			"CVE-2021-42278", // sAMAccountName spoofing (noPac)
		},
		quirks: []string{"active-directory", "domain-controller", "powershell"},
	}
}
