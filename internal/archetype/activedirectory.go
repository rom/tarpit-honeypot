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
// All aliases resolve to one canonical profile (Name "active-directory")
// so dedup in All()/Names() is deterministic regardless of which alias the
// operator names in sensor.archetype. normalize() folds spaces/case.
var adArchetypes = map[string]*Profile{
	"active-directory":            adProfile(),
	"domain-controller":           adProfile(),
	"windows-server-2019-ad":      adProfile(),
	"windows-server-2019-dc":      adProfile(),
	"windows-active-directory-dc": adProfile(),
	// Domain controllers pinned to an OS version + AD forest/domain functional
	// level (msDS-Behavior-Version: 2008 R2 = 4, 2012 = 5, 2016 = 7) — the level
	// an attacker reads from the rootDSE to gauge attack surface.
	"windows-2008r2-ad": adDCProfile("windows-2008r2-ad",
		"Active Directory DC (Windows Server 2008 R2, FFL 4)", "7601", iis8WelcomeHTML,
		"DC-2008R2", 4, []string{"CVE-2017-0144", "CVE-2020-1472"}),
	"windows-2012-ad": adDCProfile("windows-2012-ad",
		"Active Directory DC (Windows Server 2012, FFL 5)", "9200", iis8WelcomeHTML,
		"DC-2012", 5, []string{"CVE-2017-0144", "CVE-2020-1472", "CVE-2021-34527"}),
	"windows-2016-ad": adDCProfile("windows-2016-ad",
		"Active Directory DC (Windows Server 2016, FFL 7)", "14393", iis10WelcomeHTML,
		"DC-2016", 7, []string{"CVE-2020-1472", "CVE-2021-34527", "CVE-2021-42278"}),
}

// adDCProfile builds a domain-controller profile pinned to an OS build + AD
// functional level. Same DC protocol mix as adProfile(); identity (build, IIS
// welcome page, hostname) and advertised CVEs match the era, and the functional
// level is carried in the display name + an adfl:<n> quirk.
func adDCProfile(name, display, build, iisHTML, sysName string, fl int, cves []string) *Profile {
	iisVer := "Microsoft-IIS/10.0"
	if build == "7601" {
		iisVer = "Microsoft-IIS/7.5"
	} else if build == "9200" {
		iisVer = "Microsoft-IIS/8.0"
	}
	return &Profile{
		Name:            name,
		DisplayName:     display,
		Family:          "windows",
		httpServer:      iisVer,
		smtpProduct:     "Microsoft ESMTP MAIL Service",
		cliPrompt:       "PS C:\\Windows\\system32> ",
		httpTitle:       "IIS Windows Server",
		httpBodyHTML:    iisHTML,
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows (Build " + build + " Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     sysName,
		snmpSysContact:  "Administrator@corp.local",
		snmpSysLocation: "HQ Datacenter",
		icmpTTL:         128,
		tls:             TLSPosture{MaxVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 53, Handler: "dns", Note: "AD-integrated DNS"},
			{Port: 88, Handler: "kerberos", Note: "Kerberos KDC"},
			{Port: 135, Handler: "dcerpc", Note: "RPC endpoint mapper"},
			{Port: 139, Handler: "raw", Note: "NetBIOS session"},
			{Port: 389, Handler: "ldap", Note: "LDAP"},
			{Port: 445, Handler: "smb", Note: "SMB / AD replication"},
			{Port: 464, Handler: "raw", Note: "kpasswd"},
			{Port: 636, Handler: "https", Note: "LDAPS"},
			{Port: 3268, Handler: "ldap", Note: "Global Catalog"},
			{Port: 3269, Handler: "https", Note: "Global Catalog over SSL"},
			{Port: 3389, Handler: "rdp", Note: "Remote Desktop"},
			{Port: 5985, Handler: "winrm", Note: "WinRM / PowerShell Remoting"},
			{Port: 9389, Handler: "raw", Note: "AD Web Services (ADWS)"},
		},
		patchLevel: display,
		cveVulns:   cves,
		quirks:     []string{"active-directory", "domain-controller", "powershell", "adfl:" + string(rune('0'+fl))},
	}
}

func adProfile() *Profile {
	return &Profile{
		Name:        "active-directory",
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
