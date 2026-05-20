package archetype

import "crypto/tls"

// windowsArchetypes covers the Windows client + server line. Key
// consistency points reproduced here:
//   - httpServer is the matching IIS version (IIS 7.0 ships with
//     Server 2008, 7.5 with 2008 R2 / Win7, 8.0 with 2012 / Win8,
//     8.5 with 2012 R2 / Win8.1, 10.0 with 2016+ / Win10+).
//   - SNMP sysObjectID is under the Microsoft enterprise OID
//     .1.3.6.1.4.1.311.1.1.3.1.x.
//   - Older releases advertise weak TLS (Server 2008 caps at TLS 1.0,
//     2012/2012R2 at TLS 1.2 with CBC ciphers) so the negotiated
//     protocol matches the firmware era.
//   - icmpTTL 128 (Windows default) for traceroute / OS fingerprint
//     consistency.
//   - cliPrompt is the cmd.exe "C:\>" form; pre-OpenSSH Windows has no
//     ssh banner (sshBanner left empty), modern (Win10 1809+/Server
//     2019+) ships OpenSSH-for-Windows.
var windowsArchetypes = map[string]*Profile{
	"windows-7": {
		Name: "windows-7", DisplayName: "Windows 7", Family: "windows",
		macOUI:          [3]byte{}, // hardware-dependent; no pinned OUI
		httpServer:      "Microsoft-IIS/7.5",
		smtpProduct:     "Microsoft ESMTP MAIL Service",
		cliPrompt:       "C:\\Users\\Administrator>",
		httpTitle:       "IIS7",
		httpBodyHTML:    iis7WelcomeHTML,
		snmpSysDescr:    "Hardware: Intel64 Family 6 Model 60 Stepping 3 AT/AT COMPATIBLE - Software: Windows Version 6.1 (Build 7601 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.1",
		snmpSysName:     "WIN7-CLIENT",
		icmpTTL:         128,
		tls:             TLSPosture{MaxVersion: tls.VersionTLS11, WeakCiphers: true},
		defaultServices: []DefaultService{
			{Port: 135, Handler: "dcerpc", Note: "RPC endpoint mapper"},
			{Port: 139, Handler: "raw", Note: "NetBIOS session"},
			{Port: 445, Handler: "smb"},
			{Port: 3389, Handler: "rdp"},
		},
		quirks: []string{"windows-no-ssh", "smbv1"},
	},
	"windows-8": {
		Name: "windows-8", DisplayName: "Windows 8", Family: "windows",
		httpServer:      "Microsoft-IIS/8.0",
		smtpProduct:     "Microsoft ESMTP MAIL Service",
		cliPrompt:       "C:\\Users\\Administrator>",
		httpTitle:       "IIS8",
		httpBodyHTML:    iis8WelcomeHTML,
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 6.2 (Build 9200 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.1",
		snmpSysName:     "WIN8-CLIENT",
		icmpTTL:         128,
		tls:             TLSPosture{MaxVersion: tls.VersionTLS12, WeakCiphers: true},
		defaultServices: []DefaultService{
			{Port: 135, Handler: "dcerpc"}, {Port: 445, Handler: "smb"}, {Port: 3389, Handler: "rdp"},
		},
		quirks: []string{"windows-no-ssh"},
	},
	"windows-10": {
		Name: "windows-10", DisplayName: "Windows 10", Family: "windows",
		sshBanner:       "SSH-2.0-OpenSSH_for_Windows_8.1",
		httpServer:      "Microsoft-IIS/10.0",
		smtpProduct:     "Microsoft ESMTP MAIL Service",
		cliPrompt:       "C:\\Users\\Administrator>",
		httpTitle:       "IIS Windows",
		httpBodyHTML:    iis10WelcomeHTML,
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 19045 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.1",
		snmpSysName:     "WIN10-CLIENT",
		icmpTTL:         128,
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh", Note: "OpenSSH for Windows (optional feature)"},
			{Port: 135, Handler: "dcerpc"}, {Port: 445, Handler: "smb"}, {Port: 3389, Handler: "rdp"},
			{Port: 5985, Handler: "winrm"},
		},
	},
	"windows-11": {
		Name: "windows-11", DisplayName: "Windows 11", Family: "windows",
		sshBanner:       "SSH-2.0-OpenSSH_for_Windows_9.5",
		httpServer:      "Microsoft-IIS/10.0",
		smtpProduct:     "Microsoft ESMTP MAIL Service",
		cliPrompt:       "C:\\Users\\Administrator>",
		httpTitle:       "IIS Windows",
		httpBodyHTML:    iis10WelcomeHTML,
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 22631 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.1",
		snmpSysName:     "WIN11-CLIENT",
		icmpTTL:         128,
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 135, Handler: "dcerpc"},
			{Port: 445, Handler: "smb"}, {Port: 3389, Handler: "rdp"}, {Port: 5985, Handler: "winrm"},
		},
	},
	"windows-server-2008": {
		Name: "windows-server-2008", DisplayName: "Windows Server 2008", Family: "windows",
		httpServer:      "Microsoft-IIS/7.0",
		smtpProduct:     "Microsoft ESMTP MAIL Service",
		cliPrompt:       "C:\\Windows\\system32>",
		httpTitle:       "IIS7",
		httpBodyHTML:    iis7WelcomeHTML,
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 6.0 (Build 6002 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "WIN-SRV2008",
		icmpTTL:         128,
		tls:             TLSPosture{MaxVersion: tls.VersionTLS10, WeakCiphers: true},
		defaultServices: []DefaultService{
			{Port: 135, Handler: "dcerpc"}, {Port: 139, Handler: "raw"}, {Port: 445, Handler: "smb"},
			{Port: 389, Handler: "ldap"}, {Port: 88, Handler: "kerberos"}, {Port: 3389, Handler: "rdp"},
		},
		quirks: []string{"windows-no-ssh", "smbv1", "ancient-firmware"},
	},
	"windows-server-2012": {
		Name: "windows-server-2012", DisplayName: "Windows Server 2012", Family: "windows",
		httpServer:      "Microsoft-IIS/8.0",
		smtpProduct:     "Microsoft ESMTP MAIL Service",
		cliPrompt:       "C:\\Windows\\system32>",
		httpTitle:       "IIS8",
		httpBodyHTML:    iis8WelcomeHTML,
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 6.2 (Build 9200 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "WIN-SRV2012",
		icmpTTL:         128,
		tls:             TLSPosture{MaxVersion: tls.VersionTLS12, WeakCiphers: true},
		defaultServices: []DefaultService{
			{Port: 135, Handler: "dcerpc"}, {Port: 445, Handler: "smb"}, {Port: 389, Handler: "ldap"},
			{Port: 88, Handler: "kerberos"}, {Port: 3389, Handler: "rdp"}, {Port: 5985, Handler: "winrm"},
		},
		quirks: []string{"windows-no-ssh"},
	},
	"windows-server-2012-r2": {
		Name: "windows-server-2012-r2", DisplayName: "Windows Server 2012 R2", Family: "windows",
		httpServer:      "Microsoft-IIS/8.5",
		smtpProduct:     "Microsoft ESMTP MAIL Service",
		cliPrompt:       "C:\\Windows\\system32>",
		httpTitle:       "IIS8",
		httpBodyHTML:    iis8WelcomeHTML,
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 6.3 (Build 9600 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "WIN-SRV2012R2",
		icmpTTL:         128,
		tls:             TLSPosture{MaxVersion: tls.VersionTLS12, WeakCiphers: true},
		defaultServices: []DefaultService{
			{Port: 135, Handler: "dcerpc"}, {Port: 445, Handler: "smb"}, {Port: 389, Handler: "ldap"},
			{Port: 88, Handler: "kerberos"}, {Port: 3389, Handler: "rdp"}, {Port: 5985, Handler: "winrm"},
		},
		quirks: []string{"windows-no-ssh"},
	},
	"windows-server-2016": {
		Name: "windows-server-2016", DisplayName: "Windows Server 2016", Family: "windows",
		httpServer:      "Microsoft-IIS/10.0",
		smtpProduct:     "Microsoft ESMTP MAIL Service",
		cliPrompt:       "C:\\Windows\\system32>",
		httpTitle:       "IIS Windows Server",
		httpBodyHTML:    iis10WelcomeHTML,
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 14393 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "WIN-SRV2016",
		icmpTTL:         128,
		defaultServices: []DefaultService{
			{Port: 135, Handler: "dcerpc"}, {Port: 445, Handler: "smb"}, {Port: 389, Handler: "ldap"},
			{Port: 88, Handler: "kerberos"}, {Port: 3389, Handler: "rdp"}, {Port: 5985, Handler: "winrm"},
		},
		quirks: []string{"windows-no-ssh"},
	},
	"windows-server-2019": {
		Name: "windows-server-2019", DisplayName: "Windows Server 2019", Family: "windows",
		sshBanner:       "SSH-2.0-OpenSSH_for_Windows_7.7",
		httpServer:      "Microsoft-IIS/10.0",
		smtpProduct:     "Microsoft ESMTP MAIL Service",
		cliPrompt:       "C:\\Windows\\system32>",
		httpTitle:       "IIS Windows Server",
		httpBodyHTML:    iis10WelcomeHTML,
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 17763 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "WIN-SRV2019",
		icmpTTL:         128,
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 135, Handler: "dcerpc"}, {Port: 445, Handler: "smb"},
			{Port: 389, Handler: "ldap"}, {Port: 88, Handler: "kerberos"}, {Port: 3389, Handler: "rdp"},
			{Port: 5985, Handler: "winrm"},
		},
	},
	"windows-server-2022": {
		Name: "windows-server-2022", DisplayName: "Windows Server 2022", Family: "windows",
		sshBanner:       "SSH-2.0-OpenSSH_for_Windows_8.6",
		httpServer:      "Microsoft-IIS/10.0",
		smtpProduct:     "Microsoft ESMTP MAIL Service",
		cliPrompt:       "C:\\Windows\\system32>",
		httpTitle:       "IIS Windows Server",
		httpBodyHTML:    iis10WelcomeHTML,
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 20348 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "WIN-SRV2022",
		icmpTTL:         128,
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 135, Handler: "dcerpc"}, {Port: 445, Handler: "smb"},
			{Port: 389, Handler: "ldap"}, {Port: 88, Handler: "kerberos"}, {Port: 3389, Handler: "rdp"},
			{Port: 5985, Handler: "winrm"},
		},
	},
}

// The IIS default-page HTML is version-distinctive: IIS 7/8 ship the
// blue "IIS7"/"IIS8" splash with the welcome.png reference; IIS 10
// ships the flat "Internet Information Services" page. Reproducing the
// right one per archetype defeats the "page doesn't match the Server
// header" tell.
const iis7WelcomeHTML = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head><title>IIS7</title>
<style type="text/css">body{margin:0;font-size:.7em;font-family:Verdana,Arial,sans-serif;background:#EEEEEE;}</style></head>
<body><div id="header"><h1>Welcome</h1></div>
<div id="content"><img src="welcome.png" alt="IIS7" /></div></body></html>`

const iis8WelcomeHTML = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head><title>IIS8</title>
<style type="text/css">body{margin:0;font-size:.7em;font-family:Verdana,Arial,sans-serif;background:#EEEEEE;}</style></head>
<body><div id="header"><h1>Welcome</h1></div>
<div id="content"><img src="iisstart.png" alt="IIS8" /></div></body></html>`

const iis10WelcomeHTML = `<!DOCTYPE html>
<html><head><title>IIS Windows Server</title>
<style type="text/css">body{color:#000;background-color:#fff;margin:0;}
#container{margin-left:auto;margin-right:auto;text-align:center;}</style></head>
<body><div id="container"><a href="http://www.microsoft.com/web/"><img src="iisstart.png" alt="IIS" width="960" height="600" /></a></div></body></html>`
