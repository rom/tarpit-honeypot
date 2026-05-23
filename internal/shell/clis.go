package shell

import (
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

// This file holds the non-POSIX command-emulation tables: Windows
// cmd.exe, PowerShell (incl. Active Directory cmdlets), Cisco IOS, and
// the Siemens S7 PLC console. Like the POSIX table, every response is
// canned text — nothing is ever executed. The anomaly scanner
// (scanAnomalies) runs on the raw line regardless of family, so a
// PowerShell `IEX (New-Object Net.WebClient).DownloadString(...)` is
// flagged the same way a bash reverse shell is.

// foldCommands reports whether command lookup for this archetype should
// be case-insensitive. Windows (cmd/PowerShell), Cisco IOS, Moxa, and
// Siemens CLIs are all case-insensitive; POSIX shells are not.
func foldCommands(p *archetype.Profile) bool {
	if p == nil {
		return false
	}
	switch p.Family {
	case "windows", "cisco", "moxa", "siemens":
		return true
	}
	return false
}

// ---- Windows cmd.exe ----

func cmdResponses(p *archetype.Profile) map[string]response {
	host := "WIN-HOST"
	ver := "Microsoft Windows [Version 10.0.19045.3693]"
	if p != nil {
		if n := p.SNMPSysName(); n != "" {
			host = n
		}
		if d := p.SNMPSysDescr(); d != "" && strings.Contains(d, "Windows Version") {
			ver = "Microsoft Windows [" + extractWinVersion(d) + "]"
		}
	}
	return map[string]response{
		"ver":      {static: ver + "\r\n"},
		"hostname": {static: host + "\r\n"},
		"whoami":   {static: "nt authority\\system\r\n"},
		"echo":     {dyn: func(a []string) string { return strings.Join(a[1:], " ") + "\r\n" }},
		"cd":       {static: "C:\\Windows\\system32\r\n"},
		"cls":      {static: "\x1b[H\x1b[2J"},
		"dir":      {dyn: winDir},
		"type": {dyn: func(a []string) string {
			return "The system cannot find the file specified.\r\n"
		}},
		"ipconfig": {static: "\r\nWindows IP Configuration\r\n\r\nEthernet adapter Ethernet0:\r\n   IPv4 Address. . . . . . . . . . . : 10.0.0.10\r\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n   Default Gateway . . . . . . . . . : 10.0.0.1\r\n"},
		"net": {dyn: func(a []string) string {
			if len(a) >= 2 && strings.EqualFold(a[1], "user") {
				return "User accounts for \\\\" + host + "\r\n\r\nAdministrator            DefaultAccount           Guest\r\nkrbtgt                   svc_backup               jsmith\r\nThe command completed successfully.\r\n"
			}
			if len(a) >= 2 && strings.EqualFold(a[1], "group") {
				return "Group Accounts for \\\\" + host + "\r\n\r\n*Domain Admins\r\n*Domain Users\r\n*Enterprise Admins\r\nThe command completed successfully.\r\n"
			}
			return "The syntax of this command is:\r\n\r\nNET [ ACCOUNTS | COMPUTER | CONFIG | USER | GROUP | ... ]\r\n"
		}},
		"systeminfo": {static: "Host Name:                 " + host + "\r\nOS Name:                   Microsoft Windows Server 2019 Standard\r\nOS Version:                10.0.17763 N/A Build 17763\r\nSystem Type:               x64-based PC\r\nDomain:                    corp.local\r\n"},
		"tasklist":   {static: "Image Name                     PID Session Name        Mem Usage\r\n========================= ======== ================ ============\r\nSystem                           4 Services             140 K\r\nlsass.exe                      612 Services          12,300 K\r\nsvchost.exe                     900 Services          22,140 K\r\n"},
		"sc":         {static: "[SC] EnumQueryServicesStatus: OpenService FAILED 5:\r\n\r\nAccess is denied.\r\n"},
		"tree":       {static: "Folder PATH listing\r\nVolume serial number is 1234-5678\r\nC:.\r\n"},
		"ping": {dyn: func(a []string) string {
			return "Pinging " + lastArg(a) + " with 32 bytes of data:\r\nRequest timed out.\r\n"
		}},
		"powershell": {static: "Windows PowerShell\r\nCopyright (C) Microsoft Corporation. All rights reserved.\r\n\r\nPS C:\\> "},
	}
}

func winDir(argv []string) string {
	return " Volume in drive C has no label.\r\n Volume Serial Number is 1234-5678\r\n\r\n Directory of C:\\Users\\Administrator\r\n\r\n05/19/2025  02:14 PM    <DIR>          .\r\n05/19/2025  02:14 PM    <DIR>          ..\r\n05/19/2025  02:14 PM    <DIR>          Desktop\r\n05/19/2025  02:14 PM    <DIR>          Documents\r\n05/19/2025  02:14 PM             1,024 notes.txt\r\n               1 File(s)          1,024 bytes\r\n"
}

// extractWinVersion turns an SNMP sysDescr like
// "... Software: Windows Version 10.0 (Build 19045 Multiprocessor Free)"
// into the cmd.exe `ver` form "Version 10.0.19045".
func extractWinVersion(descr string) string {
	const def = "Version 10.0.19045.3693"
	i := strings.Index(descr, "Windows Version ")
	if i < 0 {
		return def
	}
	rest := descr[i+len("Windows Version "):]
	ver := rest
	if sp := strings.IndexByte(ver, ' '); sp >= 0 {
		ver = ver[:sp] // "10.0"
	}
	if ver == "" {
		return def
	}
	out := "Version " + ver
	if b := strings.Index(rest, "Build "); b >= 0 {
		bs := rest[b+len("Build "):]
		n := 0
		for n < len(bs) && bs[n] >= '0' && bs[n] <= '9' {
			n++
		}
		if n > 0 {
			out += "." + bs[:n] // "10.0.19045"
		}
	}
	return out
}

// ---- PowerShell (incl. Active Directory cmdlets) ----

func powershellResponses(p *archetype.Profile) map[string]response {
	host := "DC01"
	if p != nil {
		if n := p.SNMPSysName(); n != "" {
			host = n
		}
	}
	psv := "5.1.17763.6189"
	return map[string]response{
		"get-host":        {static: "Name             : ConsoleHost\r\nVersion          : " + psv + "\r\nInstanceId       : 8f0e...\r\n"},
		"$psversiontable": {static: "Name                           Value\r\n----                           -----\r\nPSVersion                      " + psv + "\r\nPSEdition                      Desktop\r\nCLRVersion                     4.0.30319.42000\r\n"},
		"whoami":          {static: "corp\\administrator\r\n"},
		"hostname":        {static: host + "\r\n"},
		"get-process":     {static: "Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  ProcessName\r\n-------  ------    -----      -----     ------     --  -----------\r\n    612      28    12300      24500       1.20    612  lsass\r\n    340      18     8200      15400       0.45    900  svchost\r\n"},
		"get-service":     {static: "Status   Name               DisplayName\r\n------   ----               -----------\r\nRunning  ADWS               Active Directory Web Services\r\nRunning  DNS                DNS Server\r\nRunning  kdc                Kerberos Key Distribution Center\r\nRunning  Netlogon           Netlogon\r\n"},
		"get-localuser":   {static: "Name           Enabled Description\r\n----           ------- -----------\r\nAdministrator  True    Built-in administrator account\r\nGuest          False   Built-in guest account\r\nkrbtgt         False   Key Distribution Center Service Account\r\n"},
		"get-aduser": {dyn: func(a []string) string {
			return "DistinguishedName : CN=Administrator,CN=Users,DC=corp,DC=local\r\nEnabled           : True\r\nName              : Administrator\r\nSamAccountName    : Administrator\r\nSID               : S-1-5-21-1004336348-1177238915-682003330-500\r\nUserPrincipalName : administrator@corp.local\r\n"
		}},
		"get-addomain":           {static: "DNSRoot                            : corp.local\r\nNetBIOSName                        : CORP\r\nDomainMode                         : Windows2016Domain\r\nInfrastructureMaster               : " + host + ".corp.local\r\nPDCEmulator                        : " + host + ".corp.local\r\n"},
		"get-adcomputer":         {static: "DistinguishedName : CN=" + host + ",OU=Domain Controllers,DC=corp,DC=local\r\nDNSHostName       : " + host + ".corp.local\r\nEnabled           : True\r\nName              : " + host + "\r\n"},
		"get-addomaincontroller": {static: "Name            : " + host + "\r\nDomain          : corp.local\r\nForest          : corp.local\r\nIPv4Address     : 10.0.0.10\r\nOperatingSystem : Windows Server 2019 Standard\r\n"},
		"get-adgroupmember": {dyn: func(a []string) string {
			return "distinguishedName : CN=Administrator,CN=Users,DC=corp,DC=local\r\nname              : Administrator\r\nobjectClass       : user\r\nSID               : S-1-5-21-1004336348-1177238915-682003330-500\r\n"
		}},
		"get-childitem": {dyn: psDir},
		"dir":           {dyn: psDir},
		"ls":            {dyn: psDir},
		"get-content": {dyn: func(a []string) string {
			return "Get-Content : Cannot find path '" + lastArg(a) + "' because it does not exist.\r\n"
		}},
		"cat":              {dyn: func(a []string) string { return "Get-Content : Cannot find path because it does not exist.\r\n" }},
		"type":             {dyn: func(a []string) string { return "Get-Content : Cannot find path because it does not exist.\r\n" }},
		"get-computerinfo": {static: "WindowsProductName     : Windows Server 2019 Standard\r\nWindowsVersion         : 1809\r\nOsHardwareAbstractionLayer : 10.0.17763.6189\r\nCsDomain               : corp.local\r\nCsDomainRole           : PrimaryDomainController\r\n"},
		"ipconfig":         {static: "\r\nWindows IP Configuration\r\n\r\nEthernet adapter Ethernet0:\r\n   IPv4 Address. . . . . . . . . . . : 10.0.0.10\r\n   Default Gateway . . . . . . . . . : 10.0.0.1\r\n"},
		"echo":             {dyn: func(a []string) string { return strings.Join(a[1:], " ") + "\r\n" }},
		"write-host":       {dyn: func(a []string) string { return strings.Join(a[1:], " ") + "\r\n" }},
		"cd":               {static: ""},
		"set-location":     {static: ""},
		"clear":            {static: "\x1b[H\x1b[2J"},
		"cls":              {static: "\x1b[H\x1b[2J"},
		"clear-host":       {static: "\x1b[H\x1b[2J"},
		"invoke-webrequest": {dyn: func(a []string) string {
			return "Invoke-WebRequest : Unable to connect to the remote server\r\n"
		}},
		"iwr":               {dyn: func(a []string) string { return "Invoke-WebRequest : Unable to connect to the remote server\r\n" }},
		"iex":               {static: ""},
		"invoke-expression": {static: ""},
	}
}

func psDir(argv []string) string {
	return "\r\n    Directory: C:\\Users\\Administrator\r\n\r\nMode                 LastWriteTime         Length Name\r\n----                 -------------         ------ ----\r\nd-----        5/19/2025   2:14 PM                Desktop\r\nd-----        5/19/2025   2:14 PM                Documents\r\n-a----        5/19/2025   2:14 PM           1024 notes.txt\r\n"
}

// ---- Cisco IOS ----

func ciscoResponses(p *archetype.Profile) map[string]response {
	host := "Switch"
	if p != nil {
		if n := p.SNMPSysName(); n != "" {
			host = n
		}
	}
	return map[string]response{
		"enable":  {static: "Password: "},
		"disable": {static: ""},
		"?":       {static: "Exec commands:\r\n  enable   Turn on privileged commands\r\n  ping     Send echo messages\r\n  show     Show running system information\r\n  exit     Exit from the EXEC\r\n"},
		"show": {dyn: func(a []string) string {
			if len(a) < 2 {
				return "% Incomplete command.\r\n"
			}
			switch strings.ToLower(a[1]) {
			case "version":
				return "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)\r\nCopyright (c) 1986-2017 by Cisco Systems, Inc.\r\n\r\n" + host + " uptime is 47 weeks, 2 days\r\nSystem image file is \"flash:c2960-lanbasek9-mz.150-2.SE11.bin\"\r\ncisco WS-C2960-24TT-L (PowerPC405) processor (revision C0)\r\nBase ethernet MAC Address       : 00:1A:2B:3C:4D:5E\r\n"
			case "running-config", "run":
				return "Building configuration...\r\n\r\nCurrent configuration : 1284 bytes\r\n!\r\nversion 15.0\r\nhostname " + host + "\r\n!\r\nenable secret 5 $1$mERr$...\r\n!\r\ninterface GigabitEthernet0/1\r\n switchport mode access\r\n!\r\nline vty 0 4\r\n login local\r\n!\r\nend\r\n"
			case "ip":
				return "Interface              IP-Address      OK? Method Status                Protocol\r\nVlan1                  192.168.1.1     YES NVRAM  up                    up\r\nGigabitEthernet0/1     unassigned      YES unset  up                    up\r\n"
			case "vlan":
				return "VLAN Name                             Status    Ports\r\n---- -------------------------------- --------- -------------------------------\r\n1    default                          active    Gi0/2, Gi0/3\r\n10   MGMT                             active    Gi0/1\r\n"
			case "interfaces":
				return "GigabitEthernet0/1 is up, line protocol is up\r\n  Hardware is Gigabit Ethernet, address is 001a.2b3c.4d5e\r\n  MTU 1500 bytes, BW 1000000 Kbit/sec\r\n"
			case "cdp":
				return "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID\r\nplc-1500.corp    Gig 0/2           165         R S I       S7-1500   Gig 0/0\r\n"
			case "mac":
				return "          Mac Address Table\r\n-------------------------------------------\r\nVlan    Mac Address       Type        Ports\r\n   1    001a.2b3c.4d5e    DYNAMIC     Gi0/2\r\n"
			}
			return "% Invalid input detected\r\n"
		}},
		"configure": {static: "% Authorization failed.\r\n"},
		"conf":      {static: "% Authorization failed.\r\n"},
		"ping": {dyn: func(a []string) string {
			return "Type escape sequence to abort.\r\nSending 5, 100-byte ICMP Echos to " + lastArg(a) + ":\r\n.....\r\nSuccess rate is 0 percent (0/5)\r\n"
		}},
		"terminal": {static: ""},
	}
}

// ---- Siemens S7 PLC console ----

func plcResponses(p *archetype.Profile) map[string]response {
	vendor := "SIMATIC"
	model := "S7-1500"
	fw := "V2.9.2"
	if p != nil {
		if n := p.SNMPSysName(); n != "" {
			model = n
		}
		switch {
		case strings.Contains(p.Name, "1200"):
			model = "S7-1200"
			fw = "V4.5.1"
		case p.Family == "schneider":
			vendor, fw = "Schneider Modicon", "V3.40"
		case p.Family == "omron":
			vendor, fw = "Omron Sysmac", "V1.49"
		case p.Family == "mitsubishi":
			vendor, fw = "Mitsubishi MELSEC", "V1.290"
		}
	}
	return map[string]response{
		"?":    {static: "Available: info, show, diag, exit\r\n"},
		"help": {static: "Available: info, show, diag, exit\r\n"},
		"info": {static: vendor + " " + model + "\r\nFirmware: " + fw + "\r\nSerial: S C-X1U...\r\nOperating mode: RUN\r\n"},
		"show": {dyn: func(a []string) string {
			if len(a) < 2 {
				return "show {cpu|mode|diag|hardware}\r\n"
			}
			switch strings.ToLower(a[1]) {
			case "cpu":
				return "CPU " + model + "  Firmware " + fw + "\r\nMode: RUN\r\nCycle time (last): 2 ms\r\nMemory: 1 MB work / 5 MB load\r\n"
			case "mode":
				return "Operating mode: RUN\r\nStartup: WARM RESTART\r\n"
			case "diag":
				return "Diagnostic buffer (most recent first):\r\n  1: RUN mode transition - OK\r\n  2: Power on - OK\r\n"
			case "hardware":
				return "Rack 0:\r\n  Slot 1: PS\r\n  Slot 2: CPU " + model + "\r\n  Slot 3: DI 16x24VDC\r\n  Slot 4: DO 16x24VDC\r\n"
			}
			return "Unknown subcommand\r\n"
		}},
		"diag": {static: "Diagnostic buffer: no faults.\r\n"},
		"stop": {static: "% Mode change requires PG/key-switch authorization.\r\n"},
		"run":  {static: "% Mode change requires PG/key-switch authorization.\r\n"},
	}
}

// ---- Fortinet FortiOS (FortiGate) CLI ----

func fortiosResponses(p *archetype.Profile) map[string]response {
	host := "FortiGate"
	if p != nil {
		if n := p.SNMPSysName(); n != "" {
			host = n
		}
	}
	return map[string]response{
		"?": {static: "get      Get dynamic and system information\r\nshow     Show configuration\r\ndiagnose Diagnose facility\r\nexecute  Execute commands\r\nexit     Exit\r\n"},
		"get": {dyn: func(a []string) string {
			sub := strings.ToLower(strings.Join(a[1:], " "))
			switch {
			case strings.HasPrefix(sub, "system status"):
				return "Version: FortiGate-100F v7.2.5,build1517,230810 (GA.F)\r\nSerial-Number: FGT100F" + "TK20001234\r\nHostname: " + host + "\r\nOperation Mode: NAT\r\nCurrent HA mode: standalone\r\nSystem time: Mon Jan  1 00:00:00 2024\r\n"
			case strings.HasPrefix(sub, "system performance"):
				return "CPU states: 2% user 1% system 0% nice 97% idle\r\nMemory: 38% used\r\nUptime: 47 days\r\n"
			case strings.HasPrefix(sub, "system interface"):
				return "== [ port1 ]\r\nname: port1   ip: 192.168.1.99 255.255.255.0   status: up\r\n== [ port2 ]\r\nname: port2   ip: 0.0.0.0 0.0.0.0   status: down\r\n"
			case strings.HasPrefix(sub, "router info routing-table"):
				return "S* 0.0.0.0/0 [10/0] via 192.168.1.1, port1\r\nC  192.168.1.0/24 is directly connected, port1\r\n"
			}
			return "Unknown action 0\r\n"
		}},
		"show": {static: "config system global\r\n    set hostname \"" + host + "\"\r\n    set admin-sport 443\r\nend\r\n"},
		"diagnose": {dyn: func(a []string) string {
			return "diagnose: " + strings.Join(a[1:], " ") + ": permission denied (read-only admin)\r\n"
		}},
		"execute": {static: "execute: command requires read-write privileges\r\n"},
		"config":  {static: "command parse error before 'config'\r\nCommand fail. Return code -61\r\n"},
	}
}
