package archetype

import "crypto/tls"

// enterprise2Archetypes adds legacy-Unix, alternative-Linux, and more
// network/security-appliance personas: Solaris, AIX, Gentoo, OPNsense,
// VyOS, OpenWrt, Arista EOS, Check Point Gaia, Dell iDRAC, HPE iLO. Merged
// into the registry by init().
var enterprise2Archetypes = map[string]*Profile{
	"solaris-11": {
		Name: "solaris-11", DisplayName: "Oracle Solaris 11", Family: "solaris",
		sshBanner:    "SSH-2.0-Sun_SSH_2.2",
		httpServer:   "Apache/2.4.51 (Unix)",
		ftpBanner:    "220 solaris FTP server ready.",
		telnetBanner: "\r\nSunOS 5.11\r\n\r\nlogin: ",
		loginPrompt:  "login: ",
		cliPrompt:    "root@solaris:~# ",
		snmpSysDescr: "SunOS solaris 5.11 11.4 sun4v sparc",
		snmpSysName:  "solaris", snmpSysObjectID: ".1.3.6.1.4.1.42",
		icmpTTL: 255, // classic Solaris default TTL
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 23, Handler: "telnet"},
			{Port: 79, Handler: "raw", Note: "finger"}, {Port: 111, Handler: "rpcbind"},
		},
		quirks: []string{"solaris"},
	},
	"aix-7": {
		Name: "aix-7", DisplayName: "IBM AIX 7.2", Family: "aix",
		sshBanner:    "SSH-2.0-OpenSSH_8.1",
		httpServer:   "IBM_HTTP_Server",
		ftpBanner:    "220 aix FTP server (Version 4.2) ready.",
		telnetBanner: "\r\nAIX Version 7.2\r\nlogin: ",
		loginPrompt:  "login: ",
		cliPrompt:    "# ",
		snmpSysDescr: "IBM PowerPC CHRP Computer AIX version 7.2",
		snmpSysName:  "aix", snmpSysObjectID: ".1.3.6.1.4.1.2.6.13",
		icmpTTL: 255,
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 23, Handler: "telnet"}, {Port: 111, Handler: "rpcbind"},
		},
		quirks: []string{"aix"},
	},
	"gentoo": {
		Name: "gentoo", DisplayName: "Gentoo Linux", Family: "gentoo",
		sshBanner:    "SSH-2.0-OpenSSH_9.8",
		httpServer:   "Apache/2.4.62 (Gentoo)",
		ftpBanner:    "220 ProFTPD Server (Gentoo)",
		cliPrompt:    "gentoo ~ # ",
		snmpSysDescr: "Linux gentoo 6.6.30-gentoo #1 SMP x86_64 GNU/Linux",
		snmpSysName:  "gentoo", snmpSysObjectID: ".1.3.6.1.4.1.8072.3.2.10",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 80, Handler: "http"}, {Port: 443, Handler: "https"},
		},
		quirks: []string{"source-based"},
	},
	"opnsense": {
		Name: "opnsense", DisplayName: "OPNsense firewall", Family: "opnsense",
		sshBanner:    "SSH-2.0-OpenSSH_9.6 FreeBSD-20240301",
		httpServer:   "OPNsense",
		httpTitle:    "Login | OPNsense",
		httpBodyHTML: "<html><head><title>Login | OPNsense</title></head><body>OPNsense</body></html>",
		cliPrompt:    "root@opnsense:~ # ",
		snmpSysDescr: "OPNsense fw.local FreeBSD 14.1-RELEASE amd64",
		snmpSysName:  "opnsense", snmpSysObjectID: ".1.3.6.1.4.1.8072.3.2.10",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 443, Handler: "https", Note: "web GUI"}, {Port: 22, Handler: "ssh"},
		},
		quirks: []string{"freebsd"},
	},
	"vyos": {
		Name: "vyos", DisplayName: "VyOS router", Family: "vyos",
		sshBanner:    "SSH-2.0-OpenSSH_9.2p1 Debian-2",
		httpServer:   "nginx",
		cliPrompt:    "vyos@vyos:~$ ",
		snmpSysDescr: "VyOS 1.4 (sagitta) Linux 6.1.0 x86_64",
		snmpSysName:  "vyos", snmpSysObjectID: ".1.3.6.1.4.1.44641",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 443, Handler: "https"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"debian-based-router"},
	},
	"openwrt": {
		Name: "openwrt", DisplayName: "OpenWrt router", Family: "openwrt",
		sshBanner:    "SSH-2.0-dropbear_2022.83",
		httpServer:   "uhttpd",
		httpTitle:    "LuCI - Lua Configuration Interface",
		httpBodyHTML: "<html><head><title>OpenWrt - LuCI</title></head><body>OpenWrt</body></html>",
		cliPrompt:    "root@OpenWrt:~# ",
		snmpSysDescr: "Linux OpenWrt 5.15.150 #0 SMP mips GNU/Linux",
		snmpSysName:  "OpenWrt", snmpSysObjectID: ".1.3.6.1.4.1.8072.3.2.10",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 80, Handler: "http"}, {Port: 443, Handler: "https"},
		},
		quirks: []string{"dropbear-ssh"},
	},
	"arista-eos": {
		Name: "arista-eos", DisplayName: "Arista EOS switch", Family: "arista",
		macOUI:       [3]byte{0x00, 0x1c, 0x73}, // Arista
		sshBanner:    "SSH-2.0-OpenSSH_8.8",
		httpServer:   "nginx",
		cliPrompt:    "arista#",
		loginPrompt:  "login: ",
		telnetBanner: "\r\nArista EOS\r\nlogin: ",
		snmpSysDescr: "Arista Networks EOS version 4.31.2F running on an Arista DCS-7050SX3",
		snmpSysName:  "arista", snmpSysObjectID: ".1.3.6.1.4.1.30065",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 23, Handler: "telnet"},
			{Port: 443, Handler: "https", Note: "eAPI"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"eos"},
	},
	"checkpoint-gaia": {
		Name: "checkpoint-gaia", DisplayName: "Check Point Gaia firewall", Family: "checkpoint",
		sshBanner:    "SSH-2.0-OpenSSH_7.4",
		httpServer:   "Check Point SVN foundation",
		httpTitle:    "Check Point Gaia",
		httpBodyHTML: "<html><head><title>Check Point Gaia Portal</title></head><body>Gaia</body></html>",
		cliPrompt:    "gaia> ",
		snmpSysDescr: "Check Point Gaia R81.20",
		snmpSysName:  "gaia", snmpSysObjectID: ".1.3.6.1.4.1.2620",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 443, Handler: "https", Note: "Gaia portal"}, {Port: 22, Handler: "ssh"},
		},
		quirks: []string{"gaia"},
	},
	"dell-idrac": {
		Name: "dell-idrac", DisplayName: "Dell iDRAC 9 (lights-out)", Family: "dell",
		macOUI:       [3]byte{0x00, 0x14, 0x22}, // Dell
		sshBanner:    "SSH-2.0-OpenSSH_7.8",
		httpServer:   "Mbedthis-Appweb",
		httpTitle:    "Integrated Dell Remote Access Controller 9",
		httpBodyHTML: "<html><head><title>iDRAC9</title></head><body>Integrated Dell Remote Access Controller</body></html>",
		snmpSysDescr: "Integrated Dell Remote Access Controller 9 (iDRAC9) firmware 6.10.30.00",
		snmpSysName:  "idrac", snmpSysObjectID: ".1.3.6.1.4.1.674.10892.5",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 443, Handler: "idrac", Note: "iDRAC web/Redfish"}, {Port: 22, Handler: "ssh"},
		},
		quirks: []string{"lights-out"},
	},
	"hpe-ilo": {
		Name: "hpe-ilo", DisplayName: "HPE iLO 5 (lights-out)", Family: "hp",
		macOUI:       [3]byte{0x9c, 0x8e, 0x99}, // HPE
		sshBanner:    "SSH-2.0-mpSSH_0.2.1",
		httpServer:   "HPE-iLO-Server/1.30",
		httpTitle:    "HPE Integrated Lights-Out 5",
		httpBodyHTML: "<html><head><title>iLO 5</title></head><body>HPE Integrated Lights-Out</body></html>",
		snmpSysDescr: "HPE Integrated Lights-Out 5 (iLO 5) firmware 2.78",
		snmpSysName:  "ilo", snmpSysObjectID: ".1.3.6.1.4.1.232",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 443, Handler: "ilo", Note: "iLO web/Redfish"}, {Port: 22, Handler: "ssh"},
		},
		quirks: []string{"lights-out"},
	},
}
