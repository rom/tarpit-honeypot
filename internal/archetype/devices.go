package archetype

import "crypto/tls"

// devices.go holds the "non-distro" archetypes: BSD family + the
// industrial / embedded devices (Moxa, Siemens SCALANCE / S7). Split
// from archetype.go so the OS-distro registry stays a quick read.
//
// Every entry here populates the full Profile surface — banners, MAC
// OUI, SNMP identity, CLI prompt, default services, and any quirks the
// handler layer needs to know about. The values are taken from public
// product datasheets / observed scans / Shodan banners.

var deviceArchetypes = map[string]*Profile{
	// ---- BSD family ----
	"freebsd-13": {
		Name: "freebsd-13", DisplayName: "FreeBSD 13", Family: "bsd",
		sshBanner:       "SSH-2.0-OpenSSH_8.8 FreeBSD-20211221",
		httpServer:      "Apache/2.4.62 (FreeBSD)",
		ftpBanner:       "220 ProFTPD 1.3.7e Server (FreeBSD) [::ffff:127.0.0.1]",
		telnetBanner:    "\r\nFreeBSD/amd64 (host.example.com) (ttyu0)\r\n\r\nlogin: ",
		smtpProduct:     "Sendmail 8.16.1/8.16.1",
		mysqlVersion:    "10.6.16-MariaDB",
		cliPrompt:       "host% ",
		httpTitle:       "FreeBSD Web Console",
		httpBodyHTML:    "<html><body><h1>It works! (FreeBSD)</h1></body></html>",
		snmpSysDescr:    "FreeBSD host.example.com 13.3-RELEASE FreeBSD 13.3-RELEASE GENERIC amd64",
		snmpSysObjectID: ".1.3.6.1.4.1.2238.1.0",
		snmpSysName:     "freebsd13",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"},
			{Port: 25, Handler: "smtp_recv", Note: "sendmail default"},
		},
	},
	"freebsd-14": {
		Name: "freebsd-14", DisplayName: "FreeBSD 14", Family: "bsd",
		sshBanner:       "SSH-2.0-OpenSSH_9.5 FreeBSD-20231004",
		httpServer:      "Apache/2.4.62 (FreeBSD)",
		ftpBanner:       "220 ProFTPD Server (FreeBSD)",
		telnetBanner:    "\r\nFreeBSD/amd64 (host.example.com) (ttyu0)\r\n\r\nlogin: ",
		smtpProduct:     "Sendmail 8.17.2/8.17.2",
		mysqlVersion:    "10.11.6-MariaDB",
		cliPrompt:       "host% ",
		httpTitle:       "FreeBSD Web Console",
		httpBodyHTML:    "<html><body><h1>It works! (FreeBSD)</h1></body></html>",
		snmpSysDescr:    "FreeBSD host.example.com 14.1-RELEASE FreeBSD 14.1-RELEASE GENERIC amd64",
		snmpSysObjectID: ".1.3.6.1.4.1.2238.1.0",
		snmpSysName:     "freebsd14",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"},
		},
	},
	"openbsd-7-5": {
		Name: "openbsd-7.5", DisplayName: "OpenBSD 7.5", Family: "bsd",
		sshBanner:       "SSH-2.0-OpenSSH_9.7",
		httpServer:      "OpenBSD httpd",
		ftpBanner:       "220 OpenBSD ftpd ready",
		telnetBanner:    "\r\nOpenBSD/amd64 (obsd.example.com) (tty00)\r\n\r\nlogin: ",
		smtpProduct:     "OpenSMTPD",
		mysqlVersion:    "",
		cliPrompt:       "obsd$ ",
		httpTitle:       "OpenBSD httpd",
		httpBodyHTML:    "<html><body><pre>It works.</pre></body></html>",
		snmpSysDescr:    "OpenBSD obsd.example.com 7.5 GENERIC#10 amd64",
		snmpSysObjectID: ".1.3.6.1.4.1.30155.1.1",
		snmpSysName:     "obsd75",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"},
			{Port: 25, Handler: "smtp_recv", Note: "OpenSMTPD default"},
		},
	},
	"openbsd-7-6": {
		Name: "openbsd-7.6", DisplayName: "OpenBSD 7.6", Family: "bsd",
		sshBanner:       "SSH-2.0-OpenSSH_9.8",
		httpServer:      "OpenBSD httpd",
		ftpBanner:       "220 OpenBSD ftpd ready",
		telnetBanner:    "\r\nOpenBSD/amd64 (obsd.example.com) (tty00)\r\n\r\nlogin: ",
		smtpProduct:     "OpenSMTPD",
		cliPrompt:       "obsd$ ",
		httpTitle:       "OpenBSD httpd",
		httpBodyHTML:    "<html><body><pre>It works.</pre></body></html>",
		snmpSysDescr:    "OpenBSD obsd.example.com 7.6 GENERIC#10 amd64",
		snmpSysObjectID: ".1.3.6.1.4.1.30155.1.1",
		snmpSysName:     "obsd76",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"},
		},
	},
	"freebsd-11": {
		Name: "freebsd-11", DisplayName: "FreeBSD 11", Family: "bsd",
		sshBanner:       "SSH-2.0-OpenSSH_7.2 FreeBSD-20161230",
		httpServer:      "Apache/2.4.34 (FreeBSD)",
		ftpBanner:       "220 FreeBSD-11 FTP server ready.",
		telnetBanner:    "\r\nFreeBSD/amd64 (freebsd) (ttyv0)\r\n\r\nlogin: ",
		smtpProduct:     "Sendmail 8.15.2",
		mysqlVersion:    "5.6.51",
		cliPrompt:       "host% ",
		httpTitle:       "FreeBSD Web Console",
		httpBodyHTML:    "<html><body><h1>It works! (FreeBSD)</h1></body></html>",
		snmpSysDescr:    "FreeBSD host.example.com 11.4-RELEASE FreeBSD 11.4-RELEASE GENERIC amd64",
		snmpSysObjectID: ".1.3.6.1.4.1.2238.1.0",
		snmpSysName:     "freebsd11",
		// FreeBSD 11 base OpenSSL 1.0.2: TLS 1.0–1.2, no TLS 1.3.
		tls: TLSPosture{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, WeakCiphers: true},
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"},
		},
	},
	"openbsd-7-4": {
		Name: "openbsd-7.4", DisplayName: "OpenBSD 7.4", Family: "bsd",
		sshBanner:       "SSH-2.0-OpenSSH_9.5",
		httpServer:      "OpenBSD httpd",
		ftpBanner:       "220 OpenBSD ftpd ready",
		telnetBanner:    "\r\nOpenBSD/amd64 (obsd.example.com) (tty00)\r\n\r\nlogin: ",
		smtpProduct:     "OpenSMTPD",
		cliPrompt:       "obsd$ ",
		httpTitle:       "OpenBSD httpd",
		httpBodyHTML:    "<html><body><pre>It works.</pre></body></html>",
		snmpSysDescr:    "OpenBSD obsd.example.com 7.4 GENERIC#10 amd64",
		snmpSysObjectID: ".1.3.6.1.4.1.30155.1.1",
		snmpSysName:     "obsd74",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"},
			{Port: 25, Handler: "smtp_recv", Note: "OpenSMTPD default"},
		},
	},
	"openbsd-7-7": {
		Name: "openbsd-7.7", DisplayName: "OpenBSD 7.7", Family: "bsd",
		sshBanner:       "SSH-2.0-OpenSSH_10.0",
		httpServer:      "OpenBSD httpd",
		ftpBanner:       "220 OpenBSD ftpd ready",
		telnetBanner:    "\r\nOpenBSD/amd64 (obsd.example.com) (tty00)\r\n\r\nlogin: ",
		smtpProduct:     "OpenSMTPD",
		cliPrompt:       "obsd$ ",
		httpTitle:       "OpenBSD httpd",
		httpBodyHTML:    "<html><body><pre>It works.</pre></body></html>",
		snmpSysDescr:    "OpenBSD obsd.example.com 7.7 GENERIC#10 amd64",
		snmpSysObjectID: ".1.3.6.1.4.1.30155.1.1",
		snmpSysName:     "obsd77",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"},
		},
	},
	"netbsd-9": {
		Name: "netbsd-9", DisplayName: "NetBSD 9", Family: "bsd",
		sshBanner:    "SSH-2.0-OpenSSH_8.0 NetBSD_Secure_Shell-20190418",
		httpServer:   "bozohttpd/20190228",
		ftpBanner:    "220 nbsd.example.com FTP server (NetBSD-ftpd 20180605) ready.",
		telnetBanner: "\r\nNetBSD/amd64 (nbsd.example.com) (ttyp0)\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 3.4.8",
		cliPrompt:    "nbsd# ",
		httpTitle:    "NetBSD",
		httpBodyHTML: "<html><body><pre>It works (NetBSD).</pre></body></html>",
		snmpSysDescr: "NetBSD nbsd.example.com 9.3 NetBSD 9.3 (GENERIC) amd64",
		snmpSysName:  "netbsd9",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"},
		},
	},
	"netbsd-10": {
		Name: "netbsd-10", DisplayName: "NetBSD 10", Family: "bsd",
		sshBanner:    "SSH-2.0-OpenSSH_9.6 NetBSD_Secure_Shell-20240115",
		httpServer:   "bozohttpd/20240126",
		ftpBanner:    "220 nbsd.example.com FTP server (NetBSD-ftpd 20240114) ready.",
		telnetBanner: "\r\nNetBSD/amd64 (nbsd.example.com) (ttyp0)\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 3.8.5",
		cliPrompt:    "nbsd# ",
		httpTitle:    "NetBSD",
		httpBodyHTML: "<html><body><pre>It works (NetBSD).</pre></body></html>",
		snmpSysDescr: "NetBSD nbsd.example.com 10.0 NetBSD 10.0 (GENERIC) amd64",
		snmpSysName:  "netbsd10",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"},
		},
	},
	"arch-linux": {
		Name: "arch-linux", DisplayName: "Arch Linux", Family: "arch",
		sshBanner:       "SSH-2.0-OpenSSH_9.9",
		httpServer:      "nginx/1.27.3",
		ftpBanner:       "220 (vsFTPd 3.0.5)",
		telnetBanner:    "\r\nArch Linux \\r (\\l)\r\n\r\narch login: ",
		smtpProduct:     "Postfix 3.9.0",
		mysqlVersion:    "11.4.3-MariaDB",
		cliPrompt:       "[user@arch ~]$ ",
		httpTitle:       "Welcome to nginx",
		httpBodyHTML:    "<html><body><h1>Welcome to nginx!</h1></body></html>",
		snmpSysDescr:    "Linux arch 6.10.10-arch1-1 #1 SMP PREEMPT_DYNAMIC x86_64",
		snmpSysObjectID: ".1.3.6.1.4.1.8072.3.2.10",
		snmpSysName:     "arch",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"},
		},
	},

	// ---- Rocky / Alma / Oracle (RHEL ABI clones) ----
	"rocky-linux-9": {
		Name: "rocky-9", DisplayName: "Rocky Linux 9", Family: "rhel",
		sshBanner:       "SSH-2.0-OpenSSH_8.7",
		httpServer:      "Apache/2.4.62 (Rocky Linux)",
		ftpBanner:       "220 (vsFTPd 3.0.5)",
		telnetBanner:    "\r\nRocky Linux release 9.4 (Blue Onyx)\r\nKernel \\r on an \\m\r\n\r\nlogin: ",
		smtpProduct:     "Postfix 3.5.25",
		mysqlVersion:    "10.5.22-MariaDB",
		cliPrompt:       "[root@rocky9 ~]# ",
		httpTitle:       "HTTP Server Test Page",
		httpBodyHTML:    "<html><body><h1>Rocky Linux Test Page</h1></body></html>",
		snmpSysDescr:    "Linux rocky9 5.14.0-427.31.1.el9_4.x86_64 #1 SMP PREEMPT_DYNAMIC Tue Aug 13 x86_64",
		snmpSysObjectID: ".1.3.6.1.4.1.8072.3.2.10",
		snmpSysName:     "rocky9",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"},
		},
	},
	"almalinux-9": {
		Name: "almalinux-9", DisplayName: "AlmaLinux 9", Family: "rhel",
		sshBanner:       "SSH-2.0-OpenSSH_8.7",
		httpServer:      "Apache/2.4.62 (AlmaLinux)",
		ftpBanner:       "220 (vsFTPd 3.0.5)",
		telnetBanner:    "\r\nAlmaLinux release 9.4 (Seafoam Ocelot)\r\nKernel \\r on an \\m\r\n\r\nlogin: ",
		smtpProduct:     "Postfix 3.5.25",
		mysqlVersion:    "10.5.22-MariaDB",
		cliPrompt:       "[root@alma9 ~]# ",
		httpTitle:       "HTTP Server Test Page",
		httpBodyHTML:    "<html><body><h1>AlmaLinux Test Page</h1></body></html>",
		snmpSysDescr:    "Linux alma9 5.14.0-427.31.1.el9_4.x86_64 #1 SMP PREEMPT_DYNAMIC Mon Aug 12 x86_64",
		snmpSysObjectID: ".1.3.6.1.4.1.8072.3.2.10",
		snmpSysName:     "alma9",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"},
		},
	},
	"oracle-linux-8": {
		Name: "oracle-linux-8", DisplayName: "Oracle Linux 8", Family: "rhel",
		sshBanner:       "SSH-2.0-OpenSSH_8.0",
		httpServer:      "Apache/2.4.37 (Oracle Linux Server)",
		ftpBanner:       "220 (vsFTPd 3.0.3)",
		telnetBanner:    "\r\nOracle Linux Server release 8.10\r\nKernel \\r on an \\m\r\n\r\nlogin: ",
		smtpProduct:     "Postfix 3.5.8",
		mysqlVersion:    "8.0.36-commercial",
		cliPrompt:       "[root@oracle8 ~]# ",
		httpTitle:       "Oracle Linux HTTP Server Test Page",
		httpBodyHTML:    "<html><body><h1>Oracle Linux Test Page</h1></body></html>",
		snmpSysDescr:    "Linux oracle8 4.18.0-553.16.1.el8_10.x86_64 #1 SMP Mon Aug 19 x86_64",
		snmpSysObjectID: ".1.3.6.1.4.1.111.1.1",
		snmpSysName:     "oracle8",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"},
		},
	},
	"oracle-linux-9": {
		Name: "oracle-linux-9", DisplayName: "Oracle Linux 9", Family: "rhel",
		sshBanner:       "SSH-2.0-OpenSSH_8.7",
		httpServer:      "Apache/2.4.62 (Oracle Linux Server)",
		ftpBanner:       "220 (vsFTPd 3.0.5)",
		telnetBanner:    "\r\nOracle Linux Server release 9.4\r\nKernel \\r on an \\m\r\n\r\nlogin: ",
		smtpProduct:     "Postfix 3.5.25",
		mysqlVersion:    "8.0.36-commercial",
		cliPrompt:       "[root@oracle9 ~]# ",
		httpTitle:       "Oracle Linux HTTP Server Test Page",
		httpBodyHTML:    "<html><body><h1>Oracle Linux 9 Test Page</h1></body></html>",
		snmpSysDescr:    "Linux oracle9 5.14.0-427.31.1.el9_4.x86_64 #1 SMP PREEMPT_DYNAMIC Tue Aug 13 x86_64",
		snmpSysObjectID: ".1.3.6.1.4.1.111.1.1",
		snmpSysName:     "oracle9",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"},
		},
	},

	// ---- Moxa EDS-208 (8-port unmanaged industrial Ethernet switch) ----
	// In practice the EDS-208 family ships a small web admin + telnet
	// configurator + SNMP v1/v2c. OUI 00:90:E8 is Moxa.
	"moxa-eds-208": {
		Name: "moxa-eds-208", DisplayName: "Moxa EDS-208", Family: "moxa",
		macOUI:       [3]byte{0x00, 0x90, 0xE8},
		sshBanner:    "SSH-2.0-MoxaCLI_1.0",
		httpServer:   "Moxa-HTTPd",
		telnetBanner: "Model      : EDS-208\r\nFirmware   : V1.7\r\nSerial No. : 12345\r\n\r\nUsername: ",
		loginPrompt:  "Username: ",
		cliPrompt:    "EDS-208> ",
		httpTitle:    "Moxa EDS-208 Web Console",
		httpBodyHTML: `<html><head><title>Moxa EDS-208</title></head><body>` +
			`<h2>Moxa EtherDevice Switch EDS-208</h2>` +
			`<p>Model: EDS-208 / Firmware: V1.7 build 18121420</p>` +
			`<form><label>Username: <input name=u></label><br>` +
			`<label>Password: <input type=password name=p></label><br>` +
			`<input type=submit value=Login></form></body></html>`,
		snmpSysDescr:    "Moxa EtherDevice Switch EDS-208",
		snmpSysObjectID: ".1.3.6.1.4.1.8691.7.1",
		snmpSysName:     "EDS-208",
		snmpSysContact:  "operator@example.com",
		snmpSysLocation: "Cabinet A, Rack 3",
		snmpIfTable:     mockSwitchInterfaces(8, "Port"),
		lldpNeighbors:   nil,
		defaultServices: []DefaultService{
			{Port: 23, Handler: "telnet", Note: "Moxa CLI"},
			{Port: 80, Handler: "http", Note: "Moxa web admin"},
			{Port: 161, Handler: "snmp", Note: "v1/v2c"},
		},
		quirks: []string{"moxa-banner-on-telnet-connect"},
	},

	// ---- Moxa NPort 5210 (serial-to-Ethernet device server) ----
	// 2 serial ports. Listens on TCP 4001/4002 for raw serial passthrough.
	"moxa-nport-5210": {
		Name: "moxa-nport-5210", DisplayName: "Moxa NPort 5210", Family: "moxa",
		macOUI:       [3]byte{0x00, 0x90, 0xE8},
		sshBanner:    "SSH-2.0-MoxaSSH_1.0",
		httpServer:   "Moxa-HTTPd",
		telnetBanner: "Model      : NPort 5210\r\nFirmware   : 2.7\r\nMAC Addr.  : 00:90:E8:00:00:00\r\n\r\nUsername: ",
		loginPrompt:  "Username: ",
		cliPrompt:    "NPort> ",
		httpTitle:    "NPort 5210 Web Console",
		httpBodyHTML: `<html><head><title>NPort 5210</title></head><body>` +
			`<h2>NPort 5210 Series Serial Device Server</h2>` +
			`<p>Firmware V2.7 build 23010615</p>` +
			`<a href="/main.htm">Login</a></body></html>`,
		snmpSysDescr:    "Moxa NPort 5210 V2.7",
		snmpSysObjectID: ".1.3.6.1.4.1.8691.5.5",
		snmpSysName:     "NPort_5210",
		snmpSysContact:  "operator@example.com",
		snmpSysLocation: "PLC Cabinet",
		snmpIfTable:     mockSwitchInterfaces(2, "Serial"),
		defaultServices: []DefaultService{
			{Port: 23, Handler: "telnet", Note: "Moxa CLI"},
			{Port: 80, Handler: "http", Note: "Moxa web admin"},
			{Port: 161, Handler: "snmp", Note: "v1/v2c"},
			{Port: 4001, Handler: "raw", Note: "serial port 1 raw TCP"},
			{Port: 4002, Handler: "raw", Note: "serial port 2 raw TCP"},
		},
		quirks: []string{"moxa-nport-raw-serial-passthrough"},
	},

	// ---- Serial / Ethernet converters (terminal / device servers) ----
	"moxa-nport-5150": {
		Name: "moxa-nport-5150", DisplayName: "Moxa NPort 5150 (1-port serial-to-Ethernet)", Family: "moxa",
		macOUI:       [3]byte{0x00, 0x90, 0xE8},
		sshBanner:    "SSH-2.0-MoxaSSH_1.0",
		httpServer:   "Moxa-HTTPd",
		telnetBanner: "Model      : NPort 5150\r\nFirmware   : 3.7\r\nMAC Addr.  : 00:90:E8:00:00:00\r\n\r\nUsername: ",
		loginPrompt:  "Username: ",
		cliPrompt:    "NPort> ",
		httpTitle:    "NPort 5150 Web Console",
		httpBodyHTML: `<html><head><title>NPort 5150</title></head><body>` +
			`<h2>NPort 5150 Serial Device Server</h2><p>Firmware V3.7</p><a href="/main.htm">Login</a></body></html>`,
		snmpSysDescr:    "Moxa NPort 5150 V3.7",
		snmpSysObjectID: ".1.3.6.1.4.1.8691.5.5",
		snmpSysName:     "NPort_5150",
		snmpSysLocation: "RTU cabinet",
		icmpTTL:         64,
		defaultServices: []DefaultService{
			{Port: 23, Handler: "telnet", Note: "Moxa CLI"},
			{Port: 80, Handler: "http", Note: "Moxa web admin"},
			{Port: 161, Handler: "snmp", Note: "v1/v2c"},
			{Port: 4001, Handler: "raw", Note: "serial port 1 raw TCP"},
		},
		quirks: []string{"moxa-nport-raw-serial-passthrough", "serial"},
	},
	"digi-portserver-ts": {
		Name: "digi-portserver-ts", DisplayName: "Digi PortServer TS (terminal server)", Family: "digi",
		macOUI:          [3]byte{0x00, 0x40, 0x9D}, // Digi International
		sshBanner:       "SSH-2.0-OpenSSH_5.5",
		httpServer:      "Digi/EmbeddedWeb",
		telnetBanner:    "\r\nWelcome to the Digi PortServer TS 16\r\n\r\nlogin: ",
		loginPrompt:     "login: ",
		cliPrompt:       "#> ",
		httpTitle:       "Digi PortServer TS",
		httpBodyHTML:    `<html><head><title>Digi PortServer TS</title></head><body><h2>Digi PortServer TS 16</h2><p>Version 82000747_T2</p></body></html>`,
		snmpSysDescr:    "Digi PortServer TS 16 Version 82000747_T2",
		snmpSysObjectID: ".1.3.6.1.4.1.332.11.6",
		snmpSysName:     "portserver-ts",
		snmpSysLocation: "Comms room",
		icmpTTL:         64,
		defaultServices: []DefaultService{
			{Port: 23, Handler: "telnet", Note: "Digi CLI"},
			{Port: 80, Handler: "http", Note: "Digi web admin"},
			{Port: 161, Handler: "snmp", Note: "v1/v2c"},
			{Port: 771, Handler: "raw", Note: "RealPort"},
			{Port: 2001, Handler: "raw", Note: "serial port 1 raw TCP"},
		},
		quirks: []string{"digi-realport", "serial"},
	},
	"lantronix-uds1100": {
		Name: "lantronix-uds1100", DisplayName: "Lantronix UDS1100 (1-port device server)", Family: "lantronix",
		macOUI:       [3]byte{0x00, 0x20, 0x4a}, // Lantronix
		httpServer:   "Lantronix Web Manager",
		httpTitle:    "Lantronix UDS1100",
		httpBodyHTML: `<html><head><title>UDS1100</title></head><body><h2>Lantronix UDS1100</h2><p>Device Server</p></body></html>`,
		telnetBanner: "\r\nLantronix UDS1100\r\nPress Enter for Setup Mode\r\n",
		snmpSysDescr: "Lantronix UDS1100 V6.8.0.2",
		snmpSysName:  "uds1100", snmpSysObjectID: ".1.3.6.1.4.1.244",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 9999, Handler: "lantronix", Note: "setup"},
			{Port: 80, Handler: "http", Note: "web manager"},
			{Port: 10001, Handler: "raw", Note: "serial port 1 raw TCP"},
		},
		quirks: []string{"lantronix-discovery", "serial"},
	},
	"lantronix-eds2100": {
		Name: "lantronix-eds2100", DisplayName: "Lantronix EDS2100 (2-port device server)", Family: "lantronix",
		macOUI:       [3]byte{0x00, 0x20, 0x4a},
		httpServer:   "Lantronix Web Manager",
		httpTitle:    "Lantronix EDS2100",
		httpBodyHTML: `<html><head><title>EDS2100</title></head><body><h2>Lantronix EDS2100</h2><p>Device Server</p></body></html>`,
		telnetBanner: "\r\nLantronix EDS2100\r\nPress Enter for Setup Mode\r\n",
		snmpSysDescr: "Lantronix EDS2100 V5.2.0.1",
		snmpSysName:  "eds2100", snmpSysObjectID: ".1.3.6.1.4.1.244",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 9999, Handler: "lantronix", Note: "setup"},
			{Port: 80, Handler: "http", Note: "web manager"},
			{Port: 443, Handler: "https", Note: "web manager (TLS)"},
			{Port: 161, Handler: "snmp", Note: "v1/v2c"},
			{Port: 10001, Handler: "raw", Note: "serial port 1 raw TCP"},
			{Port: 10002, Handler: "raw", Note: "serial port 2 raw TCP"},
		},
		quirks: []string{"lantronix-discovery", "serial"},
	},
	"lantronix-xport": {
		Name: "lantronix-xport", DisplayName: "Lantronix XPort (embedded device server)", Family: "lantronix",
		macOUI:       [3]byte{0x00, 0x20, 0x4a},
		httpServer:   "Lantronix Web Manager",
		httpTitle:    "Lantronix XPort",
		httpBodyHTML: `<html><head><title>XPort</title></head><body><h2>Lantronix XPort</h2><p>Embedded Device Server</p></body></html>`,
		telnetBanner: "\r\nLantronix XPort\r\nPress Enter for Setup Mode\r\n",
		snmpSysDescr: "Lantronix XPort-03 V6.10.0.0",
		snmpSysName:  "xport", snmpSysObjectID: ".1.3.6.1.4.1.244",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 9999, Handler: "lantronix", Note: "setup"},
			{Port: 80, Handler: "http", Note: "web manager"},
			{Port: 10001, Handler: "raw", Note: "serial port raw TCP"},
		},
		quirks: []string{"lantronix-discovery", "serial"},
	},
	"westermo-lynx-3510": {
		Name: "westermo-lynx-3510", DisplayName: "Westermo Lynx 3510 (WeOS managed switch)", Family: "westermo",
		macOUI:          [3]byte{0x00, 0x07, 0x7C},
		sshBanner:       "SSH-2.0-OpenSSH_7.4 WeOS",
		httpServer:      "GoAhead-Webs",
		telnetBanner:    "\r\nWestermo Lynx WeOS v4.32.4\r\nlogin: ",
		loginPrompt:     "login: ",
		cliPrompt:       "lynx:/#> ",
		httpTitle:       "Westermo Lynx 3510",
		httpBodyHTML:    `<html><head><title>Westermo Lynx 3510</title></head><body><h2>Westermo Lynx 3510-F2G-T8</h2><p>WeOS v4.32.4</p></body></html>`,
		snmpSysDescr:    "Westermo Lynx 3510-F2G-T8 WeOS v4.32.4",
		snmpSysObjectID: ".1.3.6.1.4.1.16177.1.5.1",
		snmpSysName:     "lynx-3510",
		snmpSysLocation: "Substation bay 3",
		icmpTTL:         64,
		snmpIfTable:     mockSwitchInterfaces(10, "Eth"),
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh", Note: "WeOS CLI"}, {Port: 23, Handler: "telnet"},
			{Port: 80, Handler: "http"}, {Port: 443, Handler: "https"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"weos", "westermo-frnt"},
	},
	"westermo-lynx-5512": {
		Name: "westermo-lynx-5512", DisplayName: "Westermo Lynx 5512 (WeOS managed switch)", Family: "westermo",
		macOUI:          [3]byte{0x00, 0x07, 0x7C},
		sshBanner:       "SSH-2.0-OpenSSH_7.4 WeOS",
		httpServer:      "GoAhead-Webs",
		telnetBanner:    "\r\nWestermo Lynx WeOS v4.32.4\r\nlogin: ",
		loginPrompt:     "login: ",
		cliPrompt:       "lynx:/#> ",
		httpTitle:       "Westermo Lynx 5512",
		httpBodyHTML:    `<html><head><title>Westermo Lynx 5512</title></head><body><h2>Westermo Lynx 5512-F4G-T8</h2><p>WeOS v4.32.4</p></body></html>`,
		snmpSysDescr:    "Westermo Lynx 5512-F4G-T8 WeOS v4.32.4",
		snmpSysObjectID: ".1.3.6.1.4.1.16177.1.5.1",
		snmpSysName:     "lynx-5512",
		snmpSysLocation: "Substation bay 5",
		icmpTTL:         64,
		snmpIfTable:     mockSwitchInterfaces(12, "Eth"),
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh", Note: "WeOS CLI"}, {Port: 23, Handler: "telnet"},
			{Port: 80, Handler: "http"}, {Port: 443, Handler: "https"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"weos", "westermo-frnt"},
	},

	// ---- Siemens SCALANCE XB-208 (industrial managed switch) ----
	// SCALANCE switches default to web + SNMP + LLDP + STP. OUI 28:63:36
	// belongs to Siemens AG.
	"siemens-scalance-xb-208": {
		Name: "siemens-scalance-xb-208", DisplayName: "Siemens SCALANCE XB-208", Family: "siemens",
		macOUI:       [3]byte{0x28, 0x63, 0x36},
		sshBanner:    "SSH-2.0-SCALANCE_X-200_v06.01.01",
		httpServer:   "Siemens Web Server",
		telnetBanner: "Welcome to SCALANCE XB-208\r\nFirmware: V06.01.01\r\n\r\nlogin: ",
		loginPrompt:  "login: ",
		cliPrompt:    "scalance-xb208# ",
		httpTitle:    "SCALANCE XB-208",
		httpBodyHTML: `<html><head><title>SCALANCE XB-208</title></head><body>` +
			`<h2>SIMATIC NET SCALANCE XB-208</h2>` +
			`<p>Firmware V06.01.01 / HW: 6GK5208-0BA00-2AB2</p>` +
			`<form><label>Name: <input name=u></label><br>` +
			`<label>Password: <input type=password name=p></label><br>` +
			`<input type=submit value=Login></form></body></html>`,
		snmpSysDescr:    "Siemens, SIMATIC NET, SCALANCE XB-208, 6GK5208-0BA00-2AB2, HW: 4, FW: V06.01.01",
		snmpSysObjectID: ".1.3.6.1.4.1.4196.1.1.5.2.30",
		snmpSysName:     "scalance-xb208",
		snmpSysContact:  "ops@example.com",
		snmpSysLocation: "Factory floor / Cell 3",
		snmpIfTable:     mockSwitchInterfaces(8, "Ethernet"),
		tls:             TLSPosture{MaxVersion: tlsVersionTLS12, WeakCiphers: true},
		lldpNeighbors: []LLDPPeer{
			{ChassisID: "28:63:36:00:11:22", PortID: "1", SystemName: "scalance-xb208-uplink", PortDescr: "Port 1"},
			{ChassisID: "28:63:36:00:33:44", PortID: "2", SystemName: "s7-1500-cell3", PortDescr: "Port 2"},
		},
		mrpRings: []MRPRing{
			{Name: "Ring1", Role: "client", Ports: []int{1, 2}, State: "closed"},
		},
		profinetDevices: scalanceProfinetTree,
		vlans: []VLAN{
			{ID: 1, Name: "default", Ports: []int{1, 2, 3, 4}},
			{ID: 10, Name: "PROFINET", Ports: []int{5, 6}},
			{ID: 20, Name: "Management", Ports: []int{7, 8}},
		},
		hmis: []HMI{
			{Name: "HMI-Press-01", IP: "192.168.0.50", Type: "SIMATIC HMI TP700 Comfort"},
		},
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh", Note: "SCALANCE CLI"},
			{Port: 23, Handler: "telnet", Note: "SCALANCE CLI"},
			{Port: 80, Handler: "http", Note: "Web management"},
			{Port: 443, Handler: "https"},
			{Port: 161, Handler: "snmp"},
		},
		quirks: []string{"siemens-lldp-med-disabled"},
	},

	// ---- Siemens SCALANCE S615 (industrial security router / firewall) ----
	"siemens-scalance-s615": {
		Name: "siemens-scalance-s615", DisplayName: "Siemens SCALANCE S615", Family: "siemens",
		macOUI:       [3]byte{0x28, 0x63, 0x36},
		sshBanner:    "SSH-2.0-SCALANCE_S615_v07.02",
		httpServer:   "Siemens Web Server",
		telnetBanner: "Welcome to SCALANCE S615\r\nFirmware: V07.02.00\r\n\r\nlogin: ",
		loginPrompt:  "login: ",
		cliPrompt:    "scalance-s615# ",
		httpTitle:    "SCALANCE S615",
		httpBodyHTML: `<html><head><title>SCALANCE S615</title></head><body>` +
			`<h2>SIMATIC NET SCALANCE S615</h2>` +
			`<p>Industrial Security Router / Firewall</p>` +
			`<p>Firmware V07.02.00 / HW: 6GK5615-0AA00-2AA2</p>` +
			`<form><label>Name: <input name=u></label><br>` +
			`<label>Password: <input type=password name=p></label><br>` +
			`<input type=submit value=Login></form></body></html>`,
		snmpSysDescr:    "Siemens, SIMATIC NET, SCALANCE S615, 6GK5615-0AA00-2AA2, HW: 2, FW: V07.02.00",
		snmpSysObjectID: ".1.3.6.1.4.1.4196.1.1.5.2.42",
		snmpSysName:     "scalance-s615",
		snmpSysContact:  "ops@example.com",
		snmpSysLocation: "Cell gateway",
		snmpIfTable:     mockSwitchInterfaces(5, "vlan"),
		tls:             TLSPosture{MaxVersion: tlsVersionTLS12, WeakCiphers: true},
		vlans: []VLAN{
			{ID: 1, Name: "INT", Ports: []int{1, 2, 3, 4}},
			{ID: 100, Name: "EXT", Ports: []int{5}},
		},
		profinetDevices: scalanceProfinetTree,
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 443, Handler: "https"}, {Port: 161, Handler: "snmp"},
			{Port: 500, Handler: "raw", Note: "IKE / IPsec VPN"},
		},
		quirks: []string{"siemens-firewall"},
	},

	// ---- Siemens SCALANCE SC-600 (next-gen industrial firewall) ----
	"siemens-scalance-sc-600": {
		Name: "siemens-scalance-sc-600", DisplayName: "Siemens SCALANCE SC-600", Family: "siemens",
		macOUI:       [3]byte{0x28, 0x63, 0x36},
		sshBanner:    "SSH-2.0-SCALANCE_SC600_v02.03",
		httpServer:   "Siemens Web Server",
		telnetBanner: "Welcome to SCALANCE SC636-2C\r\nFirmware: V02.03.02\r\n\r\nlogin: ",
		loginPrompt:  "login: ",
		cliPrompt:    "scalance-sc636# ",
		httpTitle:    "SCALANCE SC-600",
		httpBodyHTML: `<html><head><title>SCALANCE SC636-2C</title></head><body>` +
			`<h2>SIMATIC NET SCALANCE SC636-2C</h2>` +
			`<p>Industrial Security Appliance</p>` +
			`<p>Firmware V02.03.02 / HW: 6GK5636-2GS00-2AC2</p>` +
			`<form><label>Name: <input name=u></label><br>` +
			`<label>Password: <input type=password name=p></label><br>` +
			`<input type=submit value=Login></form></body></html>`,
		snmpSysDescr:    "Siemens, SIMATIC NET, SCALANCE SC636-2C, 6GK5636-2GS00-2AC2, HW: 1, FW: V02.03.02",
		snmpSysObjectID: ".1.3.6.1.4.1.4196.1.1.5.2.55",
		snmpSysName:     "scalance-sc636",
		snmpSysContact:  "ops@example.com",
		snmpSysLocation: "Plant DMZ",
		snmpIfTable:     mockSwitchInterfaces(6, "P"),
		tls:             TLSPosture{}, // SC-600 line supports modern TLS
		vlans: []VLAN{
			{ID: 1, Name: "internal", Ports: []int{1, 2, 3, 4}},
			{ID: 200, Name: "dmz", Ports: []int{5, 6}},
		},
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 443, Handler: "https"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"siemens-firewall"},
	},

	// ---- Siemens S7-1200 PLC ----
	// S7 protocol (port 102 ISO-TSAP), web server, optionally PROFINET.
	// SIMATIC S7-1200 series 6ES7 212-1xx0xx-0XB0.
	"siemens-s7-1200": {
		Name: "siemens-s7-1200", DisplayName: "Siemens S7-1200 PLC", Family: "siemens",
		macOUI:       [3]byte{0x28, 0x63, 0x36},
		httpServer:   "Siemens Web Server",
		telnetBanner: "",
		cliPrompt:    "",
		httpTitle:    "S7-1200 Web Server",
		httpBodyHTML: `<html><head><title>S7-1200 Station</title></head><body>` +
			`<h2>SIMATIC S7-1200</h2>` +
			`<p>CPU: 1212C DC/DC/DC / Order no. 6ES7 212-1AE40-0XB0</p>` +
			`<p>Firmware V4.5.1 / Step 7 V17</p>` +
			`<a href="/Portal/Login.html">Login</a></body></html>`,
		snmpSysDescr:    "Siemens, SIMATIC S7, CPU-1200, 6ES7 212-1AE40-0XB0, HW: 4, FW: V4.5.1",
		snmpSysObjectID: ".1.3.6.1.4.1.4196.1.1.5.2.22",
		snmpSysName:     "s7-1200-plc",
		snmpSysContact:  "automation@example.com",
		snmpSysLocation: "Cell A",
		snmpIfTable: []Interface{
			{Index: 1, Descr: "Ethernet PROFINET", Type: 6, Speed: 100_000_000, OperUp: true},
		},
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "S7-1200 web server"},
			{Port: 102, Handler: "s7", Note: "S7 ISO-TSAP"},
			{Port: 161, Handler: "snmp"},
		},
		quirks: []string{"siemens-s7-no-ssh", "siemens-s7-no-telnet"},
	},

	// ---- Siemens S7-1500 PLC ----
	// Larger range, HTTPS by default, OPC UA optional, PROFINET, S7.
	"siemens-s7-1500": {
		Name: "siemens-s7-1500", DisplayName: "Siemens S7-1500 PLC", Family: "siemens",
		macOUI:       [3]byte{0x28, 0x63, 0x36},
		httpServer:   "Siemens Web Server",
		telnetBanner: "",
		cliPrompt:    "",
		httpTitle:    "S7-1500 Web Server",
		httpBodyHTML: `<html><head><title>SIMATIC S7-1500</title></head><body>` +
			`<h2>SIMATIC S7-1500</h2>` +
			`<p>CPU: 1516-3 PN/DP / Order no. 6ES7 516-3AN02-0AB0</p>` +
			`<p>Firmware V2.9.4 / TIA Portal V17</p>` +
			`<a href="/Portal/Login.html">Login</a></body></html>`,
		snmpSysDescr:    "Siemens, SIMATIC S7, CPU-1500, 6ES7 516-3AN02-0AB0, HW: 6, FW: V2.9.4",
		snmpSysObjectID: ".1.3.6.1.4.1.4196.1.1.5.2.23",
		snmpSysName:     "s7-1500-plc",
		snmpSysContact:  "automation@example.com",
		snmpSysLocation: "Plant 1 / Cell B",
		snmpIfTable: []Interface{
			{Index: 1, Descr: "X1 PROFINET", Type: 6, Speed: 1_000_000_000, OperUp: true},
			{Index: 2, Descr: "X2 PROFINET", Type: 6, Speed: 1_000_000_000, OperUp: true},
			{Index: 3, Descr: "X3 DP-Master", Type: 6, Speed: 12_000_000, OperUp: true},
		},
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "S7-1500 web server"},
			{Port: 443, Handler: "https"},
			{Port: 102, Handler: "s7", Note: "S7 ISO-TSAP"},
			{Port: 161, Handler: "snmp"},
			{Port: 4840, Handler: "opcua", Note: "OPC UA server (optional)"},
		},
		quirks: []string{"siemens-s7-no-ssh", "siemens-s7-no-telnet", "siemens-s7-1500-opcua"},
	},
}

// mockSwitchInterfaces builds a believable ifTable for a small managed
// switch. Each port shows ifType=ethernetCsmacd (6), 1 Gbit, oper=up.
// The MAC tail bytes are derived from the port index for stability —
// the leading 3 bytes (OUI) are filled in at runtime from macOUI.
func mockSwitchInterfaces(ports int, prefix string) []Interface {
	out := make([]Interface, 0, ports+1)
	for i := 1; i <= ports; i++ {
		out = append(out, Interface{
			Index:  i,
			Descr:  formatPortDescr(prefix, i),
			Type:   6,
			Speed:  1_000_000_000,
			OperUp: i%2 == 1, // alternate up/down so the picture isn't suspicious
		})
	}
	return out
}

func formatPortDescr(prefix string, i int) string {
	// Hand-rolled to avoid importing fmt for one call site.
	return prefix + " " + itoaShort(i)
}

func itoaShort(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	idx := len(buf)
	for n > 0 {
		idx--
		buf[idx] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[idx:])
}

// tlsVersionTLS12 mirrors crypto/tls.VersionTLS12 (0x0303) without
// importing crypto/tls into this data-only file.
const tlsVersionTLS12 = 0x0303

// scalanceProfinetTree is the fake PROFINET device tree a SCALANCE
// switch advertises — one IO-controller (the PLC) plus a couple of
// IO-devices (drives / remote IO) on the cell network. Shared by the
// SCALANCE archetypes.
var scalanceProfinetTree = []PROFINETDevice{
	{StationName: "plc-cell3", IP: "192.168.0.10", Role: "io-controller", Vendor: "Siemens"},
	{StationName: "et200sp-01", IP: "192.168.0.21", Role: "io-device", Vendor: "Siemens"},
	{StationName: "sinamics-g120-01", IP: "192.168.0.31", Role: "io-device", Vendor: "Siemens"},
}
