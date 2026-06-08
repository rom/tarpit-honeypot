package archetype

// networkDeviceArchetypes models SOHO / edge networking gear that shows up
// constantly on internet-exposed and OT-edge segments: MikroTik RouterOS
// routers and Teltonika RUT-series industrial cellular routers. Both are
// Linux-based (icmpTTL 64) but present very distinct, recognisable service
// banners + SNMP identities that scanners (Shodan/Censys) key on.
var networkDeviceArchetypes = map[string]*Profile{
	"mikrotik-router":       mikrotikProfile(),
	"mikrotik-routeros":     mikrotikProfile(),
	"mikrotik-routerboard":  mikrotikProfile(),
	"mikrotik-routeros-7":   mikrotikProfileVer("7.15.3", "RB5009UG+S+", "mikrotik-routeros-7", "MikroTik RouterOS 7 (RB5009)", nil),
	"mikrotik-routeros-640": mikrotikProfileVer("6.40.8", "RB951G-2HnD", "mikrotik-routeros-640", "MikroTik RouterOS 6.40 (Winbox CVE-2018-14847)", []string{"CVE-2018-14847"}),
	"teltonika-rut240":      teltonikaRUT240(),
	"teltonika-router":      teltonikaRUT240(),

	// ---- Service-provider / data-center routers & switches ----
	"juniper-mx480": {
		Name: "juniper-mx480", DisplayName: "Juniper MX480 (Junos)", Family: "juniper",
		patchLevel:      "Junos 21.4R1",
		cveVulns:        []string{"CVE-2023-36845"},
		macOUI:          [3]byte{0x3C, 0x61, 0x04},
		sshBanner:       "SSH-2.0-OpenSSH_7.4",
		telnetBanner:    "\r\nMX480 (ttyu0)\r\n\r\nlogin: ",
		loginPrompt:     "login: ",
		cliPrompt:       "root@mx480> ",
		httpServer:      "Juniper Networks J-Web",
		httpTitle:       "Juniper Web Device Manager",
		httpBodyHTML:    `<html><head><title>Juniper Web Device Manager</title></head><body><h2>MX480 Universal Routing Platform</h2><p>Junos 21.4R3</p></body></html>`,
		snmpSysDescr:    "Juniper Networks, Inc. mx480 internet router, kernel JUNOS 21.4R3, Build date: 2022-03-31",
		snmpSysObjectID: ".1.3.6.1.4.1.2636.1.1.1.2.25",
		snmpSysName:     "mx480",
		snmpSysLocation: "Core PoP A",
		icmpTTL:         64,
		cpe:             "cpe:2.3:o:juniper:junos:21.4:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 23, Handler: "telnet"}, {Port: 443, Handler: "https"},
			{Port: 161, Handler: "snmp"}, {Port: 830, Handler: "raw", Note: "NETCONF"},
		},
		quirks: []string{"juniper", "junos"},
	},
	"juniper-mx960": {
		Name: "juniper-mx960", DisplayName: "Juniper MX960 (Junos)", Family: "juniper",
		patchLevel:      "Junos 21.4R1",
		cveVulns:        []string{"CVE-2023-36845"},
		macOUI:          [3]byte{0x3C, 0x61, 0x04},
		sshBanner:       "SSH-2.0-OpenSSH_7.4",
		telnetBanner:    "\r\nMX960 (ttyu0)\r\n\r\nlogin: ",
		loginPrompt:     "login: ",
		cliPrompt:       "root@mx960> ",
		httpServer:      "Juniper Networks J-Web",
		httpTitle:       "Juniper Web Device Manager",
		httpBodyHTML:    `<html><head><title>Juniper Web Device Manager</title></head><body><h2>MX960 Universal Routing Platform</h2><p>Junos 21.4R3</p></body></html>`,
		snmpSysDescr:    "Juniper Networks, Inc. mx960 internet router, kernel JUNOS 21.4R3, Build date: 2022-03-31",
		snmpSysObjectID: ".1.3.6.1.4.1.2636.1.1.1.2.29",
		snmpSysName:     "mx960",
		snmpSysLocation: "Core PoP B",
		icmpTTL:         64,
		cpe:             "cpe:2.3:o:juniper:junos:21.4:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 23, Handler: "telnet"}, {Port: 443, Handler: "https"},
			{Port: 161, Handler: "snmp"}, {Port: 830, Handler: "raw", Note: "NETCONF"},
		},
		quirks: []string{"juniper", "junos"},
	},
	"juniper-ex4300": {
		Name: "juniper-ex4300", DisplayName: "Juniper EX4300 (Junos switch)", Family: "juniper",
		patchLevel:      "Junos 20.4R1",
		cveVulns:        []string{"CVE-2023-36845"},
		macOUI:          [3]byte{0x3C, 0x61, 0x04},
		sshBanner:       "SSH-2.0-OpenSSH_7.4",
		telnetBanner:    "\r\nEX4300 (ttyu0)\r\n\r\nlogin: ",
		loginPrompt:     "login: ",
		cliPrompt:       "root@ex4300> ",
		httpServer:      "Juniper Networks J-Web",
		httpTitle:       "Juniper Web Device Manager",
		httpBodyHTML:    `<html><head><title>Juniper Web Device Manager</title></head><body><h2>EX4300-48T Ethernet Switch</h2><p>Junos 20.4R3</p></body></html>`,
		snmpSysDescr:    "Juniper Networks, Inc. ex4300-48t Ethernet Switch, kernel JUNOS 20.4R3",
		snmpSysObjectID: ".1.3.6.1.4.1.2636.1.1.1.2.82",
		snmpSysName:     "ex4300",
		snmpSysLocation: "DC1 access",
		icmpTTL:         64,
		cpe:             "cpe:2.3:o:juniper:junos:20.4:*:*:*:*:*:*:*",
		snmpIfTable:     mockSwitchInterfaces(48, "ge-0/0/"),
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 23, Handler: "telnet"}, {Port: 443, Handler: "https"},
			{Port: 161, Handler: "snmp"}, {Port: 830, Handler: "raw", Note: "NETCONF"},
		},
		quirks: []string{"juniper", "junos"},
	},
	"juniper-qfx5120": {
		Name: "juniper-qfx5120", DisplayName: "Juniper QFX5120 (Junos DC switch)", Family: "juniper",
		patchLevel:      "Junos 21.2R1",
		cveVulns:        []string{"CVE-2023-36845"},
		macOUI:          [3]byte{0x3C, 0x61, 0x04},
		sshBanner:       "SSH-2.0-OpenSSH_7.4",
		loginPrompt:     "login: ",
		cliPrompt:       "root@qfx5120> ",
		httpServer:      "Juniper Networks J-Web",
		httpTitle:       "Juniper Web Device Manager",
		httpBodyHTML:    `<html><head><title>Juniper Web Device Manager</title></head><body><h2>QFX5120-48Y</h2><p>Junos 21.2R3</p></body></html>`,
		snmpSysDescr:    "Juniper Networks, Inc. qfx5120-48y Ethernet Switch, kernel JUNOS 21.2R3",
		snmpSysObjectID: ".1.3.6.1.4.1.2636.1.1.1.2.158",
		snmpSysName:     "qfx5120",
		snmpSysLocation: "DC1 spine",
		icmpTTL:         64,
		cpe:             "cpe:2.3:o:juniper:junos:21.2:*:*:*:*:*:*:*",
		snmpIfTable:     mockSwitchInterfaces(48, "et-0/0/"),
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 443, Handler: "https"},
			{Port: 161, Handler: "snmp"}, {Port: 830, Handler: "raw", Note: "NETCONF"},
		},
		quirks: []string{"juniper", "junos"},
	},
	"arista-7280r": {
		Name: "arista-7280r", DisplayName: "Arista 7280R (EOS)", Family: "arista",
		macOUI:          [3]byte{0x00, 0x1C, 0x73},
		sshBanner:       "SSH-2.0-OpenSSH_8.0",
		loginPrompt:     "localhost login: ",
		cliPrompt:       "arista-7280#",
		httpServer:      "nginx",
		httpTitle:       "Arista EOS",
		httpBodyHTML:    `<html><head><title>Arista EOS</title></head><body><h2>Arista DCS-7280R3-24</h2><p>EOS 4.30.3M</p></body></html>`,
		snmpSysDescr:    "Arista Networks EOS version 4.30.3M running on an Arista Networks DCS-7280R3-24",
		snmpSysObjectID: ".1.3.6.1.4.1.30065.1.3011.7280",
		snmpSysName:     "arista-7280r",
		snmpSysLocation: "Edge PoP",
		icmpTTL:         64,
		cpe:             "cpe:2.3:o:arista:eos:4.30.3m:*:*:*:*:*:*:*",
		snmpIfTable:     mockSwitchInterfaces(24, "Ethernet"),
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 443, Handler: "https", Note: "eAPI"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"arista", "eos"},
	},
	"cisco-ncs5500": {
		Name: "cisco-ncs5500", DisplayName: "Cisco NCS 5500 (IOS XR)", Family: "cisco",
		patchLevel:      "IOS XR 7.3.1",
		cveVulns:        []string{"CVE-2022-20821"},
		macOUI:          [3]byte{0x00, 0x00, 0x0c},
		sshBanner:       "SSH-2.0-Cisco-2.0",
		telnetBanner:    "\r\nUser Access Verification\r\n\r\nUsername: ",
		loginPrompt:     "Username: ",
		cliPrompt:       "RP/0/RP0/CPU0:ncs5500#",
		snmpSysDescr:    "Cisco IOS XR Software (NCS-5500), Version 7.5.2, Copyright (c) 2022 by Cisco Systems, Inc.",
		snmpSysObjectID: ".1.3.6.1.4.1.9.1.2734",
		snmpSysName:     "ncs5500",
		snmpSysLocation: "Core PoP",
		icmpTTL:         255,
		cpe:             "cpe:2.3:o:cisco:ios_xr:7.5.2:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 23, Handler: "telnet"},
			{Port: 161, Handler: "snmp"}, {Port: 830, Handler: "raw", Note: "NETCONF"},
		},
		quirks: []string{"cisco", "iosxr"},
	},
	"cisco-asr9000": {
		Name: "cisco-asr9000", DisplayName: "Cisco ASR 9000 (IOS XR)", Family: "cisco",
		patchLevel:      "IOS XR 7.3.1",
		cveVulns:        []string{"CVE-2022-20821"},
		macOUI:          [3]byte{0x00, 0x00, 0x0c},
		sshBanner:       "SSH-2.0-Cisco-2.0",
		telnetBanner:    "\r\nUser Access Verification\r\n\r\nUsername: ",
		loginPrompt:     "Username: ",
		cliPrompt:       "RP/0/RSP0/CPU0:asr9000#",
		snmpSysDescr:    "Cisco IOS XR Software (Cisco ASR9K Series), Version 7.5.2, Copyright (c) 2022 by Cisco Systems, Inc.",
		snmpSysObjectID: ".1.3.6.1.4.1.9.1.1639",
		snmpSysName:     "asr9000",
		snmpSysLocation: "Edge PoP",
		icmpTTL:         255,
		cpe:             "cpe:2.3:o:cisco:ios_xr:7.5.2:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 23, Handler: "telnet"},
			{Port: 161, Handler: "snmp"}, {Port: 830, Handler: "raw", Note: "NETCONF"},
		},
		quirks: []string{"cisco", "iosxr"},
	},
	"nokia-7750-sr1": {
		Name: "nokia-7750-sr1", DisplayName: "Nokia 7750 SR-1 (SR OS)", Family: "nokia",
		macOUI:          [3]byte{0x00, 0x1a, 0xf0},
		sshBanner:       "SSH-2.0-OpenSSH_7.5",
		telnetBanner:    "\r\nNokia 7750 SR-1\r\n\r\nLogin: ",
		loginPrompt:     "Login: ",
		cliPrompt:       "A:nokia-7750# ",
		snmpSysDescr:    "TiMOS-B-22.10.R1 both/x86_64 Nokia 7750 SR Copyright (c) 2000-2022 Nokia.",
		snmpSysObjectID: ".1.3.6.1.4.1.6527.1.3.1",
		snmpSysName:     "nokia-7750-sr1",
		snmpSysLocation: "Core PoP",
		icmpTTL:         255,
		cpe:             "cpe:2.3:o:nokia:sr_os:22.10.r1:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 23, Handler: "telnet"},
			{Port: 161, Handler: "snmp"}, {Port: 830, Handler: "raw", Note: "NETCONF"},
		},
		quirks: []string{"nokia", "sros"},
	},
	"ubiquiti-unifi-switch": {
		Name: "ubiquiti-unifi-switch", DisplayName: "Ubiquiti UniFi Switch (USW)", Family: "ubiquiti",
		macOUI:          [3]byte{0xfc, 0xec, 0xda},
		sshBanner:       "SSH-2.0-OpenSSH_8.4",
		loginPrompt:     "login: ",
		cliPrompt:       "USW-24-PoE# ",
		httpServer:      "nginx",
		httpTitle:       "UniFi",
		httpBodyHTML:    `<html><head><title>UniFi</title></head><body>UniFi Network</body></html>`,
		snmpSysDescr:    "USW-24-PoE, 6.5.59.14555",
		snmpSysObjectID: ".1.3.6.1.4.1.41112",
		snmpSysName:     "USW-24-PoE",
		snmpSysLocation: "IDF-1",
		icmpTTL:         64,
		snmpIfTable:     mockSwitchInterfaces(24, "Port "),
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 80, Handler: "http"}, {Port: 443, Handler: "https"},
			{Port: 161, Handler: "snmp"},
		},
		quirks: []string{"ubiquiti", "unifi"},
	},
	"ubiquiti-unifi-ap": {
		Name: "ubiquiti-unifi-ap", DisplayName: "Ubiquiti UniFi AP (UAP)", Family: "ubiquiti",
		macOUI:          [3]byte{0xfc, 0xec, 0xda},
		sshBanner:       "SSH-2.0-OpenSSH_8.4",
		loginPrompt:     "login: ",
		cliPrompt:       "U6-Pro# ",
		httpServer:      "nginx",
		httpTitle:       "UniFi",
		httpBodyHTML:    `<html><head><title>UniFi</title></head><body>UniFi Network</body></html>`,
		snmpSysDescr:    "U6-Pro, 6.5.59.14555",
		snmpSysObjectID: ".1.3.6.1.4.1.41112",
		snmpSysName:     "U6-Pro",
		snmpSysLocation: "Floor 2",
		icmpTTL:         64,
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 80, Handler: "http"}, {Port: 8443, Handler: "https"},
			{Port: 161, Handler: "snmp"},
		},
		quirks: []string{"ubiquiti", "unifi"},
	},
	"ubiquiti-udm": {
		Name: "ubiquiti-udm", DisplayName: "Ubiquiti Dream Machine (UniFi OS)", Family: "ubiquiti",
		macOUI:          [3]byte{0x74, 0x83, 0xc2},
		sshBanner:       "SSH-2.0-OpenSSH_8.4",
		loginPrompt:     "login: ",
		cliPrompt:       "UDM-Pro# ",
		httpServer:      "nginx",
		httpTitle:       "UniFi OS",
		httpBodyHTML:    `<html><head><title>UniFi OS</title></head><body><h2>UniFi Dream Machine Pro</h2><p>UniFi OS 3.2.12</p></body></html>`,
		snmpSysDescr:    "UniFi Dream Machine Pro, UniFi OS 3.2.12",
		snmpSysObjectID: ".1.3.6.1.4.1.41112",
		snmpSysName:     "UDM-Pro",
		snmpSysLocation: "Network closet",
		icmpTTL:         64,
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 443, Handler: "https", Note: "UniFi OS"},
			{Port: 80, Handler: "http"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"ubiquiti", "unifi"},
	},

	// ---- SOHO / consumer routers (frequent botnet targets) ----
	"dlink-router": {
		Name: "dlink-router", DisplayName: "D-Link DIR router", Family: "dlink",
		macOUI:          [3]byte{0x14, 0xd6, 0x4d},
		httpServer:      "lighttpd/1.4.45",
		httpTitle:       "D-LINK SYSTEMS",
		httpBodyHTML:    `<html><head><title>D-LINK SYSTEMS, INC. | WIRELESS ROUTER</title></head><body><h2>DIR-882</h2><p>Firmware 1.30</p></body></html>`,
		telnetBanner:    "\r\nDIR-882 login: ",
		loginPrompt:     "login: ",
		snmpSysDescr:    "D-Link DIR-882 Wireless Router",
		snmpSysObjectID: ".1.3.6.1.4.1.171",
		snmpSysName:     "dlink-router",
		icmpTTL:         64,
		patchLevel:      "DIR-882 1.30",
		cveVulns:        []string{"CVE-2019-16920", "CVE-2015-2051"},
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "web admin"}, {Port: 443, Handler: "https"},
			{Port: 23, Handler: "telnet"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"soho-router"},
	},
	"tplink-router": {
		Name: "tplink-router", DisplayName: "TP-Link Archer router", Family: "tplink",
		macOUI:          [3]byte{0x50, 0xc7, 0xbf},
		httpServer:      "Router Webserver",
		httpTitle:       "TP-LINK",
		httpBodyHTML:    `<html><head><title>TP-LINK Wireless Router Archer AX21</title></head><body><h2>Archer AX21</h2><p>Firmware 1.1.4 Build 20230219</p></body></html>`,
		telnetBanner:    "\r\nArcher AX21 login: ",
		loginPrompt:     "login: ",
		snmpSysDescr:    "TP-Link Archer AX21 (AX1800)",
		snmpSysObjectID: ".1.3.6.1.4.1.11863",
		snmpSysName:     "tplink-router",
		icmpTTL:         64,
		patchLevel:      "Archer AX21 1.1.4",
		cveVulns:        []string{"CVE-2023-1389"},
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "web admin"}, {Port: 443, Handler: "https"},
			{Port: 161, Handler: "snmp"},
		},
		quirks: []string{"soho-router"},
	},
	"asus-router": {
		Name: "asus-router", DisplayName: "ASUS RT-AX router (ASUSWRT)", Family: "asus",
		macOUI:          [3]byte{0x2c, 0x56, 0xdc},
		sshBanner:       "SSH-2.0-OpenSSH_8.7",
		httpServer:      "httpd/2.0",
		httpTitle:       "ASUS Wireless Router",
		httpBodyHTML:    `<html><head><title>ASUS Wireless Router RT-AX88U</title></head><body><h2>RT-AX88U</h2><p>ASUSWRT 3.0.0.4.388</p></body></html>`,
		telnetBanner:    "\r\nRT-AX88U login: ",
		loginPrompt:     "login: ",
		snmpSysDescr:    "ASUSTeK RT-AX88U ASUSWRT 3.0.0.4.388",
		snmpSysObjectID: ".1.3.6.1.4.1.2623",
		snmpSysName:     "asus-router",
		icmpTTL:         64,
		patchLevel:      "ASUSWRT 3.0.0.4.388",
		cveVulns:        []string{"CVE-2024-3080"},
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "web admin"}, {Port: 8443, Handler: "https"},
			{Port: 22, Handler: "ssh"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"soho-router"},
	},
	// MikroTik hAP ax3 (RouterOS 7) — advertises the RouterOS Winbox privesc.
	"mikrotik-hap-ax3": mikrotikProfileVer("7.15.3", "hAP ax3 (C53UiG+5HPaxD2HPaxD)", "mikrotik-hap-ax3", "MikroTik hAP ax3 (RouterOS 7)", []string{"CVE-2023-30799"}),
}

// mikrotikProfile is a MikroTik RouterOS device. RouterOS has a wholly
// distinctive fingerprint: the SSH server announces "ROSSSH", FTP/Telnet
// say "MikroTik", the web UI is webfig, and Winbox (8291) + the API
// (8728) are MikroTik-only. SNMP sysObjectID lives under the MikroTik
// enterprise tree (.1.3.6.1.4.1.14988). Family "mikrotik" routes the
// interactive shell to the RouterOS CLI emulator.
func mikrotikProfile() *Profile {
	return mikrotikProfileVer("6.49.10", "RB750Gr3", "mikrotik-routeros", "MikroTik RouterOS (RB750Gr3, 6.49.10)", nil)
}

// mikrotikProfileVer builds a RouterOS profile pinned to a specific version +
// board so the catalog can carry several RouterOS generations (the current 7.x
// line and the legacy 6.40 build that shipped the Winbox path-traversal,
// CVE-2018-14847). The fingerprint is otherwise identical RouterOS shape.
func mikrotikProfileVer(ver, board, name, display string, cves []string) *Profile {
	return &Profile{
		Name:        name,
		DisplayName: display,
		Family:      "mikrotik",
		macOUI:      [3]byte{0x4c, 0x5e, 0x0c}, // Routerboard.com / MikroTikls
		cveVulns:    cves,
		sshBanner:   "SSH-2.0-ROSSSH",
		ftpBanner:   "220 router FTP server (MikroTik " + ver + ") ready",
		// RouterOS console login: a "MikroTik v<ver>" header then a login.
		loginPrompt: "\r\n\r\nMikroTik v" + ver + " (stable)\r\nLogin: ",
		cliPrompt:   "[admin@MikroTik] > ",
		httpServer:  "", // RouterOS www sends no Server header
		httpTitle:   "RouterOS router configuration page",
		httpBodyHTML: "<html><head><title>RouterOS router configuration page</title></head>" +
			"<body><p>You have connected to a router. Administrative access only.</p>" +
			"<p>If this device is not yours, please disconnect now.</p>" +
			"<p><a href=\"/webfig/\">webfig</a></p></body></html>",
		snmpSysDescr:    "RouterOS " + board,
		snmpSysObjectID: ".1.3.6.1.4.1.14988.1",
		snmpSysName:     "MikroTik",
		snmpSysContact:  "",
		snmpSysLocation: "",
		icmpTTL:         64, // RouterOS is Linux-based
		snmpIfTable: []Interface{
			{Index: 1, Descr: "ether1", Type: 6, Speed: 1_000_000_000, OperUp: true},
			{Index: 2, Descr: "ether2", Type: 6, Speed: 1_000_000_000, OperUp: true},
			{Index: 3, Descr: "ether3", Type: 6, Speed: 1_000_000_000, OperUp: false},
			{Index: 4, Descr: "bridge", Type: 6, Speed: 1_000_000_000, OperUp: true},
		},
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh", Note: "SSH"},
			{Port: 23, Handler: "telnet", Note: "Telnet"},
			{Port: 21, Handler: "ftp", Note: "FTP"},
			{Port: 80, Handler: "http", Note: "webfig"},
			{Port: 8291, Handler: "raw", Note: "Winbox (MikroTik proprietary mgmt)"},
			{Port: 8728, Handler: "raw", Note: "RouterOS API"},
			{Port: 161, Handler: "snmp", Note: "SNMP"},
		},
		quirks: []string{"routeros", "mikrotik"},
	}
}

// teltonikaRUT240 is a Teltonika RUT240 industrial LTE router running
// RutOS (an OpenWrt derivative). Dropbear SSH, lighttpd web UI, BusyBox
// shell, Teltonika enterprise SNMP OID (.1.3.6.1.4.1.48690). The shell
// falls back to the POSIX/BusyBox table (RutOS genuinely drops to ash).
func teltonikaRUT240() *Profile {
	return &Profile{
		Name:         "teltonika-rut240",
		DisplayName:  "Teltonika RUT240 (RutOS, LTE router)",
		Family:       "teltonika",
		macOUI:       [3]byte{0x20, 0x97, 0x27}, // Teltonika OUI
		sshBanner:    "SSH-2.0-dropbear",
		httpServer:   "lighttpd/1.4.59",
		telnetBanner: "\r\nRUT240 login: ",
		loginPrompt:  "\r\nRUT240 login: ",
		cliPrompt:    "root@RUT240:~# ",
		httpTitle:    "Teltonika Networks - RUT240",
		httpBodyHTML: "<html><head><title>Teltonika Networks - RUT240</title></head>" +
			"<body><h1>RUT240</h1><p>Sign in to RutOS to manage this device.</p></body></html>",
		snmpSysDescr:    "Teltonika RUT240 RutOS",
		snmpSysObjectID: ".1.3.6.1.4.1.48690",
		snmpSysName:     "RUT240",
		snmpSysContact:  "",
		snmpSysLocation: "",
		icmpTTL:         64, // OpenWrt/Linux-based
		snmpIfTable: []Interface{
			{Index: 1, Descr: "eth0", Type: 6, Speed: 100_000_000, OperUp: true},
			{Index: 2, Descr: "wwan0", Type: 1, Speed: 50_000_000, OperUp: true}, // LTE
			{Index: 3, Descr: "br-lan", Type: 6, Speed: 100_000_000, OperUp: true},
		},
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh", Note: "Dropbear SSH"},
			{Port: 80, Handler: "http", Note: "RutOS web UI"},
			{Port: 443, Handler: "https", Note: "RutOS web UI (TLS)"},
			{Port: 161, Handler: "snmp", Note: "SNMP"},
		},
		quirks: []string{"rutos", "openwrt"},
	}
}
