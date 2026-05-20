package archetype

// networkDeviceArchetypes models SOHO / edge networking gear that shows up
// constantly on internet-exposed and OT-edge segments: MikroTik RouterOS
// routers and Teltonika RUT-series industrial cellular routers. Both are
// Linux-based (icmpTTL 64) but present very distinct, recognisable service
// banners + SNMP identities that scanners (Shodan/Censys) key on.
var networkDeviceArchetypes = map[string]*Profile{
	"mikrotik-router":      mikrotikProfile("mikrotik-router"),
	"mikrotik-routeros":    mikrotikProfile("mikrotik-routeros"),
	"mikrotik-routerboard": mikrotikProfile("mikrotik-routerboard"),
	"teltonika-rut240":     teltonikaRUT240(),
	"teltonika-router":     teltonikaRUT240(),
}

// mikrotikProfile is a MikroTik RouterOS device. RouterOS has a wholly
// distinctive fingerprint: the SSH server announces "ROSSSH", FTP/Telnet
// say "MikroTik", the web UI is webfig, and Winbox (8291) + the API
// (8728) are MikroTik-only. SNMP sysObjectID lives under the MikroTik
// enterprise tree (.1.3.6.1.4.1.14988). Family "mikrotik" routes the
// interactive shell to the RouterOS CLI emulator.
func mikrotikProfile(name string) *Profile {
	const ver = "6.49.10"
	return &Profile{
		Name:        name,
		DisplayName: "MikroTik RouterOS (RB750Gr3, " + ver + ")",
		Family:      "mikrotik",
		macOUI:      [3]byte{0x4c, 0x5e, 0x0c}, // Routerboard.com / MikroTikls
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
		snmpSysDescr:    "RouterOS RB750Gr3",
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
