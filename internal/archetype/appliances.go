package archetype

import "crypto/tls"

// applianceArchetypes models common internet- and OT-exposed appliances
// that the distro/Windows/Cisco/edge profiles don't cover: firewalls, NAS,
// IP cameras, more PLC vendors, a network printer, and a VoIP PBX. Each
// carries the distinctive HTTP headers / Server banner / SNMP identity that
// scanners (Shodan/Censys) key on. Families are appliance-specific so the
// distro-completeness tests don't apply to them.
var applianceArchetypes = map[string]*Profile{
	"pfsense":               pfsense(),
	"fortigate":             fortigate(),
	"synology-dsm":          synologyDSM(),
	"qnap-qts":              qnapQTS(),
	"netgear-readynas":      netgearReadyNAS(),
	"asustor-nas":           asustorNAS(),
	"oki-printer":           okiPrinter(),
	"toshiba-estudio":       toshibaEStudio(),
	"hikvision-camera":      hikvisionCamera(),
	"hikvision-ptz":         hikvisionPTZ(),
	"hikvision-nvr":         hikvisionNVR(),
	"axis-camera":           axisCamera(),
	"axis-p3245":            axisP3245(),
	"axis-q6075":            axisQ6075(),
	"bosch-camera":          boschCamera(),
	"bosch-flexidome":       boschFlexidome(),
	"bosch-autodome":        boschAutodome(),
	"ubiquiti-edgerouter":   ubiquitiEdgeRouter(),
	"rockwell-controllogix": rockwellControlLogix(),
	"schneider-modicon":     schneiderModicon(),
	"omron-plc":             omronPLC(),
	"hp-printer":            hpPrinter(),
	"asterisk-voip":         asteriskVoIP(),
}

func pfsense() *Profile {
	return &Profile{
		Name: "pfsense", DisplayName: "pfSense (Netgate firewall)", Family: "pfsense",
		sshBanner:    "SSH-2.0-OpenSSH_8.8 FreeBSD-20211221",
		httpServer:   "nginx",
		httpTitle:    "Login - pfSense",
		httpBodyHTML: "<html><head><title>pfSense - Login</title></head><body><h1>pfSense</h1><form>Username Password</form></body></html>",
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN", "X-Content-Type-Options": "nosniff"},
		snmpSysDescr: "pfSense fw01.local FreeBSD 14.0-RELEASE-p6 amd64",
		snmpSysName:  "pfsense", snmpSysObjectID: ".1.3.6.1.4.1.12325.1.1.2.1.1",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 443, Handler: "https", Note: "web GUI"}, {Port: 80, Handler: "http", Note: "web GUI redirect"},
			{Port: 22, Handler: "ssh", Note: "SSH"}, {Port: 161, Handler: "snmp", Note: "SNMP"},
		},
		quirks: []string{"freebsd"},
	}
}

func fortigate() *Profile {
	return &Profile{
		Name: "fortigate", DisplayName: "Fortinet FortiGate (FortiOS)", Family: "fortios",
		sshBanner:    "SSH-2.0-OpenSSH_7.4",
		httpServer:   "xxxxxxxx-xxxxx",
		httpTitle:    "FortiGate",
		httpBodyHTML: "<html><head><title>FortiGate</title></head><body>Please Login</body></html>",
		httpHeaders: map[string]string{
			"Set-Cookie":      "SVPNCOOKIE=; path=/; secure; httponly",
			"X-Frame-Options": "SAMEORIGIN",
		},
		snmpSysDescr: "FortiGate-60F", snmpSysName: "FGT60F", snmpSysObjectID: ".1.3.6.1.4.1.12356.101.1.6001",
		macOUI:  [3]byte{0x00, 0x09, 0x0f}, // Fortinet
		icmpTTL: 255,
		tls:     TLSPosture{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, WeakCiphers: true},
		// FortiOS SSL-VPN path traversal (CVE-2018-13379) is the canonical
		// FortiGate exposure; advertised only when vuln_emulation is on.
		patchLevel: "FortiOS 6.0.4", cveVulns: []string{"CVE-2018-13379"},
		defaultServices: []DefaultService{
			{Port: 443, Handler: "https", Note: "admin / SSL-VPN"}, {Port: 22, Handler: "ssh", Note: "SSH"},
			{Port: 10443, Handler: "https", Note: "SSL-VPN portal"}, {Port: 161, Handler: "snmp", Note: "SNMP"},
		},
		quirks: []string{"fortios"},
	}
}

func synologyDSM() *Profile {
	return &Profile{
		Name: "synology-dsm", DisplayName: "Synology DiskStation (DSM)", Family: "synology",
		sshBanner:    "SSH-2.0-OpenSSH_8.2p1",
		httpServer:   "nginx",
		httpTitle:    "Synology DiskStation",
		httpBodyHTML: "<html><head><title>Synology DiskStation</title></head><body>QuickConnect</body></html>",
		httpHeaders:  map[string]string{"X-Content-Type-Options": "nosniff", "Set-Cookie": "id=; path=/; HttpOnly"},
		snmpSysDescr: "Synology DS920+ DSM 7.2", snmpSysName: "DiskStation", snmpSysObjectID: ".1.3.6.1.4.1.6574.1",
		macOUI:  [3]byte{0x00, 0x11, 0x32}, // Synology
		icmpTTL: 64,
		ftpFeatures: []string{
			"EPRT", "EPSV", "MDTM", "MFMT", "MLSD",
			"MLST type*;size*;modify*;UNIX.mode*;UNIX.owner*;UNIX.group*",
			"PASV", "REST STREAM", "SIZE", "TVFS", "UTF8",
		},
		defaultServices: []DefaultService{
			{Port: 5000, Handler: "http", Note: "DSM web"}, {Port: 5001, Handler: "https", Note: "DSM web (TLS)"},
			{Port: 445, Handler: "smb", Note: "SMB"}, {Port: 22, Handler: "ssh", Note: "SSH"},
			{Port: 21, Handler: "ftp", Note: "FTP"},
		},
		quirks: []string{"nas"},
	}
}

func qnapQTS() *Profile {
	return &Profile{
		Name: "qnap-qts", DisplayName: "QNAP Turbo NAS (QTS)", Family: "qnap",
		sshBanner:    "SSH-2.0-OpenSSH_8.4",
		httpServer:   "http server",
		httpTitle:    "QNAP Turbo NAS",
		httpBodyHTML: "<html><head><title>QNAP Turbo NAS</title></head><body>QTS</body></html>",
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "QNAP TS-453D QTS 5.0", snmpSysName: "NAS", snmpSysObjectID: ".1.3.6.1.4.1.24681.1",
		macOUI:  [3]byte{0x24, 0x5e, 0xbe}, // QNAP
		icmpTTL: 64,
		ftpFeatures: []string{
			"CLNT", "EPRT", "EPSV", "MDTM", "MFMT", "MLSD",
			"MLST type*;size*;modify*;UNIX.mode*", "PASV", "REST STREAM",
			"SIZE", "TVFS", "UTF8",
		},
		defaultServices: []DefaultService{
			{Port: 8080, Handler: "http", Note: "QTS web"}, {Port: 443, Handler: "https", Note: "QTS web (TLS)"},
			{Port: 445, Handler: "smb", Note: "SMB"}, {Port: 22, Handler: "ssh", Note: "SSH"},
			{Port: 21, Handler: "ftp", Note: "FTP"},
		},
		quirks: []string{"nas"},
	}
}

func hikvisionCamera() *Profile {
	return &Profile{
		Name: "hikvision-camera", DisplayName: "Hikvision IP camera", Family: "hikvision",
		httpServer:   "App-webs/",
		httpTitle:    "",
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN", "WWW-Authenticate": "Digest realm=\"IP Camera\""},
		snmpSysDescr: "Hikvision DS-2CD2042WD-I", snmpSysName: "IPCamera",
		macOUI:  [3]byte{0x44, 0x19, 0xb6}, // Hikvision
		icmpTTL: 64,
		// CVE-2017-7921: Hikvision auth-bypass / backdoor — the camera's
		// signature exposure.
		patchLevel: "V5.4.0", cveVulns: []string{"CVE-2017-7921"},
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "web UI"}, {Port: 554, Handler: "rtsp", Note: "RTSP stream"},
			{Port: 8000, Handler: "raw", Note: "SDK / proprietary"},
		},
		quirks: []string{"camera", "onvif"},
	}
}

func axisCamera() *Profile {
	return &Profile{
		Name: "axis-camera", DisplayName: "Axis network camera", Family: "axis",
		httpServer:   "Apache/2.4.53",
		httpTitle:    "AXIS",
		httpHeaders:  map[string]string{"WWW-Authenticate": "Digest realm=\"AXIS_ACCC8E000000\""},
		snmpSysDescr: "AXIS M3045-V Network Camera", snmpSysName: "axis-camera",
		macOUI:  [3]byte{0x00, 0x40, 0x8c}, // Axis
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "web UI / VAPIX"}, {Port: 554, Handler: "rtsp", Note: "RTSP stream"},
		},
		quirks: []string{"camera", "onvif"},
	}
}

func boschCamera() *Profile {
	return &Profile{
		Name: "bosch-camera", DisplayName: "Bosch IP camera", Family: "bosch",
		httpServer:   "lighttpd",
		httpTitle:    "BOSCH",
		httpHeaders:  map[string]string{"WWW-Authenticate": "Digest realm=\"Bosch Security Systems\""},
		snmpSysDescr: "Bosch DINION IP starlight 7000", snmpSysName: "Camera",
		macOUI:  [3]byte{0x00, 0x07, 0x5f}, // Bosch Security Systems
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "web UI"}, {Port: 554, Handler: "rtsp", Note: "RTSP stream"},
			{Port: 1756, Handler: "raw", Note: "Bosch RCP+ control"},
		},
		quirks: []string{"camera", "onvif"},
	}
}

// --- Additional camera variants (fixed dome / PTZ / NVR) -------------------

func axisP3245() *Profile {
	return &Profile{
		Name: "axis-p3245", DisplayName: "Axis P3245-LVE dome camera", Family: "axis",
		httpServer:   "Apache/2.4.53",
		httpTitle:    "AXIS",
		httpHeaders:  map[string]string{"WWW-Authenticate": "Digest realm=\"AXIS_ACCC8E000000\""},
		snmpSysDescr: "AXIS P3245-LVE Network Camera", snmpSysName: "axis-p3245",
		macOUI:  [3]byte{0x00, 0x40, 0x8c}, // Axis
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "web UI / VAPIX"}, {Port: 443, Handler: "https", Note: "web UI (TLS)"},
			{Port: 554, Handler: "rtsp", Note: "RTSP stream"},
		},
		quirks: []string{"camera", "onvif"},
	}
}

func axisQ6075() *Profile {
	return &Profile{
		Name: "axis-q6075", DisplayName: "Axis Q6075 PTZ camera", Family: "axis",
		httpServer:   "Apache/2.4.53",
		httpTitle:    "AXIS",
		httpHeaders:  map[string]string{"WWW-Authenticate": "Digest realm=\"AXIS_ACCC8E000000\""},
		snmpSysDescr: "AXIS Q6075 PTZ Network Camera", snmpSysName: "axis-q6075",
		macOUI:  [3]byte{0x00, 0x40, 0x8c}, // Axis
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "web UI / VAPIX"}, {Port: 443, Handler: "https", Note: "web UI (TLS)"},
			{Port: 554, Handler: "rtsp", Note: "RTSP stream"},
		},
		quirks: []string{"camera", "onvif", "ptz"},
	}
}

func hikvisionPTZ() *Profile {
	return &Profile{
		Name: "hikvision-ptz", DisplayName: "Hikvision DS-2DE PTZ camera", Family: "hikvision",
		httpServer:   "App-webs/",
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN", "WWW-Authenticate": "Digest realm=\"IP Camera\""},
		snmpSysDescr: "Hikvision DS-2DE4A425IW-DE", snmpSysName: "IPCamera",
		macOUI:  [3]byte{0x44, 0x19, 0xb6}, // Hikvision
		icmpTTL: 64,
		// CVE-2021-36260: webserver command injection across many Hikvision
		// IP cameras / PTZ — the signature exposure for current firmware.
		patchLevel: "V5.5.800", cveVulns: []string{"CVE-2021-36260"},
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "web UI"}, {Port: 554, Handler: "rtsp", Note: "RTSP stream"},
			{Port: 8000, Handler: "raw", Note: "SDK / proprietary"},
		},
		quirks: []string{"camera", "onvif", "ptz"},
	}
}

func hikvisionNVR() *Profile {
	return &Profile{
		Name: "hikvision-nvr", DisplayName: "Hikvision DS-7608NI NVR", Family: "hikvision",
		httpServer:   "App-webs/",
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN", "WWW-Authenticate": "Digest realm=\"Embedded Net DVR\""},
		snmpSysDescr: "Hikvision DS-7608NI-K2 NVR", snmpSysName: "NVR",
		macOUI:     [3]byte{0x44, 0x19, 0xb6}, // Hikvision
		icmpTTL:    64,
		patchLevel: "V4.30.000", cveVulns: []string{"CVE-2021-36260"},
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "web UI"}, {Port: 554, Handler: "rtsp", Note: "RTSP stream"},
			{Port: 8000, Handler: "raw", Note: "SDK / proprietary"},
		},
		quirks: []string{"camera", "onvif", "nvr"},
	}
}

func boschFlexidome() *Profile {
	return &Profile{
		Name: "bosch-flexidome", DisplayName: "Bosch FLEXIDOME IP camera", Family: "bosch",
		httpServer:   "lighttpd",
		httpTitle:    "BOSCH",
		httpHeaders:  map[string]string{"WWW-Authenticate": "Digest realm=\"Bosch Security Systems\""},
		snmpSysDescr: "Bosch FLEXIDOME IP 5000i", snmpSysName: "Camera",
		macOUI:  [3]byte{0x00, 0x07, 0x5f}, // Bosch Security Systems
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "web UI"}, {Port: 554, Handler: "rtsp", Note: "RTSP stream"},
			{Port: 1756, Handler: "raw", Note: "Bosch RCP+ control"},
		},
		quirks: []string{"camera", "onvif"},
	}
}

func boschAutodome() *Profile {
	return &Profile{
		Name: "bosch-autodome", DisplayName: "Bosch AUTODOME PTZ camera", Family: "bosch",
		httpServer:   "lighttpd",
		httpTitle:    "BOSCH",
		httpHeaders:  map[string]string{"WWW-Authenticate": "Digest realm=\"Bosch Security Systems\""},
		snmpSysDescr: "Bosch AUTODOME IP 5000i", snmpSysName: "Camera",
		macOUI:  [3]byte{0x00, 0x07, 0x5f}, // Bosch Security Systems
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "web UI"}, {Port: 554, Handler: "rtsp", Note: "RTSP stream"},
			{Port: 1756, Handler: "raw", Note: "Bosch RCP+ control"},
		},
		quirks: []string{"camera", "onvif", "ptz"},
	}
}

func ubiquitiEdgeRouter() *Profile {
	return &Profile{
		Name: "ubiquiti-edgerouter", DisplayName: "Ubiquiti EdgeRouter (EdgeOS)", Family: "ubiquiti",
		sshBanner:    "SSH-2.0-OpenSSH_7.4 Debian",
		httpServer:   "lighttpd",
		httpTitle:    "EdgeOS",
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "EdgeOS v2.0.9 ER-X", snmpSysName: "ubnt", snmpSysObjectID: ".1.3.6.1.4.1.41112",
		macOUI:  [3]byte{0x24, 0xa4, 0x3c}, // Ubiquiti
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 443, Handler: "https", Note: "web UI"}, {Port: 22, Handler: "ssh", Note: "SSH"},
			{Port: 161, Handler: "snmp", Note: "SNMP"},
		},
		quirks: []string{"edgeos"},
	}
}

func rockwellControlLogix() *Profile {
	return &Profile{
		Name: "rockwell-controllogix", DisplayName: "Allen-Bradley ControlLogix (Rockwell)", Family: "ics",
		httpServer:   "Allen-Bradley",
		httpTitle:    "Rockwell Automation",
		snmpSysDescr: "1756-L75 ControlLogix 5575", snmpSysName: "ControlLogix",
		macOUI:  [3]byte{0x00, 0x00, 0xbc}, // Rockwell/Allen-Bradley
		icmpTTL: 64,                        // ControlLogix stacks commonly report 64
		defaultServices: []DefaultService{
			{Port: 44818, Handler: "ethernetip", Note: "EtherNet/IP (CIP)"}, {Port: 2222, Handler: "raw", Note: "EtherNet/IP I/O"},
			{Port: 80, Handler: "http", Note: "web"}, {Port: 161, Handler: "snmp", Note: "SNMP"},
		},
		quirks: []string{"cip", "rockwell"},
	}
}

func schneiderModicon() *Profile {
	return &Profile{
		Name: "schneider-modicon", DisplayName: "Schneider Modicon M340 PLC", Family: "ics",
		httpServer:   "Schneider-WEB/V",
		httpTitle:    "Schneider Electric",
		snmpSysDescr: "BMX P34 2020 Modicon M340", snmpSysName: "Modicon",
		macOUI:  [3]byte{0x00, 0x80, 0xf4}, // Schneider/Telemecanique
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 502, Handler: "modbus", Note: "Modbus/TCP"}, {Port: 44818, Handler: "ethernetip", Note: "EtherNet/IP"},
			{Port: 80, Handler: "http", Note: "web"}, {Port: 161, Handler: "snmp", Note: "SNMP"},
		},
		quirks: []string{"modbus", "schneider"},
	}
}

func omronPLC() *Profile {
	return &Profile{
		Name: "omron-plc", DisplayName: "Omron PLC (FINS)", Family: "ics",
		httpServer:   "OMRON",
		snmpSysDescr: "OMRON CJ2M-CPU", snmpSysName: "omron-plc",
		macOUI:  [3]byte{0x00, 0x00, 0x0a}, // Omron
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 9600, Handler: "fins", Note: "FINS (TCP/UDP)"}, {Port: 44818, Handler: "ethernetip", Note: "EtherNet/IP"},
			{Port: 80, Handler: "http", Note: "web"},
		},
		quirks: []string{"fins", "omron"},
	}
}

func netgearReadyNAS() *Profile {
	return &Profile{
		Name: "netgear-readynas", DisplayName: "Netgear ReadyNAS", Family: "netgear",
		sshBanner:    "SSH-2.0-OpenSSH_7.4p1 Debian-10",
		httpServer:   "Apache",
		httpTitle:    "ReadyNAS",
		httpBodyHTML: "<html><head><title>ReadyNAS</title></head><body>ReadyNAS OS 6</body></html>",
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "NETGEAR ReadyNAS RN424 ReadyNASOS 6.10", snmpSysName: "ReadyNAS", snmpSysObjectID: ".1.3.6.1.4.1.4526",
		macOUI:  [3]byte{0x00, 0x0f, 0xb5}, // Netgear
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "admin web"}, {Port: 443, Handler: "https", Note: "admin web (TLS)"},
			{Port: 445, Handler: "smb", Note: "SMB"}, {Port: 22, Handler: "ssh", Note: "SSH"},
		},
		quirks: []string{"nas"},
	}
}

func asustorNAS() *Profile {
	return &Profile{
		Name: "asustor-nas", DisplayName: "ASUSTOR NAS (ADM)", Family: "asustor",
		sshBanner:    "SSH-2.0-OpenSSH_8.4",
		httpServer:   "nginx",
		httpTitle:    "ASUSTOR",
		httpBodyHTML: "<html><head><title>ASUSTOR ADM</title></head><body>ADM</body></html>",
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "ASUSTOR AS5304T ADM 4.2", snmpSysName: "AS-NAS", snmpSysObjectID: ".1.3.6.1.4.1.43000",
		macOUI:  [3]byte{0x00, 0x1f, 0xc6}, // ASUSTeK
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 8000, Handler: "http", Note: "ADM web"}, {Port: 8001, Handler: "https", Note: "ADM web (TLS)"},
			{Port: 445, Handler: "smb", Note: "SMB"}, {Port: 22, Handler: "ssh", Note: "SSH"},
		},
		quirks: []string{"nas"},
	}
}

func okiPrinter() *Profile {
	return &Profile{
		Name: "oki-printer", DisplayName: "OKI ES network printer", Family: "printer",
		httpServer:   "EWS/2.0",
		httpTitle:    "OKI",
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "OKI ES8434 MFP", snmpSysName: "OKI", snmpSysObjectID: ".1.3.6.1.4.1.2001.1.2",
		macOUI:  [3]byte{0x00, 0x80, 0x92}, // OKI
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "EWS web"}, {Port: 443, Handler: "https", Note: "EWS web (TLS)"},
			{Port: 9100, Handler: "pjl", Note: "JetDirect / PJL"}, {Port: 631, Handler: "ipp", Note: "IPP"},
			{Port: 515, Handler: "lpd", Note: "LPD"}, {Port: 161, Handler: "snmp", Note: "SNMP"},
		},
		quirks: []string{"printer", "pjl"},
	}
}

func toshibaEStudio() *Profile {
	return &Profile{
		Name: "toshiba-estudio", DisplayName: "Toshiba e-STUDIO (MFP)", Family: "printer",
		httpServer:   "TOSHIBA e-STUDIO",
		httpTitle:    "TOSHIBA e-STUDIO",
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "TOSHIBA e-STUDIO3508A", snmpSysName: "MFP", snmpSysObjectID: ".1.3.6.1.4.1.1129",
		macOUI:  [3]byte{0x00, 0x80, 0x91}, // Toshiba
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "TopAccess web"}, {Port: 443, Handler: "https", Note: "TopAccess web (TLS)"},
			{Port: 9100, Handler: "pjl", Note: "JetDirect / PJL"}, {Port: 631, Handler: "ipp", Note: "IPP"},
			{Port: 515, Handler: "lpd", Note: "LPD"}, {Port: 161, Handler: "snmp", Note: "SNMP"},
		},
		quirks: []string{"printer", "pjl"},
	}
}

func hpPrinter() *Profile {
	return &Profile{
		Name: "hp-printer", DisplayName: "HP LaserJet (network printer)", Family: "printer",
		httpServer:   "HP HTTP Server; HP LaserJet",
		httpTitle:    "HP LaserJet",
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "HP LaserJet MFP M428fdw", snmpSysName: "NPI", snmpSysObjectID: ".1.3.6.1.4.1.11.2.3.9.1",
		macOUI:  [3]byte{0x00, 0x1b, 0x78}, // HP
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "EWS web"}, {Port: 443, Handler: "https", Note: "EWS web (TLS)"},
			{Port: 9100, Handler: "pjl", Note: "JetDirect / PJL"}, {Port: 631, Handler: "ipp", Note: "IPP"},
			{Port: 515, Handler: "lpd", Note: "LPD"}, {Port: 161, Handler: "snmp", Note: "SNMP"},
		},
		quirks: []string{"printer", "pjl"},
	}
}

func asteriskVoIP() *Profile {
	return &Profile{
		Name: "asterisk-voip", DisplayName: "Asterisk PBX (VoIP)", Family: "voip",
		sshBanner:    "SSH-2.0-OpenSSH_8.9p1 Ubuntu",
		httpServer:   "Asterisk/18.10.0",
		httpTitle:    "FreePBX Administration",
		httpHeaders:  map[string]string{"X-Powered-By": "PHP/7.4.3"},
		snmpSysDescr: "Asterisk PBX 18.10.0 on Linux", snmpSysName: "pbx",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 5060, Handler: "sip", Note: "SIP (UDP)"}, {Port: 80, Handler: "http", Note: "FreePBX web"},
			{Port: 22, Handler: "ssh", Note: "SSH"},
		},
		quirks: []string{"voip", "sip"},
	}
}
