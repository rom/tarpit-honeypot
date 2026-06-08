package archetype

import "crypto/tls"

// ciscoArchetypes models Cisco Catalyst switches running IOS / IOS-XE —
// the canonical enterprise network device. Family "cisco" routes the
// interactive shell to the Cisco IOS command emulator (enable mode, show
// version / running-config / vlan / cdp neighbors). icmpTTL 255 is the
// router/switch default; TLS posture is the older IOS HTTPS stack.
var ciscoArchetypes = map[string]*Profile{
	"cisco-ios":             ciscoProfile("cisco-ios"),
	"cisco-catalyst-2960":   ciscoProfile("cisco-catalyst-2960"),
	"cisco-catalyst-switch": ciscoProfile("cisco-catalyst-switch"),
	"cisco-catalyst-9300":   ciscoProfile("cisco-catalyst-9300"),
	"cisco-ie-2000":         ciscoIEProfile("cisco-ie-2000"),
	"cisco-ie-3400":         ciscoIEProfile("cisco-ie-3400"),
	"cisco-ir1101":          ciscoIEProfile("cisco-ir1101"),
	"cisco-ios-12":          ciscoIOS12Profile(),
	"cisco-2811":            ciscoIOS12Profile(),
}

// ciscoIOS12Profile models a classic Cisco 2811 Integrated Services Router on
// IOS 12.4(15)T — the ubiquitous mid-2000s/2010s branch router still found on
// legacy networks. IOS 12.4 offered SSH v1.99 (v1+v2) and only an SSLv3/TLS1.0
// HTTPS stack, so the posture is deliberately ancient (and internally
// consistent — no modern algorithms).
func ciscoIOS12Profile() *Profile {
	return &Profile{
		Name:        "cisco-2811",
		DisplayName: "Cisco 2811 ISR (IOS 12.4)",
		Family:      "cisco",
		macOUI:      [3]byte{0x00, 0x1a, 0x2b},
		loginPrompt: "\r\nUser Access Verification\r\n\r\nUsername: ",
		cliPrompt:   "Router>",
		// IOS 12.4 negotiates SSH v1.99 (both protocol versions).
		sshBanner:  "SSH-1.99-Cisco-1.25",
		httpServer: "cisco-IOS",
		httpTitle:  "Cisco Systems",
		httpBodyHTML: "<html><head><title>Cisco Systems</title></head><body>" +
			"<h1>Cisco 2811</h1><p>Cisco Systems, Inc. — accessing Cisco IOS HTTP server.</p>" +
			"<p>Authentication required.</p></body></html>",
		snmpSysDescr:    "Cisco IOS Software, 2800 Software (C2800NM-ADVENTERPRISEK9-M), Version 12.4(15)T17, RELEASE SOFTWARE (fc2)",
		snmpSysObjectID: ".1.3.6.1.4.1.9.1.576", // cisco2811
		snmpSysName:     "Router",
		snmpSysContact:  "noc@corp.local",
		snmpSysLocation: "Branch-DMARC",
		icmpTTL:         255,
		snmpIfTable: []Interface{
			{Index: 1, Descr: "FastEthernet0/0", Type: 6, Speed: 100_000_000, OperUp: true},
			{Index: 2, Descr: "FastEthernet0/1", Type: 6, Speed: 100_000_000, OperUp: true},
			{Index: 3, Descr: "Serial0/0/0", Type: 22, Speed: 1_544_000, OperUp: true},
		},
		// IOS 12.4 HTTPS: SSLv3 / TLS 1.0 only, legacy ciphers.
		tls: TLSPosture{MaxVersion: tls.VersionTLS10, WeakCiphers: true},
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh", Note: "SSH management"},
			{Port: 23, Handler: "telnet", Note: "Telnet (vty)"},
			{Port: 80, Handler: "http", Note: "IOS web device manager"},
			{Port: 161, Handler: "snmp", Note: "SNMP"},
		},
		patchLevel: "12.4(15)T17",
		// Smart Install (smi) RCE — the signature exposure of legacy IOS routers.
		cveVulns: []string{"CVE-2018-0171"},
		quirks:   []string{"cisco-ios", "cisco-legacy"},
	}
}

// ciscoIEProfile models Cisco's Industrial Ethernet switches (IE-2000 on
// IOS, IE-3400 on IOS-XE) and the IR1101 industrial router — the ruggedized
// gear on plant floors and at the OT edge. Family "cisco" reuses the IOS
// CLI emulator; the identity (model / sysObjectID / interface naming)
// differs from the enterprise Catalyst line.
func ciscoIEProfile(name string) *Profile {
	var display, sysDescr, sysObjectID, model, prompt string
	// IOS-XE models advertise the web-UI implant chain (CVE-2023-20198); the
	// IOS-15 IE-2000 advertises Smart Install (CVE-2018-0171).
	cves := []string{"CVE-2023-20198"}
	ifs := []Interface{
		{Index: 1, Descr: "GigabitEthernet1/1", Type: 6, Speed: 1_000_000_000, OperUp: true},
		{Index: 2, Descr: "GigabitEthernet1/2", Type: 6, Speed: 1_000_000_000, OperUp: true},
		{Index: 3, Descr: "FastEthernet1/1", Type: 6, Speed: 100_000_000, OperUp: false},
		{Index: 4, Descr: "Vlan1", Type: 53, Speed: 1_000_000_000, OperUp: true},
	}
	switch name {
	case "cisco-ie-3400":
		display = "Cisco Catalyst IE-3400 (IOS-XE 17)"
		sysDescr = "Cisco IOS Software [Cupertino], IE3400 Switch Software (IE3400-UNIVERSALK9-M), Version 17.9.4, RELEASE SOFTWARE (fc1)"
		sysObjectID = ".1.3.6.1.4.1.9.1.2920"
		model = "IE-3400-8T2S"
		prompt = "IE3400>"
	case "cisco-ir1101":
		display = "Cisco IR1101 (industrial router, IOS-XE)"
		sysDescr = "Cisco IOS Software [Cupertino], ir1101 Software (ir1101-UNIVERSALK9-M), Version 17.9.4a, RELEASE SOFTWARE (fc1)"
		sysObjectID = ".1.3.6.1.4.1.9.1.2601"
		model = "IR1101-K9"
		prompt = "IR1101>"
		ifs = []Interface{
			{Index: 1, Descr: "GigabitEthernet0/0/0", Type: 6, Speed: 1_000_000_000, OperUp: true},
			{Index: 2, Descr: "FastEthernet0/0/1", Type: 6, Speed: 100_000_000, OperUp: true},
			{Index: 3, Descr: "Cellular0/1/0", Type: 1, Speed: 100_000_000, OperUp: true},
			{Index: 4, Descr: "Vlan1", Type: 53, Speed: 1_000_000_000, OperUp: true},
		}
	default: // cisco-ie-2000
		display = "Cisco Industrial Ethernet 2000 (IOS 15)"
		sysDescr = "Cisco IOS Software, IE2000 Software (IE2000-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc3)"
		sysObjectID = ".1.3.6.1.4.1.9.1.1409"
		model = "IE-2000-8TC-G-E"
		prompt = "IE2000>"
		cves = []string{"CVE-2018-0171"}
	}
	return &Profile{
		Name:        name,
		DisplayName: display,
		Family:      "cisco",
		macOUI:      [3]byte{0x00, 0x1a, 0x2b},
		loginPrompt: "\r\nUser Access Verification\r\n\r\nUsername: ",
		cliPrompt:   prompt,
		sshBanner:   "SSH-2.0-Cisco-1.25",
		httpServer:  "cisco-IOS",
		httpTitle:   "Cisco Systems",
		httpBodyHTML: "<html><head><title>Cisco Systems</title></head><body>" +
			"<h1>" + model + "</h1><p>Cisco Systems, Inc. — Industrial — accessing Cisco IOS HTTP server.</p>" +
			"<p>Authentication required.</p></body></html>",
		snmpSysDescr:    sysDescr,
		snmpSysObjectID: sysObjectID,
		snmpSysName:     "Switch",
		snmpSysContact:  "ot-noc@corp.local",
		snmpSysLocation: "Plant floor",
		icmpTTL:         255,
		snmpIfTable:     ifs,
		vlans: []VLAN{
			{ID: 1, Name: "default", Ports: []int{1, 2}},
			{ID: 10, Name: "CONTROL", Ports: []int{3}},
		},
		tls:        TLSPosture{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, WeakCiphers: true},
		patchLevel: "IOS 15.2(7)E3",
		cveVulns:   cves,
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh", Note: "SSH management"},
			{Port: 23, Handler: "telnet", Note: "Telnet (legacy)"},
			{Port: 80, Handler: "http", Note: "IOS web device manager"},
			{Port: 443, Handler: "https"},
			{Port: 161, Handler: "snmp"},
			{Port: 4840, Handler: "opcua", Note: "IOx / OPC UA edge app (optional)"},
		},
		quirks: []string{"cisco-ios", "cisco-industrial"},
	}
}

func ciscoProfile(name string) *Profile {
	// Model-specific identity. "cisco-catalyst-switch" and
	// "cisco-catalyst-9300" present a modern IOS-XE 9300; the rest are the
	// classic 2960 / IOS 15 access switch.
	// canonicalName is fixed per model (not per alias) so All()/Names()
	// dedup deterministically when several aliases share a DisplayName.
	display := "Cisco Catalyst 2960 (IOS 15)"
	canonicalName := "cisco-catalyst-2960"
	sysDescr := "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)"
	sysObjectID := ".1.3.6.1.4.1.9.1.716" // catalyst2960
	model := "WS-C2960-24TT-L"
	// IOS-15 access switches advertise Smart Install (CVE-2018-0171); the
	// IOS-XE 9300 additionally advertises the web-UI implant chain (the
	// CVE-2023-20198 → CVE-2023-20273 in-the-wild campaign).
	patch := "15.0(2)SE11"
	cves := []string{"CVE-2018-0171"}
	switch name {
	case "cisco-catalyst-switch", "cisco-catalyst-9300":
		display = "Cisco Catalyst 9300 (IOS-XE 17)"
		canonicalName = "cisco-catalyst-9300"
		sysDescr = "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc1)"
		sysObjectID = ".1.3.6.1.4.1.9.1.2494" // cat9300
		model = "C9300-24T"
		patch = "IOS-XE 17.9.4a"
		cves = []string{"CVE-2023-20198", "CVE-2018-0171"}
	}

	p := &Profile{
		Name:        canonicalName,
		DisplayName: display,
		Family:      "cisco",
		macOUI:      [3]byte{0x00, 0x1a, 0x2b}, // Cisco Systems OUI
		// IOS telnet/SSH login banner; cliPrompt is the user-EXEC prompt.
		loginPrompt: "\r\nUser Access Verification\r\n\r\nUsername: ",
		cliPrompt:   "Switch>",
		// Cisco IOS SSH stack is recognisable: SSH-2.0-Cisco-1.25.
		sshBanner:  "SSH-2.0-Cisco-1.25",
		httpServer: "cisco-IOS",
		httpTitle:  "Cisco Systems",
		httpBodyHTML: "<html><head><title>Cisco Systems</title></head><body>" +
			"<h1>" + model + "</h1><p>Cisco Systems, Inc. — accessing Cisco IOS HTTP server.</p>" +
			"<p>Authentication required.</p></body></html>",
		snmpSysDescr:    sysDescr,
		snmpSysObjectID: sysObjectID,
		snmpSysName:     "Switch",
		snmpSysContact:  "noc@corp.local",
		snmpSysLocation: "IDF-2",
		icmpTTL:         255,
		snmpIfTable: []Interface{
			{Index: 1, Descr: "GigabitEthernet0/1", Type: 6, Speed: 1_000_000_000, OperUp: true},
			{Index: 2, Descr: "GigabitEthernet0/2", Type: 6, Speed: 1_000_000_000, OperUp: true},
			{Index: 3, Descr: "GigabitEthernet0/24", Type: 6, Speed: 1_000_000_000, OperUp: false},
			{Index: 4, Descr: "Vlan1", Type: 53, Speed: 1_000_000_000, OperUp: true},
		},
		vlans: []VLAN{
			{ID: 1, Name: "default", Ports: []int{1, 2}},
			{ID: 10, Name: "DATA", Ports: []int{3}},
			{ID: 20, Name: "VOICE", Ports: []int{4}},
			{ID: 99, Name: "MGMT", Ports: []int{24}},
		},
		lldpNeighbors: []LLDPPeer{
			{ChassisID: "001a.2b3c.4d60", PortID: "Gi0/1", SystemName: "core-rtr-01", PortDescr: "GigabitEthernet0/0/1"},
		},
		// IOS HTTPS uses an old TLS stack (TLS 1.0/1.2, CBC ciphers).
		tls: TLSPosture{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, WeakCiphers: true},
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh", Note: "SSH management"},
			{Port: 23, Handler: "telnet", Note: "Telnet (legacy)"},
			{Port: 80, Handler: "http", Note: "IOS web device manager"},
			{Port: 443, Handler: "https", Note: "IOS HTTPS device manager"},
			{Port: 161, Handler: "snmp", Note: "SNMP"},
		},
		// Cisco Smart Install (CVE-2018-0171) + the Smart Install protocol
		// on 4786 is a famous unauthenticated-RCE / config-grab vector on
		// Catalyst access switches left at default. Advertised only when
		// vuln_emulation is on; never actually exploitable.
		patchLevel: patch,
		cveVulns:   cves,
		quirks:     []string{"cisco-ios"},
	}
	return p
}
