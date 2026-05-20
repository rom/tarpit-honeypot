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
}

func ciscoProfile(name string) *Profile {
	// Model-specific identity. "cisco-catalyst-switch" and
	// "cisco-catalyst-9300" present a modern IOS-XE 9300; the rest are the
	// classic 2960 / IOS 15 access switch.
	display := "Cisco Catalyst 2960 (IOS 15)"
	sysDescr := "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)"
	sysObjectID := ".1.3.6.1.4.1.9.1.716" // catalyst2960
	model := "WS-C2960-24TT-L"
	switch name {
	case "cisco-catalyst-switch", "cisco-catalyst-9300":
		display = "Cisco Catalyst 9300 (IOS-XE 17)"
		sysDescr = "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc1)"
		sysObjectID = ".1.3.6.1.4.1.9.1.2494" // cat9300
		model = "C9300-24T"
	}

	p := &Profile{
		Name:        name,
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
		patchLevel: "15.0(2)SE11",
		cveVulns:   []string{"CVE-2018-0171"},
		quirks:     []string{"cisco-ios"},
	}
	return p
}
