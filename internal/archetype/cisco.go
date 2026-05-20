package archetype

// ciscoArchetypes models a Cisco IOS switch — the canonical enterprise
// network device. Family "cisco" routes the interactive shell to the
// Cisco IOS command emulator (enable mode, show version / running-config
// / vlan / cdp neighbors). icmpTTL 255 is the router/switch default.
var ciscoArchetypes = map[string]*Profile{
	"cisco-ios":           ciscoProfile("cisco-ios"),
	"cisco-catalyst-2960": ciscoProfile("cisco-catalyst-2960"),
}

func ciscoProfile(name string) *Profile {
	return &Profile{
		Name:        name,
		DisplayName: "Cisco Catalyst 2960 (IOS 15)",
		Family:      "cisco",
		macOUI:      [3]byte{0x00, 0x1a, 0x2b}, // Cisco OUI
		// IOS telnet/SSH login banner; cliPrompt is the user-EXEC prompt.
		loginPrompt:     "\r\nUser Access Verification\r\n\r\nUsername: ",
		cliPrompt:       "Switch>",
		snmpSysDescr:    "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)",
		snmpSysObjectID: ".1.3.6.1.4.1.9.1.716",
		snmpSysName:     "Switch",
		snmpSysContact:  "noc@corp.local",
		snmpSysLocation: "IDF-2",
		icmpTTL:         255,
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh", Note: "SSH management"},
			{Port: 23, Handler: "telnet", Note: "Telnet (legacy)"},
			{Port: 80, Handler: "http", Note: "Web device manager"},
			{Port: 161, Handler: "snmp", Note: "SNMP"},
		},
		quirks: []string{"cisco-ios"},
	}
}
