package archetype

import "crypto/tls"

// enterprise6Archetypes adds VoIP / telephony device personas: IP-PBXs
// (FreePBX, Cisco CUCM, Avaya, Mitel, 3CX, FreeSWITCH), session border
// controllers / gateways (Ribbon, AudioCodes) and IP phones (Yealink,
// Polycom). Merged into the registry by init(); each carries its own family
// (defaulting to the embedded-Linux stack) with the telephony fingerprint a
// scanner keys on. (Asterisk and Grandstream PBX personas already ship.)
var enterprise6Archetypes = map[string]*Profile{
	"freepbx": {
		Name: "freepbx", DisplayName: "FreePBX (Sangoma)", Family: "freepbx",
		sshBanner:    "SSH-2.0-OpenSSH_8.0",
		httpServer:   "Apache/2.4.37 (Sangoma)",
		httpTitle:    "FreePBX Administration",
		httpBodyHTML: "<html><head><title>FreePBX Administration</title></head><body>Sangoma FreePBX</body></html>",
		snmpSysDescr: "FreePBX 16 (Asterisk 18) on Linux",
		snmpSysName:  "freepbx", snmpSysObjectID: ".1.3.6.1.4.1.22736",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 5060, Handler: "sip_tcp", Note: "SIP"}, {Port: 5038, Handler: "asterisk_ami", Note: "AMI"},
			{Port: 4569, Handler: "iax2", Note: "IAX2"}, {Port: 80, Handler: "http"}, {Port: 443, Handler: "https"},
		},
		quirks: []string{"pbx", "asterisk"},
	},
	"cisco-cucm": {
		Name: "cisco-cucm", DisplayName: "Cisco Unified CM (CUCM)", Family: "ciscocucm",
		macOUI:       [3]byte{0x00, 0x1b, 0x54}, // Cisco
		httpServer:   "Cisco CUCM",
		httpTitle:    "Cisco Unified Communications Manager",
		httpBodyHTML: "<html><head><title>Cisco Unified CM</title></head><body>Cisco Unified Communications Manager</body></html>",
		snmpSysDescr: "Cisco Unified Communications Manager 14.0",
		snmpSysName:  "cucm", snmpSysObjectID: ".1.3.6.1.4.1.9",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 2000, Handler: "sccp", Note: "SCCP/Skinny"}, {Port: 5060, Handler: "sip_tcp", Note: "SIP"},
			{Port: 443, Handler: "https"}, {Port: 8443, Handler: "https", Note: "admin"},
		},
		quirks: []string{"pbx", "callmanager"},
	},
	"avaya-aura": {
		Name: "avaya-aura", DisplayName: "Avaya Aura Communication Manager", Family: "avaya",
		macOUI:       [3]byte{0x00, 0x04, 0x0d}, // Avaya
		sshBanner:    "SSH-2.0-OpenSSH_7.4",
		httpServer:   "Avaya",
		httpTitle:    "Avaya Aura System Manager",
		httpBodyHTML: "<html><head><title>Avaya Aura</title></head><body>Avaya Aura Communication Manager</body></html>",
		snmpSysDescr: "Avaya Aura Communication Manager 10.1",
		snmpSysName:  "avaya-cm", snmpSysObjectID: ".1.3.6.1.4.1.6889",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 5060, Handler: "sip_tcp", Note: "SIP"}, {Port: 1720, Handler: "h323", Note: "H.323"},
			{Port: 443, Handler: "https"}, {Port: 22, Handler: "ssh"},
		},
		quirks: []string{"pbx"},
	},
	"mitel-mivoice": {
		Name: "mitel-mivoice", DisplayName: "Mitel MiVoice Business", Family: "mitel",
		macOUI:       [3]byte{0x08, 0x00, 0x0f}, // Mitel
		httpServer:   "Mitel",
		httpTitle:    "Mitel MiVoice Business",
		httpBodyHTML: "<html><head><title>Mitel</title></head><body>Mitel MiVoice Business</body></html>",
		snmpSysDescr: "Mitel MiVoice Business 9.x",
		snmpSysName:  "mivoice", snmpSysObjectID: ".1.3.6.1.4.1.1027",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 5060, Handler: "sip_tcp", Note: "SIP"}, {Port: 443, Handler: "https"},
			{Port: 80, Handler: "http"},
		},
		quirks: []string{"pbx"},
	},
	"3cx": {
		Name: "3cx", DisplayName: "3CX Phone System", Family: "3cx",
		httpServer:   "3CX",
		httpTitle:    "3CX Management Console",
		httpBodyHTML: "<html><head><title>3CX</title></head><body>3CX Phone System Management Console</body></html>",
		snmpSysDescr: "3CX Phone System 20 on Debian Linux",
		snmpSysName:  "3cx", snmpSysObjectID: ".1.3.6.1.4.1.8072.3.2.10",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 5060, Handler: "sip_tcp", Note: "SIP"}, {Port: 5001, Handler: "https", Note: "mgmt"},
			{Port: 443, Handler: "https"}, {Port: 80, Handler: "http"},
		},
		quirks: []string{"pbx"},
	},
	"freeswitch": {
		Name: "freeswitch", DisplayName: "FreeSWITCH", Family: "freeswitch",
		sshBanner:    "SSH-2.0-OpenSSH_8.4",
		httpServer:   "FreeSWITCH",
		snmpSysDescr: "FreeSWITCH 1.10 on Linux",
		snmpSysName:  "freeswitch", snmpSysObjectID: ".1.3.6.1.4.1.8072.3.2.10",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 5060, Handler: "sip_tcp", Note: "SIP internal"}, {Port: 5080, Handler: "sip_tcp", Note: "SIP external"},
			{Port: 8021, Handler: "raw", Note: "Event Socket"}, {Port: 80, Handler: "http"},
		},
		quirks: []string{"pbx", "softswitch"},
	},
	"ribbon-sbc": {
		Name: "ribbon-sbc", DisplayName: "Ribbon SBC (session border controller)", Family: "ribbon",
		sshBanner:    "SSH-2.0-OpenSSH_7.4",
		httpServer:   "Ribbon",
		httpTitle:    "Ribbon SBC",
		httpBodyHTML: "<html><head><title>Ribbon SBC</title></head><body>Ribbon Session Border Controller</body></html>",
		snmpSysDescr: "Ribbon SBC SWe (Sonus) 11.x",
		snmpSysName:  "ribbon-sbc", snmpSysObjectID: ".1.3.6.1.4.1.2879",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 5060, Handler: "sip_tcp", Note: "SIP"}, {Port: 5061, Handler: "sip_tcp", Note: "SIP-TLS"},
			{Port: 443, Handler: "https"}, {Port: 22, Handler: "ssh"},
		},
		quirks: []string{"sbc"},
	},
	"audiocodes": {
		Name: "audiocodes", DisplayName: "AudioCodes Mediant gateway", Family: "audiocodes",
		macOUI:       [3]byte{0x00, 0x90, 0x8f}, // AudioCodes
		httpServer:   "AudioCodes",
		httpTitle:    "AudioCodes Mediant",
		httpBodyHTML: "<html><head><title>AudioCodes</title></head><body>AudioCodes Mediant Gateway</body></html>",
		snmpSysDescr: "AudioCodes Mediant 500 SBC/Gateway",
		snmpSysName:  "mediant", snmpSysObjectID: ".1.3.6.1.4.1.5003",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 5060, Handler: "sip_tcp", Note: "SIP"}, {Port: 80, Handler: "http"},
			{Port: 443, Handler: "https"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"gateway", "sbc"},
	},
	"yealink-phone": {
		Name: "yealink-phone", DisplayName: "Yealink IP phone", Family: "yealink",
		macOUI:       [3]byte{0x80, 0x5e, 0xc0}, // Yealink
		httpServer:   "Yealink",
		httpTitle:    "Yealink SIP-T54W",
		httpBodyHTML: "<html><head><title>Yealink</title></head><body>Yealink IP Phone</body></html>",
		snmpSysDescr: "Yealink SIP-T54W IP phone",
		snmpSysName:  "yealink", snmpSysObjectID: ".1.3.6.1.4.1.37459",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 5060, Handler: "sip_tcp", Note: "SIP"}, {Port: 80, Handler: "http"},
			{Port: 443, Handler: "https"},
		},
		quirks: []string{"ip-phone"},
	},
	"polycom-vvx": {
		Name: "polycom-vvx", DisplayName: "Poly/Polycom VVX phone", Family: "polycom",
		macOUI:       [3]byte{0x00, 0x04, 0xf2}, // Polycom
		httpServer:   "Polycom",
		httpTitle:    "Polycom VVX",
		httpBodyHTML: "<html><head><title>Polycom</title></head><body>Poly VVX Business IP Phone</body></html>",
		snmpSysDescr: "Polycom VVX 450 Business IP phone",
		snmpSysName:  "vvx", snmpSysObjectID: ".1.3.6.1.4.1.13885",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 5060, Handler: "sip_tcp", Note: "SIP"}, {Port: 80, Handler: "http"},
			{Port: 443, Handler: "https"},
		},
		quirks: []string{"ip-phone"},
	},
}
