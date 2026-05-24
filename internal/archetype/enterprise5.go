package archetype

import "crypto/tls"

// enterprise5Archetypes adds remote-access / out-of-band-management device
// personas: baseboard management controllers (Supermicro / Lenovo / Cisco UCS /
// HPE OA / Oracle ILOM / Fujitsu iRMC), serial console servers (Lantronix /
// Opengear), a KVM-over-IP appliance (Raritan) and a PDU management card (APC).
// Merged into the registry by init(); each carries its own family (defaulting
// to the embedded-Linux stack) with the BMC/console fingerprint a scanner keys
// on.
var enterprise5Archetypes = map[string]*Profile{
	"supermicro-bmc": {
		Name: "supermicro-bmc", DisplayName: "Supermicro BMC (IPMI/Redfish)", Family: "supermicro",
		macOUI:       [3]byte{0x00, 0x25, 0x90}, // Super Micro
		sshBanner:    "SSH-2.0-OpenSSH_7.4",
		httpServer:   "Supermicro",
		httpTitle:    "ATEN International - BMC",
		httpBodyHTML: "<html><head><title>BMC</title></head><body>Supermicro IPMI</body></html>",
		snmpSysDescr: "Supermicro BMC X11 firmware 1.73",
		snmpSysName:  "supermicro-bmc", snmpSysObjectID: ".1.3.6.1.4.1.10876",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 443, Handler: "redfish", Note: "Redfish/web"}, {Port: 623, Handler: "ipmi", Note: "IPMI"},
			{Port: 22, Handler: "ssh"}, {Port: 80, Handler: "http"},
		},
		quirks: []string{"bmc", "lights-out"},
	},
	"lenovo-xcc": {
		Name: "lenovo-xcc", DisplayName: "Lenovo XClarity Controller (XCC)", Family: "lenovo",
		macOUI:       [3]byte{0xe4, 0x1f, 0x13}, // IBM/Lenovo
		sshBanner:    "SSH-2.0-OpenSSH_8.0",
		httpServer:   "lighttpd",
		httpTitle:    "Lenovo XClarity Controller",
		httpBodyHTML: "<html><head><title>XClarity Controller</title></head><body>Lenovo XCC</body></html>",
		snmpSysDescr: "Lenovo XClarity Controller (XCC) ThinkSystem SR650",
		snmpSysName:  "xcc", snmpSysObjectID: ".1.3.6.1.4.1.19046",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 443, Handler: "redfish", Note: "Redfish/web"}, {Port: 623, Handler: "ipmi", Note: "IPMI"},
			{Port: 22, Handler: "ssh"},
		},
		quirks: []string{"bmc", "lights-out"},
	},
	"cisco-ucs-cimc": {
		Name: "cisco-ucs-cimc", DisplayName: "Cisco UCS CIMC", Family: "ciscoucs",
		macOUI:       [3]byte{0x00, 0x25, 0xb4}, // Cisco UCS
		sshBanner:    "SSH-2.0-OpenSSH_7.4",
		httpServer:   "CIMC",
		httpTitle:    "Cisco Integrated Management Controller",
		httpBodyHTML: "<html><head><title>Cisco IMC</title></head><body>Cisco UCS CIMC</body></html>",
		snmpSysDescr: "Cisco Integrated Management Controller (CIMC) UCS C220 M5",
		snmpSysName:  "cimc", snmpSysObjectID: ".1.3.6.1.4.1.9",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 443, Handler: "redfish", Note: "Redfish/XML-API"}, {Port: 623, Handler: "ipmi", Note: "IPMI"},
			{Port: 22, Handler: "ssh"}, {Port: 80, Handler: "http"},
		},
		quirks: []string{"bmc", "lights-out"},
	},
	"hpe-oa": {
		Name: "hpe-oa", DisplayName: "HPE Onboard Administrator", Family: "hpeoa",
		macOUI:       [3]byte{0x00, 0x17, 0xa4}, // HP
		sshBanner:    "SSH-2.0-OpenSSH_5.9",
		httpServer:   "HP-iLO-Server",
		httpTitle:    "HPE BladeSystem Onboard Administrator",
		httpBodyHTML: "<html><head><title>Onboard Administrator</title></head><body>HPE BladeSystem OA</body></html>",
		snmpSysDescr: "HPE BladeSystem c7000 Onboard Administrator 4.96",
		snmpSysName:  "hpe-oa", snmpSysObjectID: ".1.3.6.1.4.1.232",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 443, Handler: "https", Note: "OA web"}, {Port: 22, Handler: "ssh"},
			{Port: 80, Handler: "http"},
		},
		quirks: []string{"enclosure-mgmt", "lights-out"},
	},
	"oracle-ilom": {
		Name: "oracle-ilom", DisplayName: "Oracle/Sun ILOM", Family: "ilom",
		macOUI:       [3]byte{0x00, 0x14, 0x4f}, // Sun/Oracle
		sshBanner:    "SSH-2.0-OpenSSH_6.6.1",
		httpServer:   "Oracle ILOM",
		httpTitle:    "Oracle Integrated Lights Out Manager",
		httpBodyHTML: "<html><head><title>Oracle ILOM</title></head><body>Integrated Lights Out Manager</body></html>",
		snmpSysDescr: "Oracle Integrated Lights Out Manager (ILOM) 4.0",
		snmpSysName:  "ilom", snmpSysObjectID: ".1.3.6.1.4.1.42",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 443, Handler: "redfish", Note: "Redfish/web"}, {Port: 623, Handler: "ipmi", Note: "IPMI"},
			{Port: 22, Handler: "ssh"},
		},
		quirks: []string{"bmc", "lights-out"},
	},
	"fujitsu-irmc": {
		Name: "fujitsu-irmc", DisplayName: "Fujitsu iRMC", Family: "fujitsu",
		macOUI:       [3]byte{0x00, 0x19, 0x99}, // Fujitsu
		sshBanner:    "SSH-2.0-OpenSSH_7.9",
		httpServer:   "iRMC",
		httpTitle:    "Fujitsu iRMC S5",
		httpBodyHTML: "<html><head><title>iRMC</title></head><body>Fujitsu integrated Remote Management Controller</body></html>",
		snmpSysDescr: "Fujitsu iRMC S5 PRIMERGY RX2540 M5",
		snmpSysName:  "irmc", snmpSysObjectID: ".1.3.6.1.4.1.231",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 443, Handler: "redfish", Note: "Redfish/web"}, {Port: 623, Handler: "ipmi", Note: "IPMI"},
			{Port: 22, Handler: "ssh"},
		},
		quirks: []string{"bmc", "lights-out"},
	},
	"lantronix-slc": {
		Name: "lantronix-slc", DisplayName: "Lantronix SLC console server", Family: "lantronix",
		macOUI:       [3]byte{0x00, 0x20, 0x4a}, // Lantronix
		sshBanner:    "SSH-2.0-OpenSSH_7.4",
		httpServer:   "Lantronix",
		httpTitle:    "Lantronix SLC",
		httpBodyHTML: "<html><head><title>SLC</title></head><body>Lantronix Secure Console Manager</body></html>",
		telnetBanner: "\r\nLantronix SLC\r\nlogin: ",
		loginPrompt:  "login: ",
		snmpSysDescr: "Lantronix SLC8000 console manager firmware 8.5",
		snmpSysName:  "slc", snmpSysObjectID: ".1.3.6.1.4.1.244",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 9999, Handler: "lantronix", Note: "setup"}, {Port: 23, Handler: "telnet"},
			{Port: 22, Handler: "ssh"}, {Port: 80, Handler: "http"},
		},
		quirks: []string{"console-server", "serial"},
	},
	"opengear-cm": {
		Name: "opengear-cm", DisplayName: "Opengear console server", Family: "opengear",
		macOUI:       [3]byte{0x00, 0x13, 0xc6}, // Opengear
		sshBanner:    "SSH-2.0-OpenSSH_8.4",
		httpServer:   "Opengear",
		httpTitle:    "Opengear Console Manager",
		httpBodyHTML: "<html><head><title>Opengear</title></head><body>Opengear Console Manager</body></html>",
		snmpSysDescr: "Opengear CM8100 console server firmware 23.04",
		snmpSysName:  "opengear", snmpSysObjectID: ".1.3.6.1.4.1.25049",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 22, Handler: "ssh"}, {Port: 443, Handler: "https", Note: "web"},
			{Port: 80, Handler: "http"}, {Port: 23, Handler: "telnet"},
		},
		quirks: []string{"console-server", "serial"},
	},
	"raritan-kx": {
		Name: "raritan-kx", DisplayName: "Raritan Dominion KX (KVM)", Family: "raritan",
		macOUI:       [3]byte{0x00, 0x0d, 0x5d}, // Raritan
		httpServer:   "Raritan",
		httpTitle:    "Dominion KX III",
		httpBodyHTML: "<html><head><title>Dominion KX</title></head><body>Raritan Dominion KX III</body></html>",
		snmpSysDescr: "Raritan Dominion KX III KVM-over-IP switch",
		snmpSysName:  "dominion-kx", snmpSysObjectID: ".1.3.6.1.4.1.13742",
		icmpTTL: 64,
		tls:     TLSPosture{MinVersion: tls.VersionTLS12},
		defaultServices: []DefaultService{
			{Port: 443, Handler: "https", Note: "KVM web"}, {Port: 80, Handler: "http"},
			{Port: 22, Handler: "ssh"}, {Port: 5900, Handler: "vnc", Note: "KVM viewer"},
		},
		quirks: []string{"kvm-over-ip", "lights-out"},
	},
	"apc-nmc": {
		Name: "apc-nmc", DisplayName: "APC Network Management Card (rPDU)", Family: "apc",
		macOUI:       [3]byte{0x00, 0xc0, 0xb7}, // APC
		httpServer:   "APC",
		httpTitle:    "APC | Log On",
		httpBodyHTML: "<html><head><title>APC | Log On</title></head><body>Schneider Electric APC</body></html>",
		telnetBanner: "\r\nUser Name : ",
		loginPrompt:  "User Name : ",
		snmpSysDescr: "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.8.2) rPDU",
		snmpSysName:  "apc-nmc", snmpSysObjectID: ".1.3.6.1.4.1.318",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 161, Handler: "snmp", Note: "SNMP"}, {Port: 23, Handler: "telnet"},
			{Port: 80, Handler: "http"}, {Port: 443, Handler: "https"},
		},
		quirks: []string{"pdu", "power-mgmt"},
	},
}
