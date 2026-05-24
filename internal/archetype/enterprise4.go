package archetype

// enterprise4Archetypes adds OT/ICS device personas: safety controllers (SIS),
// DCS controllers, more PLC vendors, a protection relay, a solar inverter and
// an automation controller. Merged into the registry by init(). Each carries
// its own OT family (wired into the tcpstack OT fingerprint) with the SNMP /
// MAC / banner surface an ICS scanner keys on.
var enterprise4Archetypes = map[string]*Profile{
	"triconex-tricon": {
		Name: "triconex-tricon", DisplayName: "Schneider Triconex Tricon (SIS)", Family: "triconex",
		macOUI:       [3]byte{0x00, 0x80, 0xf4}, // Schneider/Telemecanique
		httpServer:   "Triconex",
		snmpSysDescr: "Triconex Tricon v10 Safety Instrumented System (TCM)",
		snmpSysName:  "tricon", snmpSysObjectID: ".1.3.6.1.4.1.5491",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 502, Handler: "modbus"}, {Port: 1502, Handler: "raw", Note: "TSAA"},
			{Port: 80, Handler: "http"},
		},
		quirks: []string{"safety-controller", "sis"},
	},
	"hima-himax": {
		Name: "hima-himax", DisplayName: "HIMA HIMax (safety PLC)", Family: "hima",
		httpServer:   "HIMA",
		snmpSysDescr: "HIMA HIMax safety controller X-CPU 01",
		snmpSysName:  "himax", snmpSysObjectID: ".1.3.6.1.4.1.21450",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 502, Handler: "modbus"}, {Port: 80, Handler: "http"},
		},
		quirks: []string{"safety-controller", "sis"},
	},
	"ge-pacsystems": {
		Name: "ge-pacsystems", DisplayName: "GE PACSystems RX3i (PLC)", Family: "ge",
		macOUI:       [3]byte{0x00, 0x09, 0x91}, // GE Fanuc
		httpServer:   "GE Intelligent Platforms",
		snmpSysDescr: "GE PACSystems RX3i CPE330 controller",
		snmpSysName:  "rx3i", snmpSysObjectID: ".1.3.6.1.4.1.24893",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 18245, Handler: "ge_srtp", Note: "SRTP"}, {Port: 502, Handler: "modbus"},
			{Port: 80, Handler: "http"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"plc"},
	},
	"yokogawa-centum": {
		Name: "yokogawa-centum", DisplayName: "Yokogawa CENTUM VP (DCS)", Family: "yokogawa",
		httpServer:   "Yokogawa",
		snmpSysDescr: "Yokogawa CENTUM VP Field Control Station",
		snmpSysName:  "centumvp", snmpSysObjectID: ".1.3.6.1.4.1.4752",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http"}, {Port: 502, Handler: "modbus"},
			{Port: 20010, Handler: "raw", Note: "Vnet/IP"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"dcs"},
	},
	"emerson-deltav": {
		Name: "emerson-deltav", DisplayName: "Emerson DeltaV (DCS controller)", Family: "emerson",
		httpServer:   "Emerson",
		snmpSysDescr: "Emerson DeltaV MD Plus controller",
		snmpSysName:  "deltav", snmpSysObjectID: ".1.3.6.1.4.1.1773",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http"}, {Port: 44818, Handler: "ethernetip"},
			{Port: 18507, Handler: "raw", Note: "DeltaV"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"dcs"},
	},
	"rockwell-micrologix": {
		Name: "rockwell-micrologix", DisplayName: "Rockwell MicroLogix 1400 (PLC)", Family: "rockwell",
		macOUI:       [3]byte{0x00, 0x00, 0xbc}, // Allen-Bradley / Rockwell
		httpServer:   "A-B WWW/1.0",
		snmpSysDescr: "Allen-Bradley MicroLogix 1400 1766-L32BWA",
		snmpSysName:  "micrologix", snmpSysObjectID: ".1.3.6.1.4.1.868",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 44818, Handler: "ethernetip"}, {Port: 80, Handler: "http"},
			{Port: 161, Handler: "snmp"}, {Port: 2222, Handler: "raw", Note: "EtherNet/IP I/O"},
		},
		quirks: []string{"plc"},
	},
	"br-x20": {
		Name: "br-x20", DisplayName: "B&R X20 (PLC)", Family: "br",
		macOUI:       [3]byte{0x00, 0x60, 0x65}, // B&R Industrie-Elektronik
		httpServer:   "B&R",
		snmpSysDescr: "B&R X20 CP1586 controller",
		snmpSysName:  "x20", snmpSysObjectID: ".1.3.6.1.4.1.20533",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 11159, Handler: "raw", Note: "ANSL"}, {Port: 80, Handler: "http"},
			{Port: 502, Handler: "modbus"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"plc"},
	},
	"sel-751": {
		Name: "sel-751", DisplayName: "SEL-751 (protection relay)", Family: "sel",
		macOUI:       [3]byte{0x00, 0x30, 0xa7}, // Schweitzer Engineering Labs
		httpServer:   "SEL",
		telnetBanner: "\r\nSEL-751\r\nPassword: ",
		loginPrompt:  "Password: ",
		snmpSysDescr: "SEL-751 Feeder Protection Relay",
		snmpSysName:  "sel751", snmpSysObjectID: ".1.3.6.1.4.1.30066",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 23, Handler: "telnet"}, {Port: 102, Handler: "mms", Note: "IEC 61850"},
			{Port: 20000, Handler: "dnp3"}, {Port: 80, Handler: "http"},
		},
		quirks: []string{"protection-relay", "power"},
	},
	"sma-inverter": {
		Name: "sma-inverter", DisplayName: "SMA Sunny (solar inverter)", Family: "sma",
		macOUI:       [3]byte{0x00, 0x40, 0xad}, // SMA Technologie
		httpServer:   "SMA",
		httpTitle:    "Sunny WebBox",
		httpBodyHTML: "<html><head><title>SMA Sunny WebBox</title></head><body>SMA Solar Technology</body></html>",
		snmpSysDescr: "SMA Sunny Tripower inverter",
		snmpSysName:  "sma", snmpSysObjectID: ".1.3.6.1.4.1.45356",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http"}, {Port: 502, Handler: "modbus", Note: "SMA Modbus"},
			{Port: 9522, Handler: "raw", Note: "Speedwire"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"renewable", "inverter"},
	},
	"bachmann-m1": {
		Name: "bachmann-m1", DisplayName: "Bachmann M1 (controller)", Family: "bachmann",
		httpServer:   "Bachmann",
		sshBanner:    "SSH-2.0-OpenSSH_7.4",
		snmpSysDescr: "Bachmann M1 MX213 controller",
		snmpSysName:  "bachmann-m1", snmpSysObjectID: ".1.3.6.1.4.1.36686",
		icmpTTL: 64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http"}, {Port: 502, Handler: "modbus"},
			{Port: 22, Handler: "ssh"}, {Port: 161, Handler: "snmp"},
		},
		quirks: []string{"controller", "wind"},
	},
}
