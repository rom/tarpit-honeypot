package archetype

import "crypto/tls"

// historianArchetypes models process historians / industrial data platforms —
// the "data" tier of an OT/SCADA estate that attackers pivot to for recipe,
// setpoint and production intelligence. Each carries the product's real listen
// ports, a believable landing page that references the product's web/API base
// paths (e.g. /piwebapi, /ProcessBook, /Historian) and a sample point/tag, and
// the hostnames these boxes conventionally use (PI-SRV01, HISTORIAN01, …).
//
// NOTE: the archetype advertises the *identity + ports*; serving live JSON at
// each API path (e.g. /piwebapi/system) is an http-handler concern, not the
// archetype layer — the landing page links the paths so a crawler records them.
var historianArchetypes = map[string]*Profile{
	// ---- OPC / gateway ----
	"kepware-opcua": {
		Name: "kepware-opcua", DisplayName: "Kepware OPC UA server (KEPServerEX)", Family: "windows",
		httpServer:      "Microsoft-IIS/10.0",
		httpTitle:       "KEPServerEX Configuration",
		httpBodyHTML:    `<html><head><title>KEPServerEX</title></head><body><h2>PTC Kepware KEPServerEX V6</h2><p>OPC UA / IoT Gateway — endpoint opc.tcp://KEP-OPCUA01:49320</p></body></html>`,
		cliPrompt:       "C:\\Windows\\system32>",
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 17763 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "KEP-OPCUA01",
		icmpTTL:         128,
		opcVendor:       "Kepware Technologies KEPServerEX",
		cpe:             "cpe:2.3:a:ptc:kepserverex:*:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 4840, Handler: "opcua", Note: "OPC UA"},
			{Port: 49320, Handler: "raw", Note: "KEPServerEX runtime / OPC UA"},
			{Port: 135, Handler: "dcerpc", Note: "DCOM / OPCEnum"},
			{Port: 80, Handler: "http", Note: "config web"},
			{Port: 161, Handler: "snmp"},
		},
		quirks: []string{"opcua", "kepware", "ot-gateway"},
	},

	// ---- OSIsoft / AVEVA PI System ----
	"aveva-pi": {
		Name: "aveva-pi", DisplayName: "AVEVA PI System / OSIsoft PI Data Archive", Family: "osisoft",
		httpServer:      "Microsoft-IIS/10.0",
		httpTitle:       "PI Web API",
		httpBodyHTML:    `<html><head><title>PI Web API</title></head><body><h2>AVEVA PI System (OSIsoft)</h2><p>PI Data Archive · PI Vision · ProcessBook</p><ul><li><a href="/piwebapi/system">/piwebapi/system</a></li><li><a href="/piwebapi/dataservers">/piwebapi/dataservers</a></li><li><a href="/piwebapi/assetservers">/piwebapi/assetservers</a></li><li><a href="/PIVision">/PIVision</a></li><li><a href="/ProcessBook">/ProcessBook</a></li></ul><p>e.g. point <code>Plant1.AreaA.Line3.Temperature</code></p></body></html>`,
		cliPrompt:       "C:\\Windows\\system32>",
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 17763 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "PI-SRV01",
		icmpTTL:         128,
		tls:             TLSPosture{MinVersion: tls.VersionTLS12},
		cpe:             "cpe:2.3:a:osisoft:pi_server:*:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 5450, Handler: "osisoft_pi", Note: "PI Data Archive / PI Network Manager"},
			{Port: 5457, Handler: "raw", Note: "PI buffering / AF"},
			{Port: 443, Handler: "https", Note: "PI Web API (/piwebapi)"},
			{Port: 80, Handler: "http", Note: "PI Vision / ProcessBook"},
			{Port: 161, Handler: "snmp"},
		},
		quirks: []string{"historian", "pi", "osisoft", "aveva"},
	},
	"aveva-pi-af": {
		Name: "aveva-pi-af", DisplayName: "AVEVA PI Asset Framework (PI AF) server", Family: "osisoft",
		httpServer:      "Microsoft-IIS/10.0",
		httpTitle:       "PI Web API",
		httpBodyHTML:    `<html><head><title>PI AF</title></head><body><h2>AVEVA PI Asset Framework</h2><ul><li><a href="/piwebapi/assetservers">/piwebapi/assetservers</a></li><li><a href="/piwebapi/system">/piwebapi/system</a></li></ul></body></html>`,
		cliPrompt:       "C:\\Windows\\system32>",
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 17763 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "PI-AF01",
		icmpTTL:         128,
		tls:             TLSPosture{MinVersion: tls.VersionTLS12},
		cpe:             "cpe:2.3:a:osisoft:pi_asset_framework:*:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 5457, Handler: "raw", Note: "PI AF"},
			{Port: 1433, Handler: "mssql", Note: "PIFD asset database (SQL Server)"},
			{Port: 443, Handler: "https", Note: "PI Web API (/piwebapi)"},
			{Port: 161, Handler: "snmp"},
		},
		quirks: []string{"historian", "pi", "osisoft", "aveva"},
	},

	// ---- AVEVA / Wonderware Historian ----
	"wonderware-historian": {
		Name: "wonderware-historian", DisplayName: "AVEVA Historian / Wonderware Historian", Family: "aveva",
		httpServer:      "Microsoft-IIS/10.0",
		httpTitle:       "AVEVA Insight",
		httpBodyHTML:    `<html><head><title>AVEVA Historian</title></head><body><h2>AVEVA Historian (Wonderware)</h2><ul><li><a href="/Historian">/Historian</a></li><li><a href="/Wonderware">/Wonderware</a></li><li><a href="/AVEVA/Insight">/AVEVA/Insight</a></li></ul><p>e.g. tag <code>Boiler01.SteamPressure</code></p></body></html>`,
		cliPrompt:       "C:\\Windows\\system32>",
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 17763 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "HISTORIAN01",
		icmpTTL:         128,
		tls:             TLSPosture{MinVersion: tls.VersionTLS12},
		cpe:             "cpe:2.3:a:aveva:historian:*:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "AVEVA Insight / Historian client"},
			{Port: 443, Handler: "https", Note: "AVEVA Insight (TLS)"},
			{Port: 1433, Handler: "mssql", Note: "Runtime historian DB (SQL Server)"},
			{Port: 32568, Handler: "raw", Note: "Historian retrieval"},
			{Port: 161, Handler: "snmp"},
		},
		quirks: []string{"historian", "wonderware", "aveva"},
	},

	// ---- AspenTech InfoPlus.21 ----
	"aspentech-ip21": {
		Name: "aspentech-ip21", DisplayName: "AspenTech InfoPlus.21 (IP.21) historian", Family: "aspentech",
		httpServer:      "Microsoft-IIS/10.0",
		httpTitle:       "Aspen InfoPlus.21",
		httpBodyHTML:    `<html><head><title>Aspen InfoPlus.21</title></head><body><h2>AspenTech InfoPlus.21 (IP.21)</h2><p>Aspen Process Explorer · A1PE web</p><p>e.g. tag <code>Compressor02.Vibration</code></p></body></html>`,
		cliPrompt:       "C:\\Windows\\system32>",
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 17763 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "IP21-SERVER",
		icmpTTL:         128,
		tls:             TLSPosture{MinVersion: tls.VersionTLS12},
		cpe:             "cpe:2.3:a:aspentech:infoplus.21:*:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "Aspen Process Explorer web"},
			{Port: 443, Handler: "https", Note: "A1PE (TLS)"},
			{Port: 10014, Handler: "aspen_ip21", Note: "InfoPlus.21 SQLplus / client"},
			{Port: 161, Handler: "snmp"},
		},
		quirks: []string{"historian", "aspentech", "ip21"},
	},

	// ---- GE / Emerson historians ----
	"ge-proficy-historian": {
		Name: "ge-proficy-historian", DisplayName: "GE Proficy Historian", Family: "ge",
		httpServer:      "Microsoft-IIS/10.0",
		httpTitle:       "Proficy Historian",
		httpBodyHTML:    `<html><head><title>Proficy Historian</title></head><body><h2>GE Proficy Historian</h2><ul><li><a href="/ProficyHistorian">/ProficyHistorian</a></li><li><a href="/ProficyWebspace">/ProficyWebspace</a></li></ul><p>e.g. tag <code>Turbine01.Speed</code></p></body></html>`,
		cliPrompt:       "C:\\Windows\\system32>",
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 17763 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "PROFICY-HIST01",
		icmpTTL:         128,
		tls:             TLSPosture{MinVersion: tls.VersionTLS12},
		cpe:             "cpe:2.3:a:ge:proficy_historian:*:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "Proficy Webspace / Historian web admin"},
			{Port: 443, Handler: "https", Note: "Proficy (TLS)"},
			{Port: 14000, Handler: "proficy_historian", Note: "Proficy Historian data archiver"},
			{Port: 161, Handler: "snmp"},
		},
		quirks: []string{"historian", "ge", "proficy"},
	},
	"emerson-historian": {
		Name: "emerson-historian", DisplayName: "Emerson Ovation / DeltaV Historian (PHD)", Family: "emerson",
		httpServer:      "Microsoft-IIS/10.0",
		httpTitle:       "Process History",
		httpBodyHTML:    `<html><head><title>Process History</title></head><body><h2>Emerson Ovation / DeltaV Historian</h2><p>Process History Database</p><p>e.g. tag <code>Substation.TR1.OilTemp</code></p></body></html>`,
		cliPrompt:       "C:\\Windows\\system32>",
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 17763 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "PHD-HIST01",
		icmpTTL:         128,
		tls:             TLSPosture{MinVersion: tls.VersionTLS12},
		cpe:             "cpe:2.3:a:emerson:ovation:*:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "Historian web"},
			{Port: 443, Handler: "https", Note: "Historian (TLS)"},
			{Port: 1433, Handler: "mssql", Note: "Historian DB (SQL Server)"},
			{Port: 161, Handler: "snmp"},
		},
		quirks: []string{"historian", "emerson", "ovation", "deltav"},
	},

	// ---- Canary Historian ----
	"canary-historian": {
		Name: "canary-historian", DisplayName: "Canary Historian", Family: "canary",
		httpServer:      "Microsoft-IIS/10.0",
		httpTitle:       "Canary",
		httpBodyHTML:    `<html><head><title>Canary</title></head><body><h2>Canary Historian</h2><ul><li><a href="/CanaryAdmin">/CanaryAdmin</a></li><li><a href="/CanaryData">/CanaryData</a></li></ul><p>e.g. tag <code>TankFarm.TK-101.Level</code></p></body></html>`,
		cliPrompt:       "C:\\Windows\\system32>",
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 20348 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "CANARY-HIST01",
		icmpTTL:         128,
		tls:             TLSPosture{MinVersion: tls.VersionTLS12},
		cpe:             "cpe:2.3:a:canarylabs:canary:*:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "Canary Web / Axiom"},
			{Port: 443, Handler: "https", Note: "Canary Web API (/CanaryData)"},
			{Port: 9990, Handler: "canary_historian", Note: "Canary Sender service"},
			{Port: 161, Handler: "snmp"},
		},
		quirks: []string{"historian", "canary"},
	},

	// ---- dataPARC ----
	"dataparc": {
		Name: "dataparc", DisplayName: "dataPARC Historian / PARCview", Family: "dataparc",
		httpServer:      "Microsoft-IIS/10.0",
		httpTitle:       "PARCview",
		httpBodyHTML:    `<html><head><title>dataPARC</title></head><body><h2>dataPARC Historian</h2><ul><li><a href="/dataPARC">/dataPARC</a></li><li><a href="/PARCview">/PARCview</a></li></ul><p>e.g. tag <code>WWTP.Pump03.Runtime</code></p></body></html>`,
		cliPrompt:       "C:\\Windows\\system32>",
		snmpSysDescr:    "Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 17763 Multiprocessor Free)",
		snmpSysObjectID: ".1.3.6.1.4.1.311.1.1.3.1.2",
		snmpSysName:     "PARCVIEW01",
		icmpTTL:         128,
		tls:             TLSPosture{MinVersion: tls.VersionTLS12},
		cpe:             "cpe:2.3:a:capstonetechnology:dataparc:*:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "PARCview web"},
			{Port: 443, Handler: "https", Note: "dataPARC (TLS)"},
			{Port: 1433, Handler: "mssql", Note: "PARCserver DB (SQL Server)"},
			{Port: 161, Handler: "snmp"},
		},
		quirks: []string{"historian", "dataparc", "parcview"},
	},

	// ---- Inductive Automation Ignition ----
	"ignition-gateway": {
		Name: "ignition-gateway", DisplayName: "Inductive Automation Ignition Gateway", Family: "ignition",
		httpServer:      "",
		httpTitle:       "Ignition Gateway",
		httpBodyHTML:    `<html><head><title>Ignition Gateway</title></head><body><h2>Inductive Automation Ignition</h2><ul><li><a href="/Ignition">/Ignition</a></li><li><a href="/vision">/vision</a></li><li><a href="/web/home">/web/home</a></li></ul></body></html>`,
		sshBanner:       "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		cliPrompt:       "ignition@gw:~$ ",
		snmpSysDescr:    "Linux ignition 5.15.0-122-generic #132-Ubuntu x86_64",
		snmpSysObjectID: ".1.3.6.1.4.1.8072.3.2.10",
		snmpSysName:     "IGNITION-GW01",
		icmpTTL:         64,
		tls:             TLSPosture{MinVersion: tls.VersionTLS12},
		cpe:             "cpe:2.3:a:inductiveautomation:ignition:*:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 8088, Handler: "http", Note: "Ignition Gateway web"},
			{Port: 8043, Handler: "https", Note: "Ignition Gateway (TLS)"},
			{Port: 62541, Handler: "opcua", Note: "Ignition OPC UA"},
			{Port: 22, Handler: "ssh"},
		},
		quirks: []string{"scada", "ignition", "opcua"},
	},

	// ---- Time-series databases ----
	"influxdb": {
		Name: "influxdb", DisplayName: "InfluxDB (time-series database)", Family: "influxdb",
		httpServer:      "InfluxDB",
		httpTitle:       "InfluxDB",
		httpBodyHTML:    `<html><head><title>InfluxDB</title></head><body>InfluxDB OSS — /api/v2 · /query · /health</body></html>`,
		sshBanner:       "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		cliPrompt:       "influx@tsdb:~$ ",
		snmpSysDescr:    "Linux influxdb 5.15.0-122-generic #132-Ubuntu x86_64",
		snmpSysObjectID: ".1.3.6.1.4.1.8072.3.2.10",
		snmpSysName:     "INFLUXDB01",
		icmpTTL:         64,
		tls:             TLSPosture{MinVersion: tls.VersionTLS12},
		cpe:             "cpe:2.3:a:influxdata:influxdb:*:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 8086, Handler: "http", Note: "InfluxDB HTTP API"},
			{Port: 8088, Handler: "raw", Note: "InfluxDB RPC / backup"},
			{Port: 22, Handler: "ssh"},
		},
		quirks: []string{"tsdb", "influxdb"},
	},
	"timescaledb": {
		Name: "timescaledb", DisplayName: "TimescaleDB (PostgreSQL time-series)", Family: "timescaledb",
		sshBanner:       "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		cliPrompt:       "postgres@tsdb:~$ ",
		snmpSysDescr:    "Linux timescaledb 5.15.0-122-generic #132-Ubuntu x86_64",
		snmpSysObjectID: ".1.3.6.1.4.1.8072.3.2.10",
		snmpSysName:     "TIMESCALE01",
		icmpTTL:         64,
		mysqlVersion:    "",
		cpe:             "cpe:2.3:a:timescale:timescaledb:*:*:*:*:*:*:*:*",
		defaultServices: []DefaultService{
			{Port: 5432, Handler: "postgres", Note: "PostgreSQL / TimescaleDB"},
			{Port: 22, Handler: "ssh"},
		},
		quirks: []string{"tsdb", "timescaledb", "postgres"},
	},
}
