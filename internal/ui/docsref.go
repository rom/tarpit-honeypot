package ui

import (
	"sort"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/mitre"
)

// Reference catalogs rendered on the docs page, generated from the same data
// the sensor actually uses (handler whitelists, the CVE catalog, the ATT&CK
// maps) so the documentation can never drift from the implementation.

type jaDoc struct{ Name, Desc string }

type handlerDoc struct{ Name, Transport, Desc string }

type techDoc struct{ ID, Desc string }

type cveDoc struct {
	ID, Name, Service, Desc, CPE string
	CVSS, EPSS                   float64
	CWE                          []string
}

// jaCatalog describes every JA*/HASSH network fingerprint the sensor computes.
// There is no in-code catalog (each is an algorithm in internal/fingerprint),
// so the descriptions live here.
func jaCatalog() []jaDoc {
	return []jaDoc{
		{"JA3", "MD5 over the TLS ClientHello (version, cipher list, extensions, curves, EC-point formats) — fingerprints the client's TLS library/stack."},
		{"JA3S", "JA3 computed over the ServerHello — fingerprints what our emulated TLS server negotiated (so two deployments don't cluster)."},
		{"JA4", "Next-generation TLS ClientHello fingerprint; sorts ciphers/extensions so it resists the shuffling that evades JA3."},
		{"JA4S", "JA4 server fingerprint over the ServerHello."},
		{"JA4H", "HTTP client fingerprint from the request method, header order/casing, and cookie presence."},
		{"JA4T", "TCP-stack fingerprint from the SYN (window size, options, MSS) — OS / stack identification at L4."},
		{"JA4SSH", "SSH client fingerprint from the KEXINIT algorithm lists (kex / host-key / cipher / MAC)."},
		{"JA4X", "X.509 certificate fingerprint from the issuer / subject / extension shape a client presents."},
		{"HASSH", "MD5 of the SSH client KEXINIT algorithm lists — fingerprints the SSH client implementation."},
		{"HASSHServer", "The HASSH equivalent for the server's KEXINIT — our emulated SSH server's fingerprint."},
	}
}

// handlerDescriptions are concise notes for the most common handlers; any
// handler not listed falls back to a generic line in handlerDocs.
var handlerDescriptions = map[string]string{
	"ssh":             "OpenSSH-flavored SSH server (banner, KEX, HASSH, captured auth attempts).",
	"ssh_interactive": "Interactive fake shell over SSH — records the attacker's command session.",
	"http":            "HTTP server; detects (never executes) the web-attack families and CVE signatures.",
	"https":           "HTTP over a real TLS handshake (self-signed, archetype-shaped; JA3/JA4/JA3S).",
	"telnet":          "Telnet login + interactive prompt; captures credentials and commands.",
	"ftp":             "FTP control channel.", "ftp_files": "FTP file server — accepts logins, serves bait files, captures creds.",
	"smtp_recv": "SMTP receiver — captures MAIL FROM/RCPT, AUTH creds, relay/open-relay probes.",
	"pop3":      "POP3 mailbox server — harvests USER/PASS, APOP and SASL logins (vuln + CVE emulation).",
	"imap":      "IMAP4rev1 server — harvests LOGIN / SASL AUTHENTICATE creds (vuln + CVE emulation).",
	"pop3s":     "Implicit-TLS POP3 (995) — the pop3 handler after a TLS handshake.",
	"imaps":     "Implicit-TLS IMAP (993) — the imap handler after a TLS handshake.",
	"smtps":     "Implicit-TLS SMTP submission (465).", "ftps": "Implicit-TLS FTP (990).",
	"dns":        "DNS resolver (UDP + TCP) — topology-coherent answers + tunneling/exfil detection.",
	"snmp":       "SNMP agent — MIB-2 sysDescr/ifTable, captures community strings.",
	"tristation": "Triconex TriStation / TSAA (UDP 1502) — safety-controller protocol abused by TRITON/TRISIS; flags probes + program-download attempts.",
	"roc_plus":   "Emerson ROC Plus (TCP 4000) — gas/oil flow-computer RTU; captures the opcode + flags login.",
	"crimson":    "Red Lion Crimson (TCP 789) — HMI/data-station management; captures the framed request.",
	"ge_egd":     "GE Ethernet Global Data (UDP 18246) — PACSystems/90-30/90-70 PLC producer/consumer data; capture-only, decodes the PDU header.",
	"bsap":       "Bristol/Emerson BSAP-IP (UDP 1234) — ControlWave/Bristol RTU SCADA polling; captures the request, bounded rate-limited ack.",
	"lontalk":    "Echelon LonTalk / LonWorks-IP CEA-852 (UDP 1628) — building/industrial control networking; capture-only, decodes the packet header.",
	// General UDP infrastructure (capture-only — several are amplification vectors).
	"wsdiscovery":   "WS-Discovery (UDP 3702) — SOAP-over-UDP device discovery (ONVIF cameras/printers); capture-only.",
	"memcached_udp": "memcached over UDP (UDP 11211) — record-breaking amplification vector; capture-only, decodes the request.",
	"natpmp":        "NAT-PMP / PCP (UDP 5351) — gateway port-mapping; amplification vector, capture-only.",
	"ubiquiti":      "Ubiquiti device discovery (UDP 10001) — UBNT/airOS/UniFi enumeration + amplification vector; capture-only.",
	"wireguard":     "WireGuard (UDP 51820) — VPN handshake; capture-only, decodes the message type.",
	"openvpn_udp":   "OpenVPN over UDP (UDP 1194) — capture-only, decodes the opcode.",
	"l2tp":          "L2TP (UDP 1701) — tunnelling control; capture-only.",
	"rip":           "RIP v1/v2 (UDP 520) — routing protocol; flags route requests (recon) and responses (route injection).",
	"steam":         "Source/Steam A2S query (UDP 27015) — game-server query + amplification vector; capture-only.",
	"sentinel_hasp": "SafeNet Sentinel HASP license manager (UDP 1947) — amplification vector + engineering-station tell; capture-only.",
	// IoT (consumer / smart-home).
	"mqtt_sn":     "MQTT-SN, MQTT for Sensor Networks (UDP 1884) — capture-only, decodes the message type.",
	"tplink_kasa": "TP-Link Kasa smart-plug/bulb LAN protocol (UDP 9999) — decrypts the autokey-XOR JSON to capture the command; capture-only.",
	"tuya":        "Tuya smart-home device LAN protocol (UDP 6667) — capture-only, decodes the 0x55AA framing.",
	"miio":        "Xiaomi mihome / miIO (UDP 54321) — capture-only, decodes the 0x2131 header + device id.",
	"lwm2m":       "OMA LwM2M device management over CoAP (UDP 5683/5684) — capture-only, flags register/bootstrap.",
	// IIoT (industrial IoT transports / discovery).
	"modbus_udp":   "Modbus over UDP (UDP 502) — capture-only; flags write/diagnostic function codes.",
	"enip_udp":     "EtherNet/IP CIP discovery — ListIdentity (UDP 44818) — Rockwell/AB enumeration + amplification vector; capture-only.",
	"opcua_pubsub": "OPC UA PubSub over UDP / UADP (UDP 4840) — capture-only, decodes the publisher id.",
	"dds_rtps":     "DDS/RTPS — OMG Data Distribution Service / ROS 2 (UDP 7400+) — capture-only, decodes the RTPS header.",
	"hartip_udp":   "HART-IP over UDP (UDP 5094) — field-device management; capture-only, decodes the header.",
	// OT / building automation.
	"crestron":  "Crestron control-system discovery (UDP 41794) — AV / room-automation enumeration; capture-only.",
	"pjlink":    "PJLink projector / AV control (UDP 4352) — flags search + power control; capture-only.",
	"cbus":      "Clipsal C-Bus lighting / building automation over IP (UDP 20023) — flags lighting actuation; capture-only.",
	"dnp3_udp":  "DNP3 over UDP (UDP 20000) — utility SCADA; flags control functions; capture-only.",
	"saia_sbus": "Saia Ether-S-Bus (UDP 5050) — Saia Burgess PCD controllers; flags PCD control commands; capture-only.",
	"modbus":    "Modbus/TCP PLC (function codes, unit ids).", "s7": "Siemens S7comm PLC.",
	"iec104": "IEC 60870-5-104 SCADA.", "dnp3": "DNP3 SCADA outstation.",
	"mqtt": "MQTT broker — captures CONNECT username/password.", "bacnet": "BACnet/IP building automation.",
	"redis": "Redis server — captures AUTH.", "mysql": "MySQL server — handshake + captured auth.",
	"postgres": "PostgreSQL server (incl. SSLRequest upgrade).", "mssql": "Microsoft SQL Server (TDS).",
	"mongodb": "MongoDB wire protocol.", "elasticsearch": "Elasticsearch HTTP API.",
	"rdp": "RDP — X.224/TLS negotiation + CredSSP/NLA probe capture.", "smb": "SMB/CIFS — dialect negotiation, ZeroLogon/Eternal* signatures.",
	"vnc": "VNC (RFB) — auth challenge + captured response.", "ldap": "LDAP — bind DN/credentials.",
	"kerberos": "Kerberos KDC — AS-REQ pre-auth (crackable timestamp) + principals.",
	"vault":    "HashiCorp Vault API — captures presented tokens.", "kubernetes_api": "Kubernetes API server — captures bearer tokens.",
	"cloud_metadata": "Cloud instance-metadata service (169.254.169.254) — credential-theft bait.",
	"svn":            "Subversion svnserve (3690) — greets, captures the client's protocol response + the repository URL it reaches for.",
	"nbd":            "Network Block Device (10809) — newstyle handshake; captures the option + requested export name, flags export enumeration.",
	"statsd":         "StatsD metrics intake (UDP 8125) — capture-only (never replies); records injected metrics.",
	"raw":            "Raw capture — records bytes, guesses the protocol, flags unknown-protocol.",
	"auto":           "Generic catch-all — captures the opening message and guesses the protocol.",
}

// handlerDocs lists every protocol handler the validator accepts (TCP + UDP),
// with its transport and a short description.
func handlerDocs() []handlerDoc {
	trans := map[string]string{}
	for _, n := range config.TCPHandlerNames() {
		trans[n] = "tcp"
	}
	for _, n := range config.UDPHandlerNames() {
		if trans[n] == "tcp" {
			trans[n] = "tcp+udp"
		} else {
			trans[n] = "udp"
		}
	}
	names := make([]string, 0, len(trans))
	for n := range trans {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]handlerDoc, 0, len(names))
	for _, n := range names {
		desc := handlerDescriptions[n]
		if desc == "" {
			desc = "emulated " + n + " service."
		}
		out = append(out, handlerDoc{Name: n, Transport: trans[n], Desc: desc})
	}
	return out
}

// techniqueDocs lists every distinct ATT&CK technique the static maps stamp,
// with its one-line description, sorted by id.
func techniqueDocs() []techDoc {
	set := map[string]struct{}{}
	for _, c := range mitre.Coverage() {
		for _, t := range c.Techniques {
			set[t] = struct{}{}
		}
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]techDoc, 0, len(ids))
	for _, id := range ids {
		out = append(out, techDoc{ID: id, Desc: mitre.Describe(id)})
	}
	return out
}

// cveDocs adapts the CVE catalog for the docs table (sorted by id via All()).
func cveDocs() []cveDoc {
	recs := cve.All()
	out := make([]cveDoc, 0, len(recs))
	for _, r := range recs {
		out = append(out, cveDoc{
			ID: r.ID, Name: r.Name, Service: r.Service, Desc: r.Description,
			CPE: r.CPE, CVSS: r.CVSS, EPSS: r.EPSS, CWE: r.CWE,
		})
	}
	return out
}
