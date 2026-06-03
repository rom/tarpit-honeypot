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
	"dns":    "DNS resolver (UDP + TCP) — topology-coherent answers + tunneling/exfil detection.",
	"snmp":   "SNMP agent — MIB-2 sysDescr/ifTable, captures community strings.",
	"modbus": "Modbus/TCP PLC (function codes, unit ids).", "s7": "Siemens S7comm PLC.",
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
