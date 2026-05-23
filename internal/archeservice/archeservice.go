// Package archeservice maps a service *role* — "webserver", "ftpserver",
// "printserver", "fileserver", "ldapserver", "adserver", … — to the set of
// (port, protocol, handler) tuples a real instance of that role exposes.
//
// A role answers "WHAT does this box do"; an archetype (internal/archetype)
// answers "WHO is this box" (the OS/vendor identity: banners, versions, TLS
// posture, MAC OUI). Combining them — a `webserver` role with a `debian-12`
// archetype — yields a Debian box serving HTTP/HTTPS with Debian's Apache
// banner + TLS posture; the same role with `windows-server-2019` serves IIS.
//
// The config layer (internal/config) expands an `archeservices:` entry into
// concrete listeners, one per Service, carrying the chosen archetype so the
// handlers answer with software/version strings consistent with it.
package archeservice

import (
	"sort"
	"strings"
)

// Service is one network endpoint a role exposes.
type Service struct {
	Port    int
	Proto   string // "tcp" | "udp"
	Handler string // a handler name valid for Proto (see config handler whitelist)
	Note    string
}

// roles is the catalog. Handlers are the existing protocol handlers; the
// archetype bound to the expanded listener supplies the actual banners.
var roles = map[string][]Service{
	"webserver": {
		{80, "tcp", "http", "HTTP"},
		{443, "tcp", "https", "HTTPS"},
	},
	"ftpserver": {
		{21, "tcp", "ftp", "FTP control"},
	},
	"sshserver": {
		{22, "tcp", "ssh", "SSH"},
	},
	"printserver": {
		{9100, "tcp", "pjl", "JetDirect / PJL raw print"},
		{631, "tcp", "ipp", "IPP / CUPS"},
		{515, "tcp", "lpd", "LPD"},
		{161, "udp", "snmp", "Printer-MIB SNMP"},
	},
	"fileserver": {
		{445, "tcp", "smb", "SMB"},
		{139, "tcp", "raw", "NetBIOS session"},
		{21, "tcp", "ftp", "FTP"},
	},
	"ldapserver": {
		{389, "tcp", "ldap", "LDAP"},
		{636, "tcp", "https", "LDAPS (TLS)"},
	},
	"adserver": {
		{53, "udp", "dns", "AD-integrated DNS"},
		{88, "tcp", "kerberos", "Kerberos KDC"},
		{135, "tcp", "dcerpc", "RPC endpoint mapper"},
		{139, "tcp", "raw", "NetBIOS session"},
		{389, "tcp", "ldap", "LDAP"},
		{445, "tcp", "smb", "SMB / AD replication"},
		{636, "tcp", "https", "LDAPS"},
		{3268, "tcp", "ldap", "Global Catalog"},
		{3269, "tcp", "https", "Global Catalog over SSL"},
		{3389, "tcp", "rdp", "Remote Desktop"},
		{5985, "tcp", "winrm", "WinRM / PowerShell Remoting"},
	},
	"mailserver": {
		{25, "tcp", "smtp_recv", "SMTP"},
		{587, "tcp", "smtp_recv", "SMTP submission"},
		{110, "tcp", "pop3", "POP3"},
		{143, "tcp", "imap", "IMAP"},
	},
	"dbserver": {
		{3306, "tcp", "mysql", "MySQL"},
		{5432, "tcp", "postgres", "PostgreSQL"},
		{1433, "tcp", "mssql", "Microsoft SQL Server"},
		{1521, "tcp", "oracle_tns", "Oracle TNS"},
		{6379, "tcp", "redis", "Redis"},
		{11211, "tcp", "memcached", "Memcached"},
		{27017, "tcp", "mongodb", "MongoDB"},
		{9200, "tcp", "elasticsearch", "Elasticsearch"},
	},
	"dnsserver": {
		{53, "udp", "dns", "DNS"},
	},
	"snmpserver": {
		{161, "udp", "snmp", "SNMP"},
	},
	"voipserver": {
		{5060, "udp", "sip", "SIP"},
	},
	"remoteaccess": {
		{22, "tcp", "ssh", "SSH"},
		{3389, "tcp", "rdp", "RDP"},
		{5900, "tcp", "vnc", "VNC"},
		{5985, "tcp", "winrm", "WinRM"},
	},
	"proxyserver": {
		{3128, "tcp", "http", "Squid HTTP proxy"},
		{8080, "tcp", "http", "HTTP proxy (alt)"},
		{1080, "tcp", "socks", "SOCKS proxy"},
	},
	"vpnserver": {
		{443, "tcp", "openvpn", "OpenVPN (TCP)"},
		{1194, "tcp", "openvpn", "OpenVPN"},
		{500, "udp", "isakmp", "IKE / IPsec"},
	},
	"monitoringserver": {
		{161, "udp", "snmp", "SNMP poller target"},
		{514, "udp", "syslog_udp", "Syslog collector"},
		{80, "tcp", "http", "Monitoring web UI"},
		{443, "tcp", "https", "Monitoring web UI (TLS)"},
	},
	"backupserver": {
		{873, "tcp", "rsync", "rsync daemon"},
		{21, "tcp", "ftp", "FTP"},
		{445, "tcp", "smb", "SMB"},
		{22, "tcp", "ssh", "SFTP / SSH"},
	},
	"iotgateway": {
		{1883, "tcp", "mqtt", "MQTT broker"},
		{5683, "udp", "coap", "CoAP"},
		{80, "tcp", "http", "Device web UI"},
		{8883, "tcp", "mqtt", "MQTT over TLS"},
	},
	"scadaserver": {
		{502, "tcp", "modbus", "Modbus/TCP"},
		{102, "tcp", "s7", "S7comm"},
		{20000, "tcp", "dnp3", "DNP3"},
		{80, "tcp", "http", "HMI web UI"},
		{161, "udp", "snmp", "SNMP"},
	},
	"routerserver": {
		{179, "tcp", "bgp", "BGP"},
		{22, "tcp", "ssh", "SSH management"},
		{23, "tcp", "telnet", "Telnet CLI"},
		{161, "udp", "snmp", "SNMP"},
		{80, "tcp", "http", "Router web UI"},
	},
}

// Lookup returns the service set for a role (case- and separator-
// insensitive: "web-server", "Web Server", "webserver" all resolve).
func Lookup(role string) ([]Service, bool) {
	s, ok := roles[normalize(role)]
	return s, ok
}

// Names returns the role names sorted alphabetically.
func Names() []string {
	out := make([]string, 0, len(roles))
	for k := range roles {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// normalize folds case and strips spaces / hyphens / underscores so the
// config can name a role naturally.
func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	r := strings.NewReplacer(" ", "", "-", "", "_", "")
	return r.Replace(s)
}
