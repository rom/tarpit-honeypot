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
	"gitserver": {
		{9418, "tcp", "git", "git daemon protocol"},
		{22, "tcp", "ssh", "git over SSH"},
		{80, "tcp", "http", "git smart-HTTP / web UI"},
		{443, "tcp", "https", "git smart-HTTP (TLS) / web UI"},
	},
	"ciserver": {
		{8080, "tcp", "http", "CI web UI (Jenkins/GitLab)"},
		{443, "tcp", "https", "CI web UI (TLS)"},
		{22, "tcp", "ssh", "git/agent SSH"},
	},
	"javaappserver": {
		{8080, "tcp", "http", "servlet container"},
		{443, "tcp", "https", "servlet container (TLS)"},
		{1099, "tcp", "rmi", "Java RMI registry"},
		{8000, "tcp", "jdwp", "Java Debug Wire Protocol"},
	},
	"containerhost": {
		{2375, "tcp", "dockerapi", "Docker API (plaintext)"},
		{2376, "tcp", "dockerapi", "Docker API (TLS)"},
		{6443, "tcp", "https", "Kubernetes API server"},
		{10250, "tcp", "https", "kubelet API"},
	},
	"messagequeue": {
		{5672, "tcp", "amqp", "AMQP / RabbitMQ"},
		{1883, "tcp", "mqtt", "MQTT"},
		{9092, "tcp", "kafka", "Kafka broker"},
		{2181, "tcp", "zookeeper", "ZooKeeper"},
		{8161, "tcp", "http", "broker web console"},
	},
	"cacheserver": {
		{6379, "tcp", "redis", "Redis"},
		{11211, "tcp", "memcached", "Memcached"},
	},
	"searchserver": {
		{9200, "tcp", "elasticsearch", "Elasticsearch HTTP API"},
		{5601, "tcp", "http", "Kibana"},
	},
	"nasserver": {
		{445, "tcp", "smb", "SMB"},
		{873, "tcp", "rsync", "rsync daemon"},
		{5000, "tcp", "http", "NAS web UI"},
		{5001, "tcp", "https", "NAS web UI (TLS)"},
		{22, "tcp", "ssh", "SFTP / SSH"},
	},
	"cameraserver": {
		{554, "tcp", "rtsp", "RTSP stream"},
		{80, "tcp", "http", "camera web UI"},
		{443, "tcp", "https", "camera web UI (TLS)"},
	},
	"bastion": {
		{22, "tcp", "ssh", "SSH jump host"},
		{3389, "tcp", "rdp", "RDP gateway"},
		{443, "tcp", "https", "web SSH/RDP portal"},
	},
	"timeserver": {
		{123, "udp", "ntp", "NTP"},
		{37, "tcp", "time", "TIME (RFC 868)"},
		{37, "udp", "time", "TIME (RFC 868)"},
		{13, "tcp", "daytime", "DAYTIME"},
	},
	"radiusserver": {
		{1812, "udp", "radius", "RADIUS authentication"},
		{1813, "udp", "radius", "RADIUS accounting"},
		{80, "tcp", "http", "admin web UI"},
	},
	"nfsserver": {
		{111, "tcp", "rpcbind", "SunRPC portmapper"},
		{2049, "tcp", "raw", "NFS"},
		{20048, "tcp", "raw", "mountd"},
	},
	"vpngateway": {
		{500, "udp", "isakmp", "IKE / IPsec"},
		{4500, "udp", "isakmp", "IPsec NAT-T"},
		{1194, "tcp", "openvpn", "OpenVPN"},
		{1723, "tcp", "pptp", "PPTP control"},
		{443, "tcp", "https", "SSL-VPN portal"},
	},
	"bigdata": {
		{9042, "tcp", "cassandra", "Cassandra CQL"},
		{2181, "tcp", "zookeeper", "ZooKeeper"},
		{9092, "tcp", "kafka", "Kafka broker"},
		{8088, "tcp", "http", "YARN ResourceManager"},
		{9870, "tcp", "http", "HDFS NameNode UI"},
	},
	"natsserver": {
		{4222, "tcp", "nats", "NATS client"},
		{8222, "tcp", "http", "NATS monitoring"},
		{6222, "tcp", "raw", "NATS cluster route"},
	},
	"streamserver": {
		{554, "tcp", "rtsp", "RTSP"},
		{8554, "tcp", "rtsp", "RTSP (alt)"},
		{8000, "tcp", "http", "stream web UI"},
		{1935, "tcp", "raw", "RTMP"},
	},
	"loadbalancer": {
		{80, "tcp", "http", "HTTP frontend"},
		{443, "tcp", "https", "HTTPS frontend"},
		{8080, "tcp", "http", "backend / alt"},
		{8404, "tcp", "http", "HAProxy stats"},
	},
	"logserver": {
		{514, "udp", "syslog_udp", "syslog"},
		{601, "tcp", "syslog_tcp", "syslog (RFC 5425/6587)"},
		{9200, "tcp", "elasticsearch", "Elasticsearch"},
		{5601, "tcp", "http", "Kibana"},
	},
	"secretstore": {
		{8200, "tcp", "https", "Vault API"},
		{8201, "tcp", "https", "Vault cluster"},
		{8500, "tcp", "http", "Consul API"},
	},
	"tomcatserver": {
		{8009, "tcp", "ajp13", "AJP13 connector"},
		{8080, "tcp", "http", "servlet container"},
		{8443, "tcp", "https", "servlet container TLS"},
		{8005, "tcp", "raw", "Tomcat shutdown"},
	},
	"erlangcluster": {
		{4369, "tcp", "epmd", "Erlang Port Mapper"},
		{5672, "tcp", "amqp", "RabbitMQ AMQP"},
		{15672, "tcp", "http", "RabbitMQ management"},
		{25672, "tcp", "raw", "Erlang distribution"},
	},
	"aaaserver": {
		{49, "tcp", "tacacs", "TACACS+"},
		{1812, "udp", "radius", "RADIUS authentication"},
		{1813, "udp", "radius", "RADIUS accounting"},
	},
	"observability": {
		{3000, "tcp", "http", "Grafana"},
		{9090, "tcp", "http", "Prometheus"},
		{9093, "tcp", "http", "Alertmanager"},
		{9100, "tcp", "raw", "node exporter"},
	},
	"objectstore": {
		{9000, "tcp", "http", "S3 / MinIO API"},
		{9001, "tcp", "http", "MinIO console"},
		{443, "tcp", "https", "S3 API (TLS)"},
	},
	"containerregistry": {
		{5000, "tcp", "http", "registry v2 API"},
		{443, "tcp", "https", "registry TLS"},
		{2375, "tcp", "dockerapi", "Docker remote API"},
	},
	"k8scontrolplane": {
		{6443, "tcp", "https", "kube-apiserver"},
		{10250, "tcp", "https", "kubelet"},
		{2379, "tcp", "http", "etcd client"},
		{10259, "tcp", "https", "kube-scheduler"},
	},
	"sqlserver": {
		{1433, "tcp", "mssql", "SQL Server"},
		{1434, "udp", "mssql_browser", "SQL Browser (SSRP)"},
		{80, "tcp", "http", "Reporting Services"},
	},
	"tsdbserver": {
		{8086, "tcp", "http", "InfluxDB"},
		{8123, "tcp", "http", "ClickHouse HTTP"},
		{2003, "tcp", "raw", "Graphite carbon"},
		{3000, "tcp", "http", "Grafana"},
	},
	"androidadb": {
		{5555, "tcp", "adb", "Android Debug Bridge"},
		{5037, "tcp", "raw", "adb server"},
		{443, "tcp", "https", "MDM console"},
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
