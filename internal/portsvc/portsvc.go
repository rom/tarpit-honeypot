// Package portsvc maps a TCP/UDP port number to a short, human-readable
// service name (IANA well-known names plus the ICS/OT and honeypot-relevant
// ports this sensor emulates). The web UI uses it to annotate destination
// ports so an analyst sees "445 (smb)" instead of a bare number.
package portsvc

import "strconv"

var names = map[int]string{
	7: "echo", 9: "discard", 13: "daytime", 17: "qotd", 19: "chargen", 21: "ftp",
	22: "ssh", 23: "telnet", 25: "smtp", 37: "time", 53: "dns", 67: "dhcp",
	69: "tftp", 80: "http", 88: "kerberos", 102: "s7/mms", 110: "pop3",
	111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
	143: "imap", 161: "snmp", 162: "snmptrap", 389: "ldap", 443: "https",
	445: "smb", 464: "kpasswd", 502: "modbus", 514: "syslog", 515: "lpd",
	554: "rtsp", 587: "smtp-submission", 623: "ipmi", 631: "ipp", 636: "ldaps",
	802: "modbus-security",
	993: "imaps", 995: "pop3s", 1025: "melsec", 1080: "socks", 1099: "java-rmi",
	1217: "codesys", 1433: "mssql", 1521: "oracle-tns", 1723: "pptp", 1883: "mqtt",
	1900: "ssdp", 1911: "fox", 1962: "pcworx", 2049: "nfs", 2375: "docker",
	2376: "docker-tls", 2404: "iec104", 3268: "globalcatalog", 3269: "globalcatalog-ssl",
	2427: "mgcp", 2727: "mgcp-ca",
	3306: "mysql", 3389: "rdp", 3671: "knx", 3782: "iccp-secure", 4460: "nts-ke", 4840: "opcua", 5060: "sip",
	5094: "hartip", 5222: "xmpp", 5353: "mdns", 5355: "llmnr", 5432: "postgres",
	5450: "osisoft-pi",
	5683: "coap", 5672: "amqp", 5900: "vnc", 5985: "winrm", 5986: "winrm-tls",
	5984: "couchdb", 8086: "influxdb", 5000: "docker-registry",
	7687: "neo4j",
	6379: "redis", 8080: "http-alt", 8443: "https-alt", 9100: "jetdirect/pjl",
	9200: "elasticsearch", 9600: "fins", 10001: "atg", 11211: "memcached",
	10250: "kubelet", 10255: "kubelet-ro",
	4712: "c37118", 8193: "focas", 18245: "ge-srtp", 20000: "dnp3",
	20547: "proconos", 27017: "mongodb", 28015: "rethinkdb", 34980: "ethercat", 44818: "ethernet/ip",
	47808: "bacnet", 48898: "ads", 48899: "ads-discovery",
	7547: "tr069", 5473: "tr069-alt",
	11434: "ollama", 1234: "lm-studio", 4646: "nomad", 8500: "consul",
	8888: "jupyter", 4444: "selenium", 8123: "clickhouse", 9000: "minio",
	104: "dicom", 2575: "hl7-mllp", 2762: "dicom-tls", 11112: "dicom",
}

// Name returns the service name for a port, or "" when unknown.
func Name(port int) string { return names[port] }

// Label returns "<port> (<service>)" when known, else just the port.
func Label(port int) string {
	if port <= 0 {
		return ""
	}
	if n := names[port]; n != "" {
		return strconv.Itoa(port) + " (" + n + ")"
	}
	return strconv.Itoa(port)
}
