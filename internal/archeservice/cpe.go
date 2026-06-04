package archeservice

// CPE for service roles. A role answers "WHAT the box does"; its concrete
// software identity (and thus the authoritative CPE) comes from the bound
// archetype. As a useful default, each role also carries the CPE of the
// canonical reference implementation a stock instance of that role runs
// (e.g. webserver -> Apache httpd, dnsserver -> ISC BIND). Roles with no single
// canonical product fall back to a generic application CPE so every role yields
// a well-formed identifier.

var roleCPE = map[string]string{
	"webserver":         "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
	"ftpserver":         "cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*",
	"sshserver":         "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
	"bastion":           "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
	"printserver":       "cpe:2.3:a:cups:cups:*:*:*:*:*:*:*:*",
	"fileserver":        "cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*",
	"nasserver":         "cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*",
	"nfsserver":         "cpe:2.3:a:linux:linux_kernel:*:*:*:*:*:*:*:*",
	"ldapserver":        "cpe:2.3:a:openldap:openldap:*:*:*:*:*:*:*:*",
	"adserver":          "cpe:2.3:o:microsoft:windows_server:*:*:*:*:*:*:*:*",
	"aaaserver":         "cpe:2.3:a:freeradius:freeradius:*:*:*:*:*:*:*:*",
	"radiusserver":      "cpe:2.3:a:freeradius:freeradius:*:*:*:*:*:*:*:*",
	"mailserver":        "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*",
	"dbserver":          "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
	"sqlserver":         "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*",
	"tsdbserver":        "cpe:2.3:a:influxdata:influxdb:*:*:*:*:*:*:*:*",
	"dnsserver":         "cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*",
	"snmpserver":        "cpe:2.3:a:net-snmp:net-snmp:*:*:*:*:*:*:*:*",
	"timeserver":        "cpe:2.3:a:ntp:ntp:*:*:*:*:*:*:*:*",
	"proxyserver":       "cpe:2.3:a:squid-cache:squid:*:*:*:*:*:*:*:*",
	"loadbalancer":      "cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*",
	"vpnserver":         "cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*",
	"vpngateway":        "cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*",
	"remoteaccess":      "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*",
	"remotedesktop":     "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*",
	"gitserver":         "cpe:2.3:a:git_project:git:*:*:*:*:*:*:*:*",
	"ciserver":          "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
	"javaappserver":     "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
	"tomcatserver":      "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
	"containerhost":     "cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*",
	"kubernetes":        "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*",
	"k8scontrolplane":   "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*",
	"containerregistry": "cpe:2.3:a:docker:distribution:*:*:*:*:*:*:*:*",
	"messagequeue":      "cpe:2.3:a:vmware:rabbitmq:*:*:*:*:*:*:*:*",
	"natsserver":        "cpe:2.3:a:nats:nats_server:*:*:*:*:*:*:*:*",
	"cacheserver":       "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
	"searchserver":      "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*",
	"monitoringserver":  "cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*",
	"observability":     "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*",
	"logserver":         "cpe:2.3:a:graylog:graylog:*:*:*:*:*:*:*:*",
	"backupserver":      "cpe:2.3:a:veeam:backup_\\&_replication:*:*:*:*:*:*:*:*",
	"objectstore":       "cpe:2.3:a:minio:minio:*:*:*:*:*:*:*:*",
	"secretstore":       "cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*",
	"bigdata":           "cpe:2.3:a:apache:hadoop:*:*:*:*:*:*:*:*",
	"streamserver":      "cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*",
	"voipserver":        "cpe:2.3:a:asterisk:asterisk:*:*:*:*:*:*:*:*",
	"pbxserver":         "cpe:2.3:a:asterisk:asterisk:*:*:*:*:*:*:*:*",
	"sipproxy":          "cpe:2.3:a:kamailio:kamailio:*:*:*:*:*:*:*:*",
	"androidadb":        "cpe:2.3:o:google:android:*:*:*:*:*:*:*:*",
	"mainframe":         "cpe:2.3:o:ibm:zos:*:*:*:*:*:*:*:*",
	"vdibroker":         "cpe:2.3:a:vmware:horizon:*:*:*:*:*:*:*:*",
}

// CPE returns the canonical reference-implementation CPE for a service role.
// The authoritative platform CPE for a deployed listener still comes from the
// bound archetype; this is the role's default-software identity. Always returns
// a well-formed cpe:2.3 string (a generic application CPE for roles with no
// single canonical product).
func CPE(role string) string {
	if c, ok := roleCPE[normalize(role)]; ok {
		return c
	}
	return "cpe:2.3:a:generic:" + normalize(role) + ":*:*:*:*:*:*:*:*"
}
