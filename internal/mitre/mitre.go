// Package mitre maps tarpit-honeypot rule IDs to MITRE ATT&CK
// technique IDs + tactic names. The mapping is consulted from the
// router right before an event is sent to the sinks, so every
// downstream consumer (CEF / LEEF / OCSF / JSON / webhook / syslog /
// MQTT / SIEM rules) sees the same set of techniques and tactics for
// the same activity.
//
// The reference is the MITRE ATT&CK Enterprise matrix v15. We keep
// the table in-source rather than loading a STIX bundle because the
// honeypot's rule set is small + stable and we want zero runtime cost.
package mitre

import (
	"sort"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/cve"
)

// Tag bundles the ATT&CK metadata attached to a single rule_id. Both
// fields can be empty for noise events the framework doesn't model
// (e.g. sensor:reload, sensor:panic).
type Tag struct {
	Techniques []string // e.g. ["T1110.001", "T1078.001"]
	Tactics    []string // e.g. ["credential-access", "initial-access"]
}

// Lookup returns the Tag for the given rule_id. Unknown rule_ids
// return an empty Tag (zero value) — the caller treats that as "no
// ATT&CK mapping".
//
// For listener:<id> events the meta.handler is used to refine the
// mapping (so listener:http-bait gets T1190 / T1078, while
// listener:ssh-bait gets T1110.001 / T1078.001).
func Lookup(ruleID, handler string) Tag {
	if t, ok := exactRules[ruleID]; ok {
		return t
	}
	// listener:<id>: look up by handler instead.
	if strings.HasPrefix(ruleID, "listener:") {
		if t, ok := handlerTags[handler]; ok {
			return t
		}
		return Tag{Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}}
	}
	// cve:<id> events inherit the exploit's ATT&CK technique from the
	// catalog (initial-access RCE, lateral-movement remote-service
	// exploit, …); unknown ids fall back to T1190.
	if strings.HasPrefix(ruleID, "cve:") {
		if rec, ok := cve.Lookup(strings.TrimPrefix(ruleID, "cve:")); ok && rec.Technique != "" {
			return Tag{Techniques: []string{rec.Technique}, Tactics: []string{rec.Tactic}}
		}
		return Tag{Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}}
	}
	// canary hits cover credential staging / persistence reconnaissance.
	if strings.HasPrefix(ruleID, "canary:url:") {
		return Tag{Techniques: []string{"T1083", "T1190"}, Tactics: []string{"discovery", "initial-access"}}
	}
	if strings.HasPrefix(ruleID, "canary:dns:") {
		return Tag{Techniques: []string{"T1071.004"}, Tactics: []string{"command-and-control"}}
	}
	if strings.HasPrefix(ruleID, "canary:") {
		return Tag{Techniques: []string{"T1083"}, Tactics: []string{"discovery"}}
	}
	if strings.HasPrefix(ruleID, "storyline:") {
		// Storyline events are aggregations; the participating
		// techniques are carried in the meta. Don't double-tag.
		return Tag{}
	}
	return Tag{}
}

// exactRules covers fully-qualified non-listener rule_ids.
var exactRules = map[string]Tag{
	"correlate:port_scan":        {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"correlate:brute_force":      {Techniques: []string{"T1110"}, Tactics: []string{"credential-access"}},
	"correlate:slow_scan":        {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"correlate:password_spray":   {Techniques: []string{"T1110.003"}, Tactics: []string{"credential-access"}},
	"correlate:credential_reuse": {Techniques: []string{"T1110.004"}, Tactics: []string{"credential-access"}},
	// Content discovery / forced browsing (dirbusting) of many URL paths.
	"correlate:path_enumeration": {Techniques: []string{"T1595.003", "T1083"}, Tactics: []string{"reconnaissance", "discovery"}},
	// DNS name enumeration: subdomain brute force / NXDOMAIN flood / DGA churn.
	"correlate:dns_enumeration": {Techniques: []string{"T1590.002", "T1568.002"}, Tactics: []string{"reconnaissance", "command-and-control"}},
	// Regularly-spaced call-home contact = C2 beaconing.
	"correlate:beacon": {Techniques: []string{"T1071"}, Tactics: []string{"command-and-control"}},
	// A profiled scan (nmap timing/scope/probe fingerprint) is active
	// scanning of the network from the adversary's recon phase, and
	// network-service discovery from ours.
	"scananalysis:profile":          {Techniques: []string{"T1595", "T1046"}, Tactics: []string{"reconnaissance", "discovery"}},
	"sniffer:arp_scan":              {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
	"sniffer:arp_reply_unsolicited": {Techniques: []string{"T1557.002"}, Tactics: []string{"credential-access"}},
	// Packet-capture scan-detection layer: stealth + volume TCP scans
	// observed on the wire that never establish a session.
	"sniffer:tcp_syn_scan":    {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"sniffer:tcp_null_scan":   {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"sniffer:tcp_fin_scan":    {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"sniffer:tcp_xmas_scan":   {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"sniffer:tcp_ack_scan":    {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"sniffer:tcp_maimon_scan": {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"sniffer:udp_scan":        {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"sniffer:ip_fragmented":   {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	// Tunnelling / overlay encapsulation observed on the segment (GRE,
	// IP-in-IP, VXLAN, GENEVE, L2TP, Teredo, …) = protocol tunnelling /
	// non-application-layer C2 transport.
	"sniffer:encapsulation": {Techniques: []string{"T1572", "T1095"}, Tactics: []string{"command-and-control"}},
	// Spanning-tree BPDUs: a root-bridge / topology-manipulation attempt
	// enables adversary-in-the-middle on the L2 segment.
	"sniffer:stp_bpdu": {Techniques: []string{"T1557"}, Tactics: []string{"credential-access", "collection"}},
	// Echo-based covert tunnel (ptunnel / icmpsh / Loki) — data smuggled in
	// ICMP = non-application-layer protocol tunnelling.
	"sniffer:icmp_tunnel": {Techniques: []string{"T1095", "T1572"}, Tactics: []string{"command-and-control"}},
	// PROFINET-DCP Identify = ICS remote system discovery on the segment.
	"honeynet:profinet_dcp_identify": {Techniques: []string{"T0846"}, Tactics: []string{"discovery"}},
	// IEC 61850 GOOSE substation multicast observed on the segment.
	"sniffer:goose":       {Techniques: []string{"T0888"}, Tactics: []string{"discovery"}},
	"dnscanary:hit":       {Techniques: []string{"T1071.004"}, Tactics: []string{"command-and-control"}},
	"dnscanary:amplifier": {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	"protocol_anomaly":    {Techniques: []string{"T1071"}, Tactics: []string{"command-and-control"}},
	// A previously-unseen host appearing on the segment maps to
	// network-service / remote-system discovery from the defender's
	// vantage (the device is doing the discovering).
	"device:new": {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
	// A known device's IP/MAC/hostname rebinding can indicate ARP-spoofing
	// / impersonation on the segment.
	"device:changed":       {Techniques: []string{"T1557.002"}, Tactics: []string{"credential-access"}},
	"correlate:icmp_sweep": {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
	// Additional opt-in correlators.
	"correlate:host_sweep":         {Techniques: []string{"T1018", "T1046"}, Tactics: []string{"discovery"}},
	"correlate:service_sweep":      {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"correlate:ua_rotation":        {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"correlate:exploit_chain":      {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"correlate:ics_control":        {Techniques: []string{"T0831"}, Tactics: []string{"impact"}},
	"correlate:canary_trip":        {Techniques: []string{"T1083"}, Tactics: []string{"discovery"}},
	"correlate:fingerprint_reuse":  {Techniques: []string{"T1583.005"}, Tactics: []string{"resource-development"}},
	"correlate:protocol_violation": {Techniques: []string{"T1595.002"}, Tactics: []string{"reconnaissance"}},
	"correlate:exfil":              {Techniques: []string{"T1048"}, Tactics: []string{"exfiltration"}},
	"correlate:session_flood":      {Techniques: []string{"T1499"}, Tactics: []string{"impact"}},
	// Enrichment-driven correlators (internal/correlate/extra3.go).
	"correlate:threat_intel_burst": {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"correlate:geo_velocity":       {Techniques: []string{"T1110.004"}, Tactics: []string{"credential-access"}},
	// Fuzzing / DoS classification (internal/fuzzdos). Fuzzing maps to
	// vulnerability scanning; a typed flood maps to endpoint DoS.
	"attack:fuzzing": {Techniques: []string{"T1595.002"}, Tactics: []string{"reconnaissance"}},
	"attack:dos":     {Techniques: []string{"T1499"}, Tactics: []string{"impact"}},
	// Additional opt-in correlators (round 2).
	"correlate:lateral_movement": {Techniques: []string{"T1021"}, Tactics: []string{"lateral-movement"}},
	"correlate:ot_recon":         {Techniques: []string{"T0846", "T0888"}, Tactics: []string{"discovery"}},
	"correlate:data_access":      {Techniques: []string{"T1213"}, Tactics: []string{"collection"}},
	"correlate:malware_campaign": {Techniques: []string{"T1105"}, Tactics: []string{"command-and-control"}},
	"correlate:webshell":         {Techniques: []string{"T1505.003", "T1059"}, Tactics: []string{"persistence", "execution"}},
	// Harvested malware / shellcode / dropper = ingress tool transfer
	// (+ obfuscated payload when base64-wrapped).
	"malware:capture": {Techniques: []string{"T1105", "T1027"}, Tactics: []string{"command-and-control", "defense-evasion"}},
	// Honeynet userspace TCP stack (internal/tcpstack). A completed
	// handshake to a virtual host's open port is service discovery; a
	// captured request is a probe; a malformed/illegal packet is a
	// crafted stealth scan (refined by its anomaly markers); a LAND
	// packet (src==dst) is an endpoint-DoS attempt (CVE-1999-0016).
	"honeynet:tcp_connect":   {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"honeynet:tcp_request":   {Techniques: []string{"T1046", "T1595"}, Tactics: []string{"discovery", "reconnaissance"}},
	"honeynet:tcp_malformed": {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"honeynet:tcp_land":      {Techniques: []string{"T1499"}, Tactics: []string{"impact"}},
}

// handlerTags is the listener-handler -> ATT&CK lookup. Handlers
// shaped like authentication endpoints (ssh, ftp, telnet, ...) map to
// T1110/T1078 (brute force / valid accounts). Handlers shaped like
// vulnerability-scanner-target services (http, smb, rdp) map to
// T1190 (exploit public-facing application).
var handlerTags = map[string]Tag{
	// Auth / credential surface.
	"ssh":             {Techniques: []string{"T1110.001", "T1078"}, Tactics: []string{"credential-access", "initial-access"}},
	"ssh_interactive": {Techniques: []string{"T1110.001", "T1078"}, Tactics: []string{"credential-access", "initial-access"}},
	"telnet":          {Techniques: []string{"T1110.001", "T1078"}, Tactics: []string{"credential-access", "initial-access"}},
	"ftp":             {Techniques: []string{"T1110.001", "T1078"}, Tactics: []string{"credential-access", "initial-access"}},
	"smtp_recv":       {Techniques: []string{"T1110.003", "T1114"}, Tactics: []string{"credential-access", "collection"}},
	"pop3":            {Techniques: []string{"T1110.001", "T1114"}, Tactics: []string{"credential-access", "collection"}},
	"imap":            {Techniques: []string{"T1110.001", "T1114"}, Tactics: []string{"credential-access", "collection"}},
	"memcached":       {Techniques: []string{"T1213", "T1046"}, Tactics: []string{"collection", "discovery"}},
	"mongodb":         {Techniques: []string{"T1213", "T1110.001"}, Tactics: []string{"collection", "credential-access"}},
	"elasticsearch":   {Techniques: []string{"T1213", "T1046"}, Tactics: []string{"collection", "discovery"}},
	"rdp":             {Techniques: []string{"T1021.001", "T1110.001"}, Tactics: []string{"lateral-movement", "credential-access"}},
	"vnc":             {Techniques: []string{"T1021.005", "T1110.001"}, Tactics: []string{"lateral-movement", "credential-access"}},
	"winrm":           {Techniques: []string{"T1021.006"}, Tactics: []string{"lateral-movement"}},
	"smb":             {Techniques: []string{"T1021.002", "T1135"}, Tactics: []string{"lateral-movement", "discovery"}},
	"postgres":        {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"mysql":           {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"redis":           {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"ldap":            {Techniques: []string{"T1110.003", "T1087.002"}, Tactics: []string{"credential-access", "discovery"}},
	"cldap":           {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
	"kerberos":        {Techniques: []string{"T1558"}, Tactics: []string{"credential-access"}},
	"dcerpc":          {Techniques: []string{"T1021.003"}, Tactics: []string{"lateral-movement"}},
	"xmpp":            {Techniques: []string{"T1071.001"}, Tactics: []string{"command-and-control"}},
	"amqp":            {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},

	// Vulnerability-scanner / publicly exposed application surface.
	"http":      {Techniques: []string{"T1190", "T1083"}, Tactics: []string{"initial-access", "discovery"}},
	"https":     {Techniques: []string{"T1190", "T1083"}, Tactics: []string{"initial-access", "discovery"}},
	"rtsp":      {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"dockerapi": {Techniques: []string{"T1190", "T1610"}, Tactics: []string{"initial-access", "execution"}},
	"ipp":       {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},

	// Discovery / IoT scanning.
	"snmp":       {Techniques: []string{"T1018", "T1110.001"}, Tactics: []string{"discovery", "credential-access"}},
	"ssdp":       {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
	"llmnr":      {Techniques: []string{"T1557.001"}, Tactics: []string{"credential-access"}},
	"nbns":       {Techniques: []string{"T1557.001"}, Tactics: []string{"credential-access"}},
	"mdns":       {Techniques: []string{"T1557.001", "T1046"}, Tactics: []string{"credential-access", "discovery"}},
	"sip":        {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"coap":       {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"knx":        {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"dhcp":       {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"radius":     {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"ntp":        {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	"tftp":       {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"ipmi":       {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"syslog_tcp": {Techniques: []string{"T1078"}, Tactics: []string{"initial-access"}},
	"syslog_udp": {Techniques: []string{"T1078"}, Tactics: []string{"initial-access"}},
	"dns":        {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},

	// inetd "small services" (RFC 862-868, 1340) — trivial, but their
	// presence is almost always a recon probe; chargen/echo are also
	// reflection-amplifier scouting targets.
	"echo":    {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"discard": {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"daytime": {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"qotd":    {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"chargen": {Techniques: []string{"T1046", "T1498.002"}, Tactics: []string{"discovery", "impact"}},
	"time":    {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},

	// ICS / OT surface — MITRE ATT&CK for ICS uses a separate
	// matrix (S0599 mapped techniques live there). We keep these
	// Enterprise-matrix equivalents for the SIEM that expects a
	// consistent ID space.
	"modbus":      {Techniques: []string{"T0814", "T0888"}, Tactics: []string{"impact", "discovery"}},
	"s7":          {Techniques: []string{"T0814", "T0888"}, Tactics: []string{"impact", "discovery"}},
	"iec104":      {Techniques: []string{"T0814"}, Tactics: []string{"impact"}},
	"mqtt":        {Techniques: []string{"T1110.001", "T0830"}, Tactics: []string{"credential-access", "lateral-movement"}},
	"opcua":       {Techniques: []string{"T0814"}, Tactics: []string{"impact"}},
	"ethernetip":  {Techniques: []string{"T0814", "T0888"}, Tactics: []string{"impact", "discovery"}},
	"bacnet":      {Techniques: []string{"T0814"}, Tactics: []string{"impact"}},
	"fins":        {Techniques: []string{"T0814"}, Tactics: []string{"impact"}},
	"melsec":      {Techniques: []string{"T0814"}, Tactics: []string{"impact"}},
	"dnp3":        {Techniques: []string{"T0814", "T0888"}, Tactics: []string{"impact", "discovery"}},
	"s7comm_plus": {Techniques: []string{"T0814", "T0888"}, Tactics: []string{"impact", "discovery"}},
	"ge_srtp":     {Techniques: []string{"T0888"}, Tactics: []string{"discovery"}},
	"codesys":     {Techniques: []string{"T0814"}, Tactics: []string{"impact"}},
	"atg":         {Techniques: []string{"T0888"}, Tactics: []string{"discovery"}},
	"fox":         {Techniques: []string{"T0888"}, Tactics: []string{"discovery"}},
	"hartip":      {Techniques: []string{"T0888"}, Tactics: []string{"discovery"}},
	"pcworx":      {Techniques: []string{"T0888"}, Tactics: []string{"discovery"}},
	"mms":         {Techniques: []string{"T0888", "T0814"}, Tactics: []string{"discovery", "impact"}},
	"ads":         {Techniques: []string{"T0888", "T0814"}, Tactics: []string{"discovery", "impact"}},
	"pjl":         {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"lpd":         {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},

	// More auth / remote-access / OOB-management surface.
	"mssql":        {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"oracle_tns":   {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"ftp_files":    {Techniques: []string{"T1110.001", "T1078"}, Tactics: []string{"credential-access", "initial-access"}},
	"rlogin":       {Techniques: []string{"T1110.001", "T1021"}, Tactics: []string{"credential-access", "lateral-movement"}},
	"vmware_authd": {Techniques: []string{"T1110.001", "T1078"}, Tactics: []string{"credential-access", "initial-access"}},
	"redfish":      {Techniques: []string{"T1190", "T1078"}, Tactics: []string{"initial-access"}},
	"x11":          {Techniques: []string{"T1021", "T1056.001"}, Tactics: []string{"lateral-movement", "collection"}},
	"nx":           {Techniques: []string{"T1021"}, Tactics: []string{"lateral-movement"}},
	"teamviewer":   {Techniques: []string{"T1219"}, Tactics: []string{"command-and-control"}},
	"anydesk":      {Techniques: []string{"T1219"}, Tactics: []string{"command-and-control"}},
	"openvpn":      {Techniques: []string{"T1133"}, Tactics: []string{"initial-access"}},
	"citrix_ica":   {Techniques: []string{"T1133"}, Tactics: []string{"initial-access"}},

	// Vendor management web UIs / lights-out: exploit-prone gateways.
	// More TCP/UDP service handlers.
	"rsync":          {Techniques: []string{"T1110.001", "T1213"}, Tactics: []string{"credential-access", "collection"}},
	"gopher":         {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"socks":          {Techniques: []string{"T1090"}, Tactics: []string{"command-and-control"}},
	"bgp":            {Techniques: []string{"T1190", "T1018"}, Tactics: []string{"initial-access", "discovery"}},
	"isakmp":         {Techniques: []string{"T1133"}, Tactics: []string{"initial-access"}},
	"netbios_dgram":  {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
	"intel_amt":      {Techniques: []string{"T1190", "T1078"}, Tactics: []string{"initial-access"}},
	"ilo":            {Techniques: []string{"T1190", "T1078"}, Tactics: []string{"initial-access"}},
	"idrac":          {Techniques: []string{"T1190", "T1078"}, Tactics: []string{"initial-access"}},
	"esxi":           {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"fortinet":       {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"pulse":          {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"citrix_gateway": {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"horizon":        {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"moxa_mgmt":      {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
}

// anomalyTags maps a handler-flagged anomaly marker to the ATT&CK
// technique it implies, so a finer detection (SQLi, command injection,
// default-credential use, an ICS write) gets precise attribution even
// though it rides on a generic handler event. Augment unions these into
// the rule_id/handler base tag.
var anomalyTags = map[string]Tag{
	"default-credential-attempt": {Techniques: []string{"T1078.001"}, Tactics: []string{"credential-access"}},
	// A probe to an unmodelled port caught by the generic `auto` catch-all.
	"unknown-protocol": {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	// Post-auth FTP abuse (uploads / downloads / SITE EXEC / FTP-bounce / …).
	"ftp-upload-attempt":   {Techniques: []string{"T1105"}, Tactics: []string{"command-and-control"}},
	"ftp-download-attempt": {Techniques: []string{"T1020"}, Tactics: []string{"exfiltration"}},
	"ftp-site-command":     {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"ftp-bounce-scan":      {Techniques: []string{"T1090", "T1046"}, Tactics: []string{"command-and-control", "discovery"}},
	"ftp-delete-attempt":   {Techniques: []string{"T1485"}, Tactics: []string{"impact"}},
	"ftp-listing":          {Techniques: []string{"T1083"}, Tactics: []string{"discovery"}},
	// A recognized vulnerability scanner (Nessus / OpenVAS / Qualys /
	// Nexpose / Acunetix / Nikto / Nuclei / sqlmap …) — active vuln
	// scanning (recon) that probes for exploitable public-facing apps.
	"vulnerability-scanner": {Techniques: []string{"T1595.002", "T1190"}, Tactics: []string{"reconnaissance", "initial-access"}},
	// A recognized C2 / red-team framework beacon (Cobalt Strike, Mythic,
	// Empire, Covenant, Sliver, Metasploit, …) — application-layer C2.
	"c2-framework": {Techniques: []string{"T1071.001", "T1219"}, Tactics: []string{"command-and-control"}},
	// A headless-browser automation driver (Selenium / Puppeteer / headless
	// Chrome / PhantomJS) — scripted recon, not a real user.
	"headless-browser":     {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"modbus-write-attempt": {Techniques: []string{"T0836", "T0831"}, Tactics: []string{"impact"}},
	// SNMP SetRequest = write the device's running config (ACL / interface
	// / config-copy-to-tftp). Manipulation on enterprise gear, modify-
	// parameter on the ICS archetypes that also speak SNMP.
	"snmp-set-attempt": {Techniques: []string{"T1565.001", "T0836"}, Tactics: []string{"impact"}},
	// A source walking the SNMP MIB faster than the configured rate =
	// network/device enumeration via SNMP.
	"snmp-walk-rate-exceeded": {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"smtp-open-relay-probe":   {Techniques: []string{"T1071.003"}, Tactics: []string{"command-and-control"}},
	"smtp-user-enumeration":   {Techniques: []string{"T1087"}, Tactics: []string{"discovery"}},
	// DNS zone-transfer (AXFR/IXFR) = bulk enumeration of internal hosts.
	"dns-zone-transfer": {Techniques: []string{"T1590.002", "T1018"}, Tactics: []string{"reconnaissance", "discovery"}},
	// Encrypted-DNS channels (DoH / DoT / DNSCrypt) = DNS tunnelled inside
	// HTTPS/TLS/DNSCrypt to evade plaintext DNS monitoring.
	"dns-over-https": {Techniques: []string{"T1572", "T1071.004"}, Tactics: []string{"command-and-control"}},
	"dns-over-tls":   {Techniques: []string{"T1572", "T1071.004"}, Tactics: []string{"command-and-control"}},
	"dnscrypt-probe": {Techniques: []string{"T1572", "T1071.004"}, Tactics: []string{"command-and-control"}},
	// Algorithmically-generated C2 rendezvous domain.
	"dns-dga-suspected": {Techniques: []string{"T1568.002"}, Tactics: []string{"command-and-control"}},
	// DNS-SD service enumeration over mDNS = local network-service discovery.
	"mdns-service-enumeration": {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	// Behavioral HTTP anomalies: malformed/smuggled headers and a spoofed
	// (impossible) browser User-Agent.
	"http-malformed-header":   {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"http-duplicate-host":     {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"http-request-smuggling":  {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"http-connect-proxy":      {Techniques: []string{"T1090"}, Tactics: []string{"command-and-control"}},
	"http-impossible-browser": {Techniques: []string{"T1036"}, Tactics: []string{"defense-evasion"}},
	// Active Directory / Kerberos abuse.
	"kerberos-tgs-request":   {Techniques: []string{"T1558.003"}, Tactics: []string{"credential-access"}},
	"kerberos-rc4-requested": {Techniques: []string{"T1558.003"}, Tactics: []string{"credential-access"}},
	"ldap-spn-enumeration":   {Techniques: []string{"T1558.003", "T1087.002"}, Tactics: []string{"credential-access", "discovery"}},
	"ldap-asrep-roast-recon": {Techniques: []string{"T1558.004", "T1087.002"}, Tactics: []string{"credential-access", "discovery"}},
	"ldap-enumeration":       {Techniques: []string{"T1087.002"}, Tactics: []string{"discovery"}},
	// MSRPC named-interface binds = AD enumeration / lateral movement.
	"dcerpc-samr-enum":       {Techniques: []string{"T1087.002"}, Tactics: []string{"discovery"}},
	"dcerpc-lsarpc-enum":     {Techniques: []string{"T1087.002", "T1482"}, Tactics: []string{"discovery"}},
	"dcerpc-srvsvc-enum":     {Techniques: []string{"T1135"}, Tactics: []string{"discovery"}},
	"dcerpc-svcctl-access":   {Techniques: []string{"T1021.002", "T1543.003"}, Tactics: []string{"lateral-movement", "persistence"}},
	"dcerpc-winreg-access":   {Techniques: []string{"T1012", "T1003.002"}, Tactics: []string{"discovery", "credential-access"}},
	"dcerpc-dcsync":          {Techniques: []string{"T1003.006"}, Tactics: []string{"credential-access"}},
	"dcerpc-netlogon-access": {Techniques: []string{"T1210"}, Tactics: []string{"lateral-movement"}},
	// memcached abuse: stats recon, writes (cache poisoning), flush_all (wipe).
	"memcached-stats-probe":   {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"memcached-write-attempt": {Techniques: []string{"T1565.001"}, Tactics: []string{"impact"}},
	"memcached-flush":         {Techniques: []string{"T1485"}, Tactics: []string{"impact"}},
	// NoSQL / search data access = collection from a data store.
	"mongodb-data-access":       {Techniques: []string{"T1213"}, Tactics: []string{"collection"}},
	"elasticsearch-data-access": {Techniques: []string{"T1213"}, Tactics: []string{"collection"}},
	"elasticsearch-recon":       {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	// TFTP upload = ingress tool / firmware push; config read = exfil from
	// a configuration repository (the "copy run tftp" pivot on net gear).
	"tftp-write-attempt": {Techniques: []string{"T1105"}, Tactics: []string{"command-and-control"}},
	"tftp-config-read":   {Techniques: []string{"T1602.001"}, Tactics: []string{"collection"}},
	// Printer / MFP abuse (PJL 9100, IPP 631, LPD 515). The generic
	// printer- markers (recon, fs access, job received, dmcmd, admin ops)
	// fall through to the "printer-" discovery prefix below; these are the
	// high-signal ones that warrant a precise technique.
	"printer-filesystem-format":     {Techniques: []string{"T1485"}, Tactics: []string{"impact"}},
	"printer-path-traversal":        {Techniques: []string{"T1083"}, Tactics: []string{"discovery"}},
	"printer-config-set":            {Techniques: []string{"T1565"}, Tactics: []string{"impact"}},
	"printer-password-set":          {Techniques: []string{"T1098"}, Tactics: []string{"persistence"}},
	"printer-credential-access":     {Techniques: []string{"T1552"}, Tactics: []string{"credential-access"}},
	"printer-rdymsg-set":            {Techniques: []string{"T1491"}, Tactics: []string{"impact"}},
	"printer-message-injection":     {Techniques: []string{"T1491"}, Tactics: []string{"impact"}},
	"printer-auth-attempt":          {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"printer-postscript-exitserver": {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"printer-postscript-fileop":     {Techniques: []string{"T1059", "T1005"}, Tactics: []string{"execution", "collection"}},
	"printer-postscript-setparams":  {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"printer-cups-rce":              {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"printer-ipp-cmd-injection":     {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"printer-lpd-injection":         {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"printer-lpd-overflow":          {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"printer-language-switch":       {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"printer-servicemode":           {Techniques: []string{"T1078"}, Tactics: []string{"privilege-escalation"}},
	"printer-firmware-upload":       {Techniques: []string{"T1601"}, Tactics: []string{"defense-evasion"}},
	"printer-zpl-config":            {Techniques: []string{"T1565"}, Tactics: []string{"impact"}},
	// Web application attack families (ride on http/https handler events).
	"webapp:sqli":              {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"webapp:lfi":               {Techniques: []string{"T1190", "T1083"}, Tactics: []string{"initial-access", "discovery"}},
	"webapp:rfi_ssrf":          {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"webapp:xss":               {Techniques: []string{"T1059.007"}, Tactics: []string{"execution"}},
	"webapp:cmdi":              {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"webapp:ssti":              {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"webapp:log4shell":         {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"webapp:xxe":               {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"webapp:deserialize":       {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"webapp:secret-file-probe": {Techniques: []string{"T1083"}, Tactics: []string{"discovery"}},
	// SSH/telnet protocol-misuse + auth markers.
	"x11-connection-attempt": {Techniques: []string{"T1021"}, Tactics: []string{"lateral-movement"}},
	"rlogin-attempt":         {Techniques: []string{"T1021"}, Tactics: []string{"lateral-movement"}},
	"redfish-auth-attempt":   {Techniques: []string{"T1078"}, Tactics: []string{"credential-access"}},
	"vmware-authd-login":     {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	// BACnet WriteProperty against a control point = ICS manipulation (the
	// BACnet analogue of modbus-write-attempt).
	"bacnet-write-attempt": {Techniques: []string{"T0836", "T0831"}, Tactics: []string{"impact"}},
	// A probe to chargen/echo etc. — the reflection-amplifier scouting target.
	"udp-amplifier-probe": {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	// A planted bait file was retrieved from the decoy FTP tree.
	"honeyfile-download": {Techniques: []string{"T1005"}, Tactics: []string{"collection"}},
	// Interactive-shell TTPs (internal/shell) captured post-login on the
	// ssh_interactive / telnet handlers — the highest-signal detections.
	"shell-reverse-shell":          {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"shell-download-tool":          {Techniques: []string{"T1105"}, Tactics: []string{"command-and-control"}},
	"shell-encoded-payload":        {Techniques: []string{"T1027", "T1140"}, Tactics: []string{"defense-evasion"}},
	"shell-living-off-the-land":    {Techniques: []string{"T1218"}, Tactics: []string{"defense-evasion"}},
	"shell-ps-download-exec":       {Techniques: []string{"T1059.001", "T1105"}, Tactics: []string{"execution", "command-and-control"}},
	"shell-ps-encoded":             {Techniques: []string{"T1059.001", "T1027"}, Tactics: []string{"execution", "defense-evasion"}},
	"shell-credential-dump":        {Techniques: []string{"T1003"}, Tactics: []string{"credential-access"}},
	"shell-creds-file-access":      {Techniques: []string{"T1552.001"}, Tactics: []string{"credential-access"}},
	"shell-passwd-read":            {Techniques: []string{"T1003.008"}, Tactics: []string{"credential-access"}},
	"shell-shadow-read":            {Techniques: []string{"T1003.008"}, Tactics: []string{"credential-access"}},
	"shell-passwd-write":           {Techniques: []string{"T1136.001"}, Tactics: []string{"persistence"}},
	"shell-ad-recon":               {Techniques: []string{"T1087.002"}, Tactics: []string{"discovery"}},
	"shell-network-recon":          {Techniques: []string{"T1016"}, Tactics: []string{"discovery"}},
	"shell-persistence-cron":       {Techniques: []string{"T1053.003"}, Tactics: []string{"persistence"}},
	"shell-persistence-ssh-key":    {Techniques: []string{"T1098.004"}, Tactics: []string{"persistence"}},
	"shell-persistence-systemd":    {Techniques: []string{"T1543.002"}, Tactics: []string{"persistence"}},
	"shell-persistence-windows":    {Techniques: []string{"T1547"}, Tactics: []string{"persistence"}},
	"shell-priv-esc-sudo":          {Techniques: []string{"T1548.003"}, Tactics: []string{"privilege-escalation"}},
	"shell-priv-esc-suid":          {Techniques: []string{"T1548.001"}, Tactics: []string{"privilege-escalation"}},
	"shell-defender-tamper":        {Techniques: []string{"T1562.001"}, Tactics: []string{"defense-evasion"}},
	"shell-disable-fw":             {Techniques: []string{"T1562.004"}, Tactics: []string{"defense-evasion"}},
	"shell-defense-evade-history":  {Techniques: []string{"T1070.003"}, Tactics: []string{"defense-evasion"}},
	"shell-defense-evade-logclean": {Techniques: []string{"T1070.002"}, Tactics: []string{"defense-evasion"}},
	"shell-coin-miner":             {Techniques: []string{"T1496"}, Tactics: []string{"impact"}},
	// Web-shell access / command execution (http handler webshell detector).
	"webshell-access-attempt": {Techniques: []string{"T1505.003"}, Tactics: []string{"persistence"}},
	"webshell-command":        {Techniques: []string{"T1505.003", "T1059"}, Tactics: []string{"persistence", "execution"}},
	// Login-form / auth submissions on services whose handler base tag isn't
	// already credential-access.
	"http-login-attempt":  {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"mssql-login-attempt": {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	// Bare service probes + malformed / non-conforming protocol input — the
	// shape of an automated scanner banner-grabbing a port.
	"oracle-tns-probe":                {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"nx-probe":                        {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"openvpn-probe":                   {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"ssh-id-non-printable":            {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"ssh-id-not-ssh":                  {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"ssh-id-overlong":                 {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"http-method-unknown":             {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"http-request-line-non-printable": {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"telnet-credential-non-printable": {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	// Printer command recon + passive DHCP client observation.
	"pjl-command":          {Techniques: []string{"T1083"}, Tactics: []string{"discovery"}},
	"dhcp-client-observed": {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	// Redis post-auth abuse chain: CONFIG SET dir / SAVE writes a webshell or
	// cron job; SLAVEOF + MODULE LOAD and EVAL Lua run code; FLUSH wipes data.
	"redis-config-set":            {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"redis-save":                  {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"redis-replication-takeover":  {Techniques: []string{"T1059", "T1210"}, Tactics: []string{"execution", "lateral-movement"}},
	"redis-module-load":           {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"redis-script-exec":           {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"redis-flush":                 {Techniques: []string{"T1485"}, Tactics: []string{"impact"}},
	"elasticsearch-write-attempt": {Techniques: []string{"T1565.001"}, Tactics: []string{"impact"}},
	// Docker remote API abuse — deploy/control a container = code execution.
	"docker-container-create": {Techniques: []string{"T1610"}, Tactics: []string{"execution"}},
	"docker-remote-control":   {Techniques: []string{"T1610"}, Tactics: []string{"execution"}},
	// CoAP write to an IoT resource = manipulation of a device value.
	"coap-write-attempt": {Techniques: []string{"T1565"}, Tactics: []string{"impact"}},
	// NTP mode-6/7 control queries + monlist = reflection-amplification recon.
	"ntp-control-query":         {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	"ntp-monlist-amplification": {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	// Postgres streaming-replication connection = bulk data access.
	"postgres-replication-connection": {Techniques: []string{"T1213"}, Tactics: []string{"collection"}},
	// Auth submissions / brute on services whose base tag isn't already creds.
	"mysql-login-attempt": {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"rtsp-auth-attempt":   {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"sip-register-probe":  {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"winrm-ntlm-auth":     {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	// SIP INVITE scanning = VoIP toll-fraud / service reconnaissance.
	"sip-invite-attempt": {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	// New-handler protocol-misuse markers.
	"rsync-module-list":   {Techniques: []string{"T1083"}, Tactics: []string{"discovery"}},
	"rsync-module-access": {Techniques: []string{"T1213"}, Tactics: []string{"collection"}},
	"gopher-request":      {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"gopher-ssrf":         {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"socks-proxy-attempt": {Techniques: []string{"T1090"}, Tactics: []string{"command-and-control"}},
	"bgp-open-attempt":    {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"bgp-probe":           {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"ike-probe":           {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"netbios-datagram":    {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
	// Developer / data-infrastructure service decoys (internal/listener/handler/devsvc.go).
	// An exposed JDWP handshake is unauthenticated RCE; RMI is the Java
	// deserialization entry point; git clone/push is source access / supply
	// chain; ZooKeeper four-letter words + Kafka metadata are cluster recon.
	"jdwp-handshake-attempt": {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"jdwp-probe":             {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"rmi-probe":              {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"git-request":            {Techniques: []string{"T1213"}, Tactics: []string{"collection"}},
	"git-push-attempt":       {Techniques: []string{"T1195"}, Tactics: []string{"initial-access"}},
	"zookeeper-fourletter":   {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"kafka-request":          {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	// Userspace TCP/IP-stack (internal/tcpstack) packet anomalies. The
	// classic stealth scans (NULL/FIN/Xmas) and illegal flag combinations
	// are crafted active scanning; corrupt-framing probes (bad checksum /
	// data-offset / truncation) are IDS-evasion-shaped recon; a LAND
	// packet (src==dst, CVE-1999-0016) is an endpoint-DoS attempt.
	"tcp-null":           {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"tcp-fin-scan":       {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"tcp-xmas":           {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"tcp-syn-fin":        {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"tcp-syn-rst":        {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"tcp-data-in-syn":    {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"tcp-bad-checksum":   {Techniques: []string{"T1595.001"}, Tactics: []string{"reconnaissance"}},
	"tcp-bad-dataoffset": {Techniques: []string{"T1595.001"}, Tactics: []string{"reconnaissance"}},
	"tcp-truncated":      {Techniques: []string{"T1595.001"}, Tactics: []string{"reconnaissance"}},
	"tcp-land":           {Techniques: []string{"T1499"}, Tactics: []string{"impact"}},
	"ip-bad-checksum":    {Techniques: []string{"T1595.001"}, Tactics: []string{"reconnaissance"}},
	"ip-bad-header-len":  {Techniques: []string{"T1595.001"}, Tactics: []string{"reconnaissance"}},
	"ip-fragmented":      {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
}

// AnomalyTag returns the ATT&CK Tag implied by a single anomaly marker.
// Exact matches win; otherwise a few marker-prefix families map by class.
func AnomalyTag(a string) Tag {
	if t, ok := anomalyTags[a]; ok {
		return t
	}
	switch {
	case strings.HasPrefix(a, "uri-"):
		// suspicious-URI probes: recon / file discovery against the app.
		return Tag{Techniques: []string{"T1595.003", "T1083"}, Tactics: []string{"reconnaissance", "discovery"}}
	case strings.HasPrefix(a, "ics-"):
		return Tag{Techniques: []string{"T0888"}, Tactics: []string{"discovery"}}
	case strings.HasPrefix(a, "webapp:"):
		// Any web-attack-class marker without an explicit entry above is at
		// least an exploit attempt against the public-facing app.
		return Tag{Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}}
	case strings.HasPrefix(a, "shell-"):
		// Any interactive-shell TTP marker without an explicit entry above
		// is at least command execution by an engaged attacker.
		return Tag{Techniques: []string{"T1059"}, Tactics: []string{"execution"}}
	case strings.HasPrefix(a, "printer-"):
		// Generic printer/MFP recon + access (fs access, info query, job
		// received, nvram, dmcmd, ipp admin op, lpd command).
		return Tag{Techniques: []string{"T1083"}, Tactics: []string{"discovery"}}
	case a == "automation-client":
		return Tag{Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}}
	case strings.HasPrefix(a, "tool:"):
		// An identified scanning/attack tool — active scanning recon.
		return Tag{Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}}
	case strings.HasPrefix(a, "tcp-"), strings.HasPrefix(a, "ip-"):
		// Any userspace-stack packet anomaly without an explicit entry is
		// at least a crafted scan probe against the IP/TCP layer.
		return Tag{Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}}
	}
	return Tag{}
}

// techDescriptions maps an ATT&CK technique ID to a one-line plain-English
// description, so the UI can explain what a clickable technique chip means.
// Keyed by base technique ID; Describe falls back from a sub-technique
// (e.g. T1110.001) to its base (T1110) on a miss. Covers the techniques the
// honeypot's rule/handler/anomaly tables actually emit.
var techDescriptions = map[string]string{
	// Reconnaissance / discovery.
	"T1595": "Active Scanning — probing the target's infrastructure for live hosts, ports, and weaknesses.",
	"T1590": "Gather Victim Network Information — collecting details about the target's network topology.",
	"T1018": "Remote System Discovery — enumerating other hosts on the network (by IP, ARP, name).",
	"T1046": "Network Service Discovery — port/service scanning to find listening services.",
	"T1083": "File and Directory Discovery — enumerating files and folders on a system.",
	"T1087": "Account Discovery — enumerating valid user/group accounts.",
	"T1135": "Network Share Discovery — listing shared folders/drives (SMB, etc.).",
	"T1016": "System Network Configuration Discovery — reading local network config (interfaces, routes, ARP).",
	"T1012": "Query Registry — reading the Windows registry for configuration/credentials.",
	"T1482": "Domain Trust Discovery — mapping AD domain trust relationships.",
	// Initial access / execution.
	"T1190": "Exploit Public-Facing Application — exploiting a vulnerability in an internet-facing service.",
	"T1133": "External Remote Services — abusing VPN/remote-access services for entry.",
	"T1195": "Supply Chain Compromise — tampering with code/dependencies (e.g. a malicious git push) before delivery.",
	"T1078": "Valid Accounts — authenticating with legitimate (often default/stolen) credentials.",
	"T1059": "Command and Scripting Interpreter — running commands via a shell/interpreter.",
	"T1610": "Deploy Container — abusing a container runtime/API to launch a malicious container.",
	"T1505": "Server Software Component — installing a malicious server module/web shell.",
	// Credential access.
	"T1110": "Brute Force — guessing credentials through repeated authentication attempts.",
	"T1557": "Adversary-in-the-Middle — intercepting/poisoning traffic to capture or relay credentials.",
	"T1558": "Steal or Forge Kerberos Tickets — Kerberoasting / AS-REP roasting / ticket abuse.",
	"T1552": "Unsecured Credentials — harvesting credentials left in files/config/history.",
	"T1003": "OS Credential Dumping — extracting account credentials from the OS (LSASS, SAM, /etc/shadow).",
	"T1212": "Exploitation for Credential Access — exploiting a flaw to obtain credentials.",
	"T1539": "Steal Web Session Cookie — capturing a session token to impersonate a user.",
	// Lateral movement / collection / C2.
	"T1021": "Remote Services — moving laterally over RDP/SMB/SSH/VNC/WinRM.",
	"T1210": "Exploitation of Remote Services — exploiting a remote service to move laterally.",
	"T1213": "Data from Information Repositories — pulling data from a database/repository.",
	"T1114": "Email Collection — accessing mailboxes to collect messages.",
	"T1005": "Data from Local System — collecting files from the compromised host.",
	"T1056": "Input Capture — keylogging/credential-prompt capture.",
	"T1071": "Application Layer Protocol — C2 carried over HTTP/DNS/mail/etc.",
	"T1572": "Protocol Tunneling — encapsulating traffic in another protocol to evade monitoring.",
	"T1095": "Non-Application Layer Protocol — C2 over a non-application protocol (ICMP, raw TCP).",
	"T1219": "Remote Access Software — using legitimate remote-access tools (TeamViewer/AnyDesk) for C2.",
	"T1568": "Dynamic Resolution — DGA/fast-flux to locate C2 infrastructure.",
	"T1090": "Proxy — relaying traffic through an intermediary (e.g. FTP bounce).",
	"T1105": "Ingress Tool Transfer — downloading additional tools/malware onto the host.",
	"T1602": "Data from Configuration Repository — pulling device configs (SNMP/TFTP).",
	// Persistence / privilege escalation / defense evasion.
	"T1098": "Account Manipulation — adding/altering accounts or keys to keep access.",
	"T1136": "Create Account — creating a new account for persistence.",
	"T1053": "Scheduled Task/Job — cron/at/systemd-timer for persistence/execution.",
	"T1543": "Create or Modify System Process — installing a service/daemon for persistence.",
	"T1547": "Boot or Logon Autostart Execution — autostart entry for persistence.",
	"T1548": "Abuse Elevation Control Mechanism — sudo/SUID abuse to escalate privileges.",
	"T1562": "Impair Defenses — disabling AV/firewall/logging.",
	"T1070": "Indicator Removal — clearing logs/history to cover tracks.",
	"T1036": "Masquerading — disguising activity (e.g. a spoofed/impossible User-Agent).",
	"T1027": "Obfuscated Files or Information — encoding/packing payloads to evade detection.",
	"T1140": "Deobfuscate/Decode Files or Information — decoding an obfuscated payload at runtime.",
	"T1218": "System Binary Proxy Execution — living-off-the-land via signed system binaries.",
	"T1564": "Hide Artifacts — concealing files/processes/sessions.",
	"T1601": "Modify System Image — patching device firmware/OS image.",
	// Impact.
	"T1499": "Endpoint Denial of Service — exhausting a service's resources to make it unavailable.",
	"T1498": "Network Denial of Service — flooding the network/link (incl. reflection/amplification).",
	"T1485": "Data Destruction — deleting/wiping data.",
	"T1486": "Data Encrypted for Impact — ransomware-style encryption.",
	"T1491": "Defacement — altering displayed content/messages.",
	"T1496": "Resource Hijacking — abusing compute (e.g. cryptomining).",
	"T1565": "Data Manipulation — tampering with stored/displayed/transmitted data.",
	"T1583": "Acquire Infrastructure — standing up attacker infra (e.g. botnet nodes).",
	"T1020": "Automated Exfiltration — automatically transferring collected data out.",
	"T1041": "Exfiltration Over C2 Channel — sending stolen data back over the C2 channel.",
	"T1048": "Exfiltration Over Alternative Protocol — exfil over a non-C2 protocol.",
	// ICS (ATT&CK for ICS) — control-protocol activity.
	"T0814": "Denial of Service (ICS) — disrupting a control device's availability.",
	"T0888": "Remote System Information Discovery (ICS) — enumerating control devices/their info.",
	"T0830": "Adversary-in-the-Middle (ICS) — intercepting control-network traffic.",
	"T0831": "Manipulation of Control (ICS) — altering the physical control process.",
	"T0836": "Modify Parameter (ICS) — changing a device setpoint/parameter.",
	"T0846": "Remote System Discovery (ICS) — discovering control devices on the segment.",
}

// Describe returns a one-line plain-English description of an ATT&CK
// technique ID (exact match, else its base technique), or "" if unknown.
func Describe(tid string) string {
	if d, ok := techDescriptions[tid]; ok {
		return d
	}
	if i := strings.IndexByte(tid, '.'); i > 0 {
		if d, ok := techDescriptions[tid[:i]]; ok {
			return d
		}
	}
	return ""
}

// Augment unions the ATT&CK metadata implied by an event's anomaly markers
// into a base Tag (from the rule_id/handler lookup). Deduplicated, base
// entries first.
func Augment(base Tag, anomalies []string) Tag {
	tech := append([]string(nil), base.Techniques...)
	tac := append([]string(nil), base.Tactics...)
	seenT, seenTac := toSet(tech), toSet(tac)
	for _, a := range anomalies {
		at := AnomalyTag(a)
		for _, x := range at.Techniques {
			if !seenT[x] {
				seenT[x] = true
				tech = append(tech, x)
			}
		}
		for _, x := range at.Tactics {
			if !seenTac[x] {
				seenTac[x] = true
				tac = append(tac, x)
			}
		}
	}
	return Tag{Techniques: tech, Tactics: tac}
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Tactics returns the canonical list of ATT&CK Enterprise tactics in
// the order we expect to see them in a real attack progression. The
// storyline correlator uses this ordering to detect kill-chain
// transitions.
func Tactics() []string {
	return []string{
		"reconnaissance",
		"resource-development",
		"initial-access",
		"execution",
		"persistence",
		"privilege-escalation",
		"defense-evasion",
		"credential-access",
		"discovery",
		"lateral-movement",
		"collection",
		"command-and-control",
		"exfiltration",
		"impact",
	}
}

// TacticRank returns the position of the tactic in the
// reconnaissance-to-impact ordering, or -1 if unknown. The storyline
// correlator uses this to score "progression" — multiple events from
// a single source whose tactic rank monotonically increases look like
// a directed attack rather than scattered noise.
func TacticRank(t string) int {
	for i, name := range Tactics() {
		if name == t {
			return i
		}
	}
	return -1
}

// d3fend maps an ATT&CK technique (matched by its base id, so
// "T1110.001" inherits "T1110") to the MITRE D3FEND defensive
// countermeasures that address it. Because tarpit-honeypot *is* a
// deception system, the decoy-branch IDs (D3-DE Decoy Environment,
// D3-DNR Decoy Network Resource, D3-DUC Decoy User Credential, D3-DO
// Decoy Object) recur — they're the countermeasure the sensor itself
// implements — alongside the detection/hardening measures a SOC would
// pair with it.
var d3fend = map[string][]string{
	"T1595": {"D3-NTA", "D3-DNR"},          // active scanning
	"T1046": {"D3-NTA", "D3-DNR"},          // network service discovery
	"T1018": {"D3-DNR"},                    // remote system discovery
	"T1083": {"D3-DF", "D3-DO"},            // file & directory discovery
	"T1190": {"D3-NTA", "D3-ITF", "D3-DE"}, // exploit public-facing app
	"T1210": {"D3-NTA", "D3-ITF", "D3-DE"}, // exploit remote services
	"T1110": {"D3-MFA", "D3-DUC", "D3-DE"}, // brute force
	"T1078": {"D3-MFA", "D3-DUC"},          // valid accounts
	"T1021": {"D3-MFA", "D3-NTA"},          // remote services
	"T1071": {"D3-NTA", "D3-DNSTA"},        // application-layer C2
	"T1105": {"D3-NTA", "D3-ITF", "D3-DA"}, // ingress tool transfer
	"T1027": {"D3-DA", "D3-FH"},            // obfuscated files / information
	"T1557": {"D3-NTA"},                    // adversary-in-the-middle
	"T1558": {"D3-MFA", "D3-DUC"},          // steal/forge Kerberos tickets
	"T1498": {"D3-ITF"},                    // network denial of service
	"T1499": {"D3-ITF", "D3-NTA"},          // endpoint denial of service (LAND / sockstress / SACK-panic class)
	"T1135": {"D3-DNR", "D3-DO"},           // network share discovery
	"T1087": {"D3-DUC"},                    // account discovery
	"T1114": {"D3-NTA"},                    // email collection
	"T1610": {"D3-NTA", "D3-ITF"},          // deploy container
	"T0814": {"D3-NTA", "D3-ITF", "D3-DE"}, // ICS: denial of service
	"T0888": {"D3-NTA", "D3-DNR"},          // ICS: remote system info discovery
	"T0846": {"D3-NTA", "D3-DNR"},          // ICS: remote system discovery (PROFINET-DCP)
	"T0830": {"D3-NTA"},                    // ICS: adversary-in-the-middle
	"T0836": {"D3-NTA", "D3-ITF", "D3-DE"}, // ICS: modify parameter
	"T0831": {"D3-NTA", "D3-DE"},           // ICS: manipulation of control
	"T1059": {"D3-NTA", "D3-DA"},           // command & scripting interpreter
	"T1056": {"D3-NTA"},                    // input capture (keylogging via X11)
	"T1219": {"D3-NTA", "D3-OTF"},          // remote access software
	"T1133": {"D3-MFA", "D3-NTA"},          // external remote services
	"T1565": {"D3-NTA", "D3-DE"},           // data manipulation (SNMP SET write)
	"T1590": {"D3-DNSTA", "D3-DNR"},        // gather victim network info (DNS AXFR)
	"T1602": {"D3-NTA", "D3-DE"},           // data from configuration repository (TFTP)
	"T1485": {"D3-NTA", "D3-DE"},           // data destruction (PJL FSINIT format)
	"T1491": {"D3-NTA"},                    // defacement (printer panel message)
	"T1098": {"D3-MFA", "D3-DUC"},          // account manipulation (printer password set)
	"T1552": {"D3-DUC", "D3-NTA"},          // unsecured credentials (printer password read)
	"T1005": {"D3-DO", "D3-NTA"},           // data from local system (PostScript file read)
	"T1601": {"D3-NTA", "D3-DE"},           // modify system image (printer firmware upload)
}

// CoverageEntry is one static rule/handler/anomaly → ATT&CK mapping,
// annotated with the D3FEND countermeasures for its techniques.
type CoverageEntry struct {
	Kind       string // "rule" | "handler" | "anomaly"
	Key        string // rule_id, handler name, or anomaly marker
	Techniques []string
	Tactics    []string
	Defenses   []string // D3FEND countermeasure ids
}

// Coverage flattens every static ATT&CK mapping (exact rules, handler
// tags, anomaly tags) into a single sorted list, each row annotated with
// the D3FEND countermeasures DefensesFor returns for its techniques.
// Used by `tarpit-honeypot list-techniques` so an operator can audit the
// sensor's ATT&CK / D3FEND coverage without reading the source.
func Coverage() []CoverageEntry {
	out := make([]CoverageEntry, 0, len(exactRules)+len(handlerTags)+len(anomalyTags))
	add := func(kind string, m map[string]Tag) {
		for k, t := range m {
			out = append(out, CoverageEntry{
				Kind:       kind,
				Key:        k,
				Techniques: t.Techniques,
				Tactics:    t.Tactics,
				Defenses:   DefensesFor(t.Techniques),
			})
		}
	}
	add("rule", exactRules)
	add("handler", handlerTags)
	add("anomaly", anomalyTags)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// DefensesFor returns the deduplicated set of D3FEND countermeasure IDs
// for a list of ATT&CK techniques (sub-techniques inherit their base
// technique's mapping). The router stamps the result on every event's
// MitreDefenses so a SOC sees "here's the attack, here's the D3FEND
// control that answers it" in one place.
func DefensesFor(techniques []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range techniques {
		base := t
		if i := strings.IndexByte(t, '.'); i > 0 {
			base = t[:i]
		}
		for _, d := range d3fend[base] {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}
