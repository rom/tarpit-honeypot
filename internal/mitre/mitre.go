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
	// A reused honey-credential is the attacker authenticating with a fake
	// secret we handed out — Valid Accounts, near-certain compromise.
	if ruleID == "canary:token_used" {
		return Tag{Techniques: []string{"T1078"}, Tactics: []string{"defense-evasion", "credential-access"}}
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
	"correlate:threat_intel_burst":  {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"correlate:geo_velocity":        {Techniques: []string{"T1110.004"}, Tactics: []string{"credential-access"}},
	"correlate:amplification_probe": {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	"correlate:default_cred_sweep":  {Techniques: []string{"T1110.001", "T1078.001"}, Tactics: []string{"credential-access"}},
	"correlate:cve_campaign":        {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
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
	// Additional opt-in correlators (round 3).
	"correlate:destructive_action": {Techniques: []string{"T1485"}, Tactics: []string{"impact"}},
	"correlate:cloud_cred_theft":   {Techniques: []string{"T1552.005"}, Tactics: []string{"credential-access"}},
	"correlate:ssrf_callback":      {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"correlate:tls_mitm_capture":   {Techniques: []string{"T1557", "T1040"}, Tactics: []string{"credential-access", "collection"}},
	"correlate:fp_rotation":        {Techniques: []string{"T1027"}, Tactics: []string{"defense-evasion"}},
	"correlate:container_takeover": {Techniques: []string{"T1610", "T1611"}, Tactics: []string{"execution", "privilege-escalation"}},
	"correlate:web_attack_probe":   {Techniques: []string{"T1190", "T1595.002"}, Tactics: []string{"initial-access", "reconnaissance"}},
	"correlate:ssh_key_spray":      {Techniques: []string{"T1110.001", "T1078"}, Tactics: []string{"credential-access", "initial-access"}},
	"correlate:spam_relay":         {Techniques: []string{"T1114", "T1087.003"}, Tactics: []string{"collection", "discovery"}},
	"correlate:dns_tunnel":         {Techniques: []string{"T1071.004", "T1048.003"}, Tactics: []string{"command-and-control", "exfiltration"}},
	"correlate:recon_to_exploit":   {Techniques: []string{"T1595", "T1190"}, Tactics: []string{"reconnaissance", "initial-access"}},
	"correlate:honeytoken_spread":  {Techniques: []string{"T1078"}, Tactics: []string{"credential-access"}},
	"correlate:tool_rotation":      {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	// OT/ICS correlators (round 4). ATT&CK for ICS matrix.
	"correlate:plc_program_download": {Techniques: []string{"T0843"}, Tactics: []string{"impact"}},
	"correlate:ics_mode_change":      {Techniques: []string{"T0858"}, Tactics: []string{"impact"}},
	"correlate:ot_kill_chain":        {Techniques: []string{"T0846", "T0831"}, Tactics: []string{"discovery", "impact"}},
	// Remote-access / OOB-management correlators (round 5).
	"correlate:remote_tool_sweep":   {Techniques: []string{"T1219"}, Tactics: []string{"command-and-control"}},
	"correlate:oob_mgmt_access":     {Techniques: []string{"T1190", "T1133"}, Tactics: []string{"initial-access"}},
	"correlate:remote_exec_command": {Techniques: []string{"T1059", "T1021"}, Tactics: []string{"execution", "lateral-movement"}},
	// VoIP / telephony correlators (round 6).
	"correlate:toll_fraud":  {Techniques: []string{"T1657"}, Tactics: []string{"impact"}},
	"correlate:voip_enum":   {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"correlate:pbx_control": {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
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
	// Cross-sensor correlation (internal/fleet) — patterns visible only once
	// events from many sensors converge on an aggregator. Each maps to the
	// underlying attacker behaviour the pattern reveals. The volume-only
	// fleet:rollup / fleet:sensor-untrusted operational events are intentionally
	// left unmapped (no attacker technique).
	"fleet:source-multi-sensor":    {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"fleet:asn-multi-sensor":       {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"fleet:fingerprint-shared":     {Techniques: []string{"T1583.005"}, Tactics: []string{"resource-development"}},
	"fleet:payload-campaign":       {Techniques: []string{"T1105"}, Tactics: []string{"command-and-control"}},
	"fleet:credential-campaign":    {Techniques: []string{"T1110.004"}, Tactics: []string{"credential-access"}},
	"fleet:cve-wave":               {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"fleet:subnet-coordinated":     {Techniques: []string{"T1595", "T1583.005"}, Tactics: []string{"reconnaissance", "resource-development"}},
	"fleet:outlier-sensor":         {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"fleet:scan-trajectory":        {Techniques: []string{"T1595.001", "T1046"}, Tactics: []string{"reconnaissance", "discovery"}},
	"fleet:synchronized-burst":     {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"fleet:first-fleet-contact":    {Techniques: []string{"T1583"}, Tactics: []string{"resource-development"}},
	"fleet:identity-pivot":         {Techniques: []string{"T1583.005"}, Tactics: []string{"resource-development"}},
	"fleet:geo-distributed-actor":  {Techniques: []string{"T1583.005"}, Tactics: []string{"resource-development"}},
	"fleet:target-profile-match":   {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"fleet:honeytoken-spread":      {Techniques: []string{"T1078"}, Tactics: []string{"credential-access"}},
	"fleet:cve-emergence":          {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"fleet:cross-protocol-actor":   {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"fleet:fingerprint-asn-spread": {Techniques: []string{"T1583.005"}, Tactics: []string{"resource-development"}},
	"fleet:threat-intel-surge":     {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"fleet:tool-campaign":          {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"fleet:c2-shared":              {Techniques: []string{"T1071"}, Tactics: []string{"command-and-control"}},
	"fleet:user-agent-shared":      {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"fleet:tactic-convergence":     {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"fleet:recidivist-network":     {Techniques: []string{"T1583"}, Tactics: []string{"resource-development"}},
	"fleet:port-campaign":          {Techniques: []string{"T1046", "T1595"}, Tactics: []string{"discovery", "reconnaissance"}},
	"fleet:credential-spray-fleet": {Techniques: []string{"T1110"}, Tactics: []string{"credential-access"}},
	"fleet:asn-org-campaign":       {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	// The egress allowlist refused an outbound dial from a handler — an
	// attempted SSRF / relay / exfil / C2 channel through the decoy.
	"egress:denied": {Techniques: []string{"T1090", "T1071"}, Tactics: []string{"command-and-control"}},
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
	"http":          {Techniques: []string{"T1190", "T1083"}, Tactics: []string{"initial-access", "discovery"}},
	"https":         {Techniques: []string{"T1190", "T1083"}, Tactics: []string{"initial-access", "discovery"}},
	"tls_intercept": {Techniques: []string{"T1557", "T1040"}, Tactics: []string{"credential-access", "collection"}},
	"rtsp":          {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"dockerapi":     {Techniques: []string{"T1190", "T1610"}, Tactics: []string{"initial-access", "execution"}},
	// Cloud-native / container attack surface.
	"cloud_metadata": {Techniques: []string{"T1552.005", "T1078.004"}, Tactics: []string{"credential-access", "defense-evasion"}},
	"etcd":           {Techniques: []string{"T1190", "T1552.007"}, Tactics: []string{"initial-access", "credential-access"}},
	"websocket":      {Techniques: []string{"T1190", "T1071.001"}, Tactics: []string{"initial-access", "command-and-control"}},
	"grpc":           {Techniques: []string{"T1190", "T1071"}, Tactics: []string{"initial-access", "command-and-control"}},
	"ssrf_canary":    {Techniques: []string{"T1190", "T1602"}, Tactics: []string{"initial-access", "collection"}},
	"kubernetes_api": {Techniques: []string{"T1190", "T1552.007"}, Tactics: []string{"initial-access", "credential-access"}},
	"vault":          {Techniques: []string{"T1190", "T1555"}, Tactics: []string{"initial-access", "credential-access"}},
	"ipp":            {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},

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
	"dtls":           {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"quic":           {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"netflow":        {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"sflow":          {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
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
	// Cobalt Strike default checksum8 beacon-staging URI.
	"cobaltstrike-stager": {Techniques: []string{"T1105", "T1071.001"}, Tactics: []string{"command-and-control"}},
	// Siemens SIPROTEC EN100 DoS packet (CVE-2015-5374) + CLDAP Netlogon
	// buffer-overflow (CVE-2026-41089) — both crash the target service.
	"siprotec-en100-dos":      {Techniques: []string{"T1499"}, Tactics: []string{"impact"}},
	"cldap-netlogon-overflow": {Techniques: []string{"T1499"}, Tactics: []string{"impact"}},
	// vsftpd 2.3.2 recursive-glob CPU-exhaustion DoS.
	"ftp-glob-dos": {Techniques: []string{"T1499.004"}, Tactics: []string{"impact"}},
	// A headless-browser automation driver (Selenium / Puppeteer / headless
	// Chrome / PhantomJS) — scripted recon, not a real user.
	"headless-browser":     {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"modbus-write-attempt": {Techniques: []string{"T0836", "T0831"}, Tactics: []string{"impact"}},

	// --- New-protocol coverage: amplification, ICS/IIoT control, building
	// automation, IoT actuation, and the discovery/credential markers the
	// added UDP handlers + deepened protocols raise. ICS uses the ATT&CK for
	// ICS (T0###) matrix; the rest use Enterprise techniques.
	//
	// UDP reflection/amplification probes (slp, memcached, natpmp, ubiquiti,
	// steam, sentinel_hasp, enip ListIdentity, ssdp:all, dns ANY, classic STUN,
	// mssql broadcast, coap discovery): Network DoS — Reflection Amplification.
	"amplification-probe":        {Techniques: []string{"T1498.002", "T1046"}, Tactics: []string{"impact", "discovery"}},
	"ssdp-all-amplification":     {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	"dns-any-amplification":      {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	"stun-classic-amplification": {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	"coap-resource-discovery":    {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	// Service / device discovery.
	"service-enumeration":     {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"device-discovery-probe":  {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"remote-desktop-probe":    {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"ics-device-enumeration":  {Techniques: []string{"T0846"}, Tactics: []string{"discovery"}},
	"ics-field-device-probe":  {Techniques: []string{"T0888"}, Tactics: []string{"discovery"}},
	"ics-data-bus-discovery":  {Techniques: []string{"T0846"}, Tactics: []string{"discovery"}},
	"ics-process-data-access": {Techniques: []string{"T0801"}, Tactics: []string{"collection"}},
	// ICS control / manipulation (impact).
	"ics-modbus-write":                   {Techniques: []string{"T0836", "T0831"}, Tactics: []string{"impact"}},
	"ics-modbus-diagnostic":              {Techniques: []string{"T0814"}, Tactics: []string{"impact"}},
	"ics-plc-write":                      {Techniques: []string{"T0836", "T0831"}, Tactics: []string{"impact"}},
	"ics-plc-mode-change":                {Techniques: []string{"T0858"}, Tactics: []string{"impact"}},
	"ics-plc-program-access":             {Techniques: []string{"T0843"}, Tactics: []string{"lateral-movement"}},
	"ics-dnp3-control":                   {Techniques: []string{"T0855"}, Tactics: []string{"impact"}},
	"ics-saia-control":                   {Techniques: []string{"T0855", "T0836"}, Tactics: []string{"impact"}},
	"ics-unitronics-plc":                 {Techniques: []string{"T0855"}, Tactics: []string{"impact"}},
	"ics-pmu-command":                    {Techniques: []string{"T0855"}, Tactics: []string{"impact"}},
	"ics-safety-controller-manipulation": {Techniques: []string{"T0831", "T0880"}, Tactics: []string{"impact"}},
	"profinet-iod-write":                 {Techniques: []string{"T0836"}, Tactics: []string{"impact"}},
	"profinet-iod-control":               {Techniques: []string{"T0855"}, Tactics: []string{"impact"}},
	"knx-bus-write":                      {Techniques: []string{"T0831"}, Tactics: []string{"impact"}},
	// IoT actuation + building automation control.
	"iot-actuation-attempt": {Techniques: []string{"T0831"}, Tactics: []string{"impact"}},
	"iot-mqtt-sn-publish":   {Techniques: []string{"T1071"}, Tactics: []string{"command-and-control"}},
	"ba-lighting-control":   {Techniques: []string{"T0831"}, Tactics: []string{"impact"}},
	"ba-projector-control":  {Techniques: []string{"T0831"}, Tactics: []string{"impact"}},
	"ba-building-control":   {Techniques: []string{"T0831"}, Tactics: []string{"impact"}},
	"ba-av-control-probe":   {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	// Routing / name-service abuse.
	"routing-recon":              {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"rip-route-injection":        {Techniques: []string{"T1557"}, Tactics: []string{"collection"}},
	"nbns-name-poisoning-target": {Techniques: []string{"T1557.001"}, Tactics: []string{"credential-access", "collection"}},
	"mdns-remote-access-recon":   {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	// Credential-bearing protocols.
	"kerberos-pre-auth-probe": {Techniques: []string{"T1558.004"}, Tactics: []string{"credential-access"}},
	"ike-aggressive-mode":     {Techniques: []string{"T1110"}, Tactics: []string{"credential-access"}},
	"radius-auth-attempt":     {Techniques: []string{"T1110"}, Tactics: []string{"credential-access"}},
	"radius-eap-auth":         {Techniques: []string{"T1110"}, Tactics: []string{"credential-access"}},
	// SNMP SetRequest = write the device's running config (ACL / interface
	// / config-copy-to-tftp). Manipulation on enterprise gear, modify-
	// parameter on the ICS archetypes that also speak SNMP.
	"snmp-set-attempt": {Techniques: []string{"T1565.001", "T0836"}, Tactics: []string{"impact"}},
	// A source walking the SNMP MIB faster than the configured rate =
	// network/device enumeration via SNMP.
	"snmp-walk-rate-exceeded": {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	// GetBulk with a huge max-repetitions = amplification primitive / bulk exfil.
	"snmp-getbulk-amplification": {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	// Default community ("public"/"private") = a weak/guessed credential.
	"snmp-default-community": {Techniques: []string{"T1078.001"}, Tactics: []string{"credential-access", "defense-evasion"}},
	// SNMP CISCO-CONFIG-COPY-MIB access = exfiltrate/overwrite the running config.
	"snmp-config-exfil":     {Techniques: []string{"T1602.001"}, Tactics: []string{"collection"}},
	"smtp-open-relay-probe": {Techniques: []string{"T1071.003"}, Tactics: []string{"command-and-control"}},
	"smtp-user-enumeration": {Techniques: []string{"T1087"}, Tactics: []string{"discovery"}},
	// DNS zone-transfer (AXFR/IXFR) = bulk enumeration of internal hosts.
	"dns-zone-transfer": {Techniques: []string{"T1590.002", "T1018"}, Tactics: []string{"reconnaissance", "discovery"}},
	// Encrypted-DNS channels (DoH / DoT / DNSCrypt) = DNS tunnelled inside
	// HTTPS/TLS/DNSCrypt to evade plaintext DNS monitoring.
	"dns-over-https": {Techniques: []string{"T1572", "T1071.004"}, Tactics: []string{"command-and-control"}},
	"dns-over-tls":   {Techniques: []string{"T1572", "T1071.004"}, Tactics: []string{"command-and-control"}},
	"dnscrypt-probe": {Techniques: []string{"T1572", "T1071.004"}, Tactics: []string{"command-and-control"}},
	// Algorithmically-generated C2 rendezvous domain.
	"dns-dga-suspected": {Techniques: []string{"T1568.002"}, Tactics: []string{"command-and-control"}},
	// --- DNS vulnerability / leakage / recon / poisoning / DoS detections ---
	// Header / opcode / section-count abuse: reflected responses + carried
	// answer/authority/additional RRs are cache-poisoning shapes; IQUERY /
	// NOTIFY / UPDATE are unexpected opcodes against a recursive resolver.
	"dns-response-as-query":   {Techniques: []string{"T1557"}, Tactics: []string{"credential-access", "collection"}},
	"dns-prestuffed-answers":  {Techniques: []string{"T1557"}, Tactics: []string{"credential-access", "collection"}},
	"dns-additional-stuffing": {Techniques: []string{"T1557"}, Tactics: []string{"credential-access", "collection"}},
	"dns-inverse-query":       {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"dns-notify-opcode":       {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"dns-dynamic-update":      {Techniques: []string{"T1565.001"}, Tactics: []string{"impact"}},
	"dns-multi-question":      {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"dns-nonstandard-class":   {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	// Server-identity / DNSSEC / service-binding recon + internal-name leakage.
	"dns-chaos-class":       {Techniques: []string{"T1590.002"}, Tactics: []string{"reconnaissance"}},
	"dns-dnssec-recon":      {Techniques: []string{"T1590.002"}, Tactics: []string{"reconnaissance"}},
	"dns-nsec-walk":         {Techniques: []string{"T1590.002"}, Tactics: []string{"reconnaissance"}},
	"dns-svcb-probe":        {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"dns-caa-probe":         {Techniques: []string{"T1590.002"}, Tactics: []string{"reconnaissance"}},
	"dns-mail-policy-probe": {Techniques: []string{"T1590.002"}, Tactics: []string{"reconnaissance"}},
	"dns-srv-ad-discovery":  {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
	"dns-ptr-reverse-sweep": {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"dns-internal-tld-leak": {Techniques: []string{"T1590.002"}, Tactics: []string{"reconnaissance"}},
	// Name-resolution MITM bait.
	"dns-wpad-probe":   {Techniques: []string{"T1557"}, Tactics: []string{"credential-access", "collection"}},
	"dns-isatap-probe": {Techniques: []string{"T1557"}, Tactics: []string{"credential-access", "collection"}},
	// Out-of-band interaction / DNS rebinding.
	"dns-oob-interaction": {Techniques: []string{"T1048"}, Tactics: []string{"exfiltration"}},
	"dns-rebind-lookup":   {Techniques: []string{"T1071.004"}, Tactics: []string{"command-and-control"}},
	// Tunnelling / exfil structure.
	"dns-cname-tunnel":       {Techniques: []string{"T1572", "T1071.004"}, Tactics: []string{"command-and-control"}},
	"dns-null-record":        {Techniques: []string{"T1572", "T1071.004"}, Tactics: []string{"command-and-control"}},
	"dns-long-encoded-label": {Techniques: []string{"T1048"}, Tactics: []string{"exfiltration"}},
	"dns-many-labels":        {Techniques: []string{"T1048"}, Tactics: []string{"exfiltration"}},
	// DoS (water-torture / parser stress) + amplification setup.
	"dns-random-subdomain":     {Techniques: []string{"T1499"}, Tactics: []string{"impact"}},
	"dns-repeated-label":       {Techniques: []string{"T1499"}, Tactics: []string{"impact"}},
	"dns-edns-large-udpsize":   {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	"dns-edns-version-nonzero": {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"dns-dnssec-amplification": {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
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
	"webapp:sqli":                  {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"webapp:lfi":                   {Techniques: []string{"T1190", "T1083"}, Tactics: []string{"initial-access", "discovery"}},
	"webapp:rfi_ssrf":              {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"webapp:xss":                   {Techniques: []string{"T1059.007"}, Tactics: []string{"execution"}},
	"webapp:cmdi":                  {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"webapp:ssti":                  {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"webapp:log4shell":             {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"webapp:xxe":                   {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"webapp:nosqli":                {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"webapp:graphql-introspection": {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"webapp:jwt-none":              {Techniques: []string{"T1078"}, Tactics: []string{"defense-evasion"}},
	"webapp:deserialize":           {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"webapp:secret-file-probe":     {Techniques: []string{"T1083"}, Tactics: []string{"discovery"}},
	// Exposed management / diagnostic / debug endpoints (info disclosure; the
	// actuator/jolokia/tomcat-manager ones are RCE footholds).
	"webapp:apache-status-exposed":     {Techniques: []string{"T1592"}, Tactics: []string{"reconnaissance"}},
	"webapp:apache-info-exposed":       {Techniques: []string{"T1592"}, Tactics: []string{"reconnaissance"}},
	"webapp:metrics-exposed":           {Techniques: []string{"T1592"}, Tactics: []string{"reconnaissance"}},
	"webapp:pprof-exposed":             {Techniques: []string{"T1592"}, Tactics: []string{"reconnaissance"}},
	"webapp:symfony-profiler-exposed":  {Techniques: []string{"T1592", "T1552"}, Tactics: []string{"reconnaissance", "credential-access"}},
	"webapp:laravel-telescope-exposed": {Techniques: []string{"T1592", "T1552"}, Tactics: []string{"reconnaissance", "credential-access"}},
	"webapp:spring-actuator-exposed":   {Techniques: []string{"T1190", "T1552"}, Tactics: []string{"initial-access", "credential-access"}},
	"webapp:jolokia-exposed":           {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"webapp:solr-admin-exposed":        {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"webapp:tomcat-manager-probe":      {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
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
	"shell-container-escape":       {Techniques: []string{"T1611"}, Tactics: []string{"privilege-escalation"}},
	"shell-cloud-cred-theft":       {Techniques: []string{"T1552.005"}, Tactics: []string{"credential-access"}},
	"shell-local-exploit":          {Techniques: []string{"T1068"}, Tactics: []string{"privilege-escalation"}},
	"shell-data-staged":            {Techniques: []string{"T1560.001"}, Tactics: []string{"collection"}},
	"shell-exfil-channel":          {Techniques: []string{"T1048"}, Tactics: []string{"exfiltration"}},
	"shell-decode-pipe-exec":       {Techniques: []string{"T1140"}, Tactics: []string{"defense-evasion"}},
	"shell-destruction":            {Techniques: []string{"T1485", "T1486"}, Tactics: []string{"impact"}},
	// Web-shell access / command execution (http handler webshell detector).
	"webshell-access-attempt": {Techniques: []string{"T1505.003"}, Tactics: []string{"persistence"}},
	"webshell-command":        {Techniques: []string{"T1505.003", "T1059"}, Tactics: []string{"persistence", "execution"}},
	// Login-form / auth submissions on services whose handler base tag isn't
	// already credential-access.
	"http-login-attempt":  {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"mssql-login-attempt": {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	// SFTP / SCP over SSH: browsing the filesystem is discovery; an scp/sftp
	// upload is ingress tool transfer; a download is exfil.
	"sftp-session":         {Techniques: []string{"T1083"}, Tactics: []string{"discovery"}},
	"scp-transfer":         {Techniques: []string{"T1105"}, Tactics: []string{"command-and-control"}},
	"scp-upload":           {Techniques: []string{"T1105"}, Tactics: []string{"command-and-control"}},
	"scp-upload-attempt":   {Techniques: []string{"T1105"}, Tactics: []string{"command-and-control"}},
	"scp-download-attempt": {Techniques: []string{"T1048"}, Tactics: []string{"exfiltration"}},
	// Honeytoken account (security.txt contact) reused as a login name — the
	// attacker scraped our published security contacts and sprayed them.
	"honeytoken:account-login": {Techniques: []string{"T1078"}, Tactics: []string{"initial-access"}},
	// Probing the bait paths advertised in robots.txt / sitemap.xml — content
	// discovery against deliberately-tempting hidden directories/files.
	"robots-honeypot-access":  {Techniques: []string{"T1595.003", "T1083"}, Tactics: []string{"reconnaissance", "discovery"}},
	"sitemap-honeypot-access": {Techniques: []string{"T1595.003"}, Tactics: []string{"reconnaissance"}},
	// Bare service probes + malformed / non-conforming protocol input — the
	// shape of an automated scanner banner-grabbing a port.
	"oracle-tns-probe":     {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"nx-probe":             {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"openvpn-probe":        {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"ssh-id-non-printable": {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"ssh-id-not-ssh":       {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"ssh-id-overlong":      {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	// CVE-2016-0777/0778: a vulnerable OpenSSH client's roaming feature lets a
	// malicious server steal the client's private key (the honeypot sets the trap).
	"ssh-roaming-vulnerable-client":   {Techniques: []string{"T1552"}, Tactics: []string{"credential-access"}},
	"ssh-roaming-offered":             {Techniques: []string{"T1552"}, Tactics: []string{"credential-access"}},
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
	// Cloud metadata / etcd — stealing IAM creds or cluster secrets.
	"cloud-credential-theft": {Techniques: []string{"T1552.005"}, Tactics: []string{"credential-access"}},
	"etcd-secret-read":       {Techniques: []string{"T1552.007"}, Tactics: []string{"credential-access"}},
	"etcd-range-read":        {Techniques: []string{"T1213"}, Tactics: []string{"collection"}},
	"etcd-write":             {Techniques: []string{"T1565.001"}, Tactics: []string{"impact"}},
	// WebSocket / gRPC probe surface.
	"ws-credential-material": {Techniques: []string{"T1552"}, Tactics: []string{"credential-access"}},
	"ws-command-payload":     {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"grpc-reflection-probe":  {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	// SSRF out-of-band callback collector.
	"ssrf-callback":          {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"ssrf-server-side-fetch": {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	// Kubernetes API server abuse.
	"k8s-token-auth":  {Techniques: []string{"T1528"}, Tactics: []string{"credential-access"}},
	"k8s-secret-enum": {Techniques: []string{"T1552.007"}, Tactics: []string{"credential-access"}},
	"k8s-pod-create":  {Techniques: []string{"T1610"}, Tactics: []string{"execution"}},
	"k8s-pod-exec":    {Techniques: []string{"T1609"}, Tactics: []string{"execution"}},
	// HashiCorp Vault abuse.
	"vault-token-auth":    {Techniques: []string{"T1528"}, Tactics: []string{"credential-access"}},
	"vault-secret-read":   {Techniques: []string{"T1555"}, Tactics: []string{"credential-access"}},
	"vault-mount-enum":    {Techniques: []string{"T1555"}, Tactics: []string{"credential-access"}},
	"vault-policy-access": {Techniques: []string{"T1555"}, Tactics: []string{"credential-access"}},
	"vault-seal-control":  {Techniques: []string{"T1485"}, Tactics: []string{"impact"}},
	// CoAP write to an IoT resource = manipulation of a device value.
	"coap-write-attempt": {Techniques: []string{"T1565"}, Tactics: []string{"impact"}},
	// Flow-export records received = network-topology reconnaissance leak.
	"netflow-export-received": {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"sflow-export-received":   {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"quic-initial":            {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"dtls-probe":              {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"dtls-malformed":          {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	// tls_intercept (decrypt-and-forward MITM) surfacing an attack that TLS hid.
	"tls-decrypted-exploit":     {Techniques: []string{"T1190", "T1557"}, Tactics: []string{"initial-access", "credential-access"}},
	"tls-decrypted-credentials": {Techniques: []string{"T1040", "T1557"}, Tactics: []string{"credential-access", "collection"}},
	// NTP mode-6/7 control queries + monlist = reflection-amplification recon.
	"ntp-control-query":         {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	"ntp-monlist-amplification": {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	"ntp-mode7-private":         {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	"ntp-nonclient-mode":        {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	// DNS SIG / TKEY exploit-probe qtypes (SIGRed / BIND TKEY DoS).
	"dns-sig-query":  {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"dns-tkey-query": {Techniques: []string{"T1499"}, Tactics: []string{"impact"}},
	// IBM MQ channel recon + MQCSP credential flow.
	"ibmmq-connect":       {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"ibmmq-security-flow": {Techniques: []string{"T1110"}, Tactics: []string{"credential-access"}},
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
	// Round-two data-infra / VPN / RPC decoys (devsvc2.go).
	"cassandra-probe":        {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"cassandra-auth-attempt": {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"nats-connect":           {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"nats-publish":           {Techniques: []string{"T1565"}, Tactics: []string{"impact"}},
	"rpcbind-query":          {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"rpcbind-dump":           {Techniques: []string{"T1135"}, Tactics: []string{"discovery"}},
	"rpcbind-getport":        {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"pptp-probe":             {Techniques: []string{"T1133"}, Tactics: []string{"initial-access"}},
	"stun-binding":           {Techniques: []string{"T1016"}, Tactics: []string{"discovery"}},
	// Round-three IoT / app-server / cluster / AAA / DB decoys (devsvc3.go).
	// An exposed ADB daemon is unauthenticated RCE (OPEN shell: is the exec
	// step); AJP forward-request is the Ghostcat carrier; epmd enumerates
	// Erlang cluster nodes; TACACS+ is the network-gear credential gate; the
	// SQL Browser enumerates SQL Server instances.
	"adb-connect":         {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"adb-shell-open":      {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"adb-auth":            {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"ajp-probe":           {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"ajp-forward-request": {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"epmd-query":          {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"epmd-names":          {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
	"tacacs-probe":        {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"tacacs-auth-start":   {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"mssql-browser-query": {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	// Round-four OT/ICS decoys (icsdecoys.go) — ATT&CK for ICS. Omron FINS/TCP,
	// SEMI HSMS/SECS-GEM, Unitronics PCOM, PROFINET-IO, VxWorks WDB.
	"fins-tcp-probe":         {Techniques: []string{"T0888"}, Tactics: []string{"discovery"}},
	"fins-tcp-write-attempt": {Techniques: []string{"T0836"}, Tactics: []string{"impact"}},
	"fins-run-mode-change":   {Techniques: []string{"T0858"}, Tactics: []string{"impact"}},
	"fins-program-download":  {Techniques: []string{"T0843"}, Tactics: []string{"impact"}},
	"secs-probe":             {Techniques: []string{"T0888"}, Tactics: []string{"discovery"}},
	"secs-program-send":      {Techniques: []string{"T0843"}, Tactics: []string{"impact"}},
	"secs-remote-command":    {Techniques: []string{"T0855"}, Tactics: []string{"impact"}},
	"pcom-probe":             {Techniques: []string{"T0888"}, Tactics: []string{"discovery"}},
	"pcom-write-attempt":     {Techniques: []string{"T0836"}, Tactics: []string{"impact"}},
	"pcom-mode-change":       {Techniques: []string{"T0858"}, Tactics: []string{"impact"}},
	"pcom-program-download":  {Techniques: []string{"T0843"}, Tactics: []string{"impact"}},
	"profinet-io-probe":      {Techniques: []string{"T0846"}, Tactics: []string{"discovery"}},
	"profinet-connect":       {Techniques: []string{"T0846"}, Tactics: []string{"discovery"}},
	"wdbrpc-probe":           {Techniques: []string{"T0846"}, Tactics: []string{"discovery"}},
	"wdbrpc-connect":         {Techniques: []string{"T0866"}, Tactics: []string{"lateral-movement"}},
	// Round-five remote-access / OOB-management decoys (remoteoob.go).
	"rexec-attempt":    {Techniques: []string{"T1021"}, Tactics: []string{"lateral-movement"}},
	"rexec-command":    {Techniques: []string{"T1059", "T1021"}, Tactics: []string{"execution", "lateral-movement"}},
	"rsh-attempt":      {Techniques: []string{"T1021"}, Tactics: []string{"lateral-movement"}},
	"rsh-command":      {Techniques: []string{"T1059", "T1021"}, Tactics: []string{"execution", "lateral-movement"}},
	"pcanywhere-probe": {Techniques: []string{"T1219"}, Tactics: []string{"command-and-control"}},
	"radmin-probe":     {Techniques: []string{"T1219"}, Tactics: []string{"command-and-control"}},
	"dameware-probe":   {Techniques: []string{"T1219"}, Tactics: []string{"command-and-control"}},
	"ard-probe":        {Techniques: []string{"T1219"}, Tactics: []string{"command-and-control"}},
	"pcoip-probe":      {Techniques: []string{"T1021"}, Tactics: []string{"lateral-movement"}},
	"spice-probe":      {Techniques: []string{"T1021"}, Tactics: []string{"lateral-movement"}},
	"lantronix-probe":  {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"tn3270-probe":     {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	// Round-six VoIP / telephony decoys (voip.go).
	"sip-options-scan": {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"sip-auth-attempt": {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"sccp-probe":       {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"sccp-register":    {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"h323-probe":       {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"h323-setup":       {Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}},
	"ami-login":        {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"ami-command":      {Techniques: []string{"T1059"}, Tactics: []string{"execution"}},
	"ami-originate":    {Techniques: []string{"T1657"}, Tactics: []string{"impact"}},
	"iax2-probe":       {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
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

// luaMarkerTag classifies a Lua-emulation flag (the part after "lua:") by the
// action its suffix names, so the 80+ dynamic service scripts contribute ATT&CK
// coverage uniformly. Checked most-severe first; falls back to a generic
// application-probe recon tag.
func luaMarkerTag(m string) Tag {
	switch {
	case strings.Contains(m, "rce") || strings.Contains(m, "code-injection") ||
		strings.Contains(m, "command-exec") || strings.Contains(m, "cmd-exec"):
		return Tag{Techniques: []string{"T1190", "T1059"}, Tactics: []string{"initial-access", "execution"}}
	case strings.Contains(m, "setup-token-abuse") || strings.Contains(m, "setup-bypass") ||
		strings.Contains(m, "auth-bypass") || strings.Contains(m, "config-push"):
		return Tag{Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}}
	case strings.Contains(m, "path-traversal"):
		return Tag{Techniques: []string{"T1190", "T1083"}, Tactics: []string{"initial-access", "discovery"}}
	case strings.Contains(m, "ssrf"):
		return Tag{Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}}
	case strings.Contains(m, "sqli"):
		return Tag{Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}}
	case strings.Contains(m, "token") || strings.Contains(m, "session-replay"):
		// A presented/replayed API token or session — use of (possibly stolen)
		// valid credentials.
		return Tag{Techniques: []string{"T1078", "T1528"}, Tactics: []string{"defense-evasion", "credential-access"}}
	case strings.Contains(m, "login-attempt") || strings.Contains(m, "auth-attempt") ||
		strings.Contains(m, "credential"):
		return Tag{Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}}
	case strings.Contains(m, "inference-abuse") || strings.Contains(m, "model-transfer"):
		// Abuse of an exposed AI/compute service.
		return Tag{Techniques: []string{"T1496"}, Tactics: []string{"impact"}}
	case strings.Contains(m, "flow-deploy"):
		return Tag{Techniques: []string{"T1059"}, Tactics: []string{"execution"}}
	case strings.Contains(m, "enum") || strings.Contains(m, "recon") ||
		strings.Contains(m, "probe") || strings.Contains(m, "unauth-access") ||
		strings.Contains(m, "resource-access") || strings.Contains(m, "model-enum"):
		return Tag{Techniques: []string{"T1046"}, Tactics: []string{"discovery"}}
	}
	// Any other lua marker is at least an application probe.
	return Tag{Techniques: []string{"T1592"}, Tactics: []string{"reconnaissance"}}
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
	case strings.HasPrefix(a, "ba-"):
		// Building-automation markers without an explicit entry: at least a
		// control-system probe of the BMS / AV / lighting surface.
		return Tag{Techniques: []string{"T1046"}, Tactics: []string{"discovery"}}
	case strings.HasPrefix(a, "iot-"):
		// IoT smart-device markers: device enumeration / LAN-protocol probe.
		return Tag{Techniques: []string{"T1046"}, Tactics: []string{"discovery"}}
	case strings.Contains(a, "amplification"):
		// Any reflection/amplification probe family: Network DoS.
		return Tag{Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}}
	case strings.HasPrefix(a, "overlay-"), strings.Contains(a, "tunnel"):
		// Overlay (VXLAN/Geneve) injection or tunnelling-protocol probe.
		return Tag{Techniques: []string{"T1572"}, Tactics: []string{"command-and-control"}}
	case strings.HasPrefix(a, "mobile-core-"), strings.HasPrefix(a, "network-infra"), strings.HasPrefix(a, "wccp"), strings.HasPrefix(a, "bfd"):
		// Mobile-core (GTP) / routing / infrastructure protocol reconnaissance.
		return Tag{Techniques: []string{"T1046"}, Tactics: []string{"discovery"}}
	case strings.HasPrefix(a, "webapp:"):
		// Any web-attack-class marker without an explicit entry above is at
		// least an exploit attempt against the public-facing app.
		return Tag{Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}}
	case strings.HasPrefix(a, "lua:"):
		// Markers raised by the dynamic Lua service emulations. Classify by the
		// action the suffix describes so an operator's custom service still
		// contributes ATT&CK coverage without a per-marker entry.
		return luaMarkerTag(strings.TrimPrefix(a, "lua:"))
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
	"T1592": "Gather Victim Host Information — collecting software/version/config detail about an exposed service.",
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
	"T1555": "Credentials from Password Stores — reading a secret store / vault (HashiCorp Vault, KV engines).",
	"T1528": "Steal Application Access Token — capturing a bearer / service-account token.",
	"T1609": "Container Administration Command — abusing a container/cluster admin API to run a command (kubectl exec).",
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
	"T1499":     "Endpoint Denial of Service — exhausting a service's resources to make it unavailable.",
	"T1498":     "Network Denial of Service — flooding the network/link (incl. reflection/amplification).",
	"T1485":     "Data Destruction — deleting/wiping data.",
	"T1486":     "Data Encrypted for Impact — ransomware-style encryption.",
	"T1491":     "Defacement — altering displayed content/messages.",
	"T1496":     "Resource Hijacking — abusing compute (e.g. cryptomining).",
	"T1657":     "Financial Theft — monetizing access directly (e.g. VoIP toll fraud, fraudulent transactions).",
	"T1565":     "Data Manipulation — tampering with stored/displayed/transmitted data.",
	"T1583":     "Acquire Infrastructure — standing up or renting attacker infra (botnet nodes, domains, ASNs) used across a campaign.",
	"T1020":     "Automated Exfiltration — automatically transferring collected data out.",
	"T1041":     "Exfiltration Over C2 Channel — sending stolen data back over the C2 channel.",
	"T1048":     "Exfiltration Over Alternative Protocol — exfil over a non-C2 protocol.",
	"T1611":     "Escape to Host — breaking out of a container to the underlying host.",
	"T1068":     "Exploitation for Privilege Escalation — a kernel/local exploit to gain higher privileges.",
	"T1560.001": "Archive Collected Data via Utility — staging data into an archive (tar/zip/7z) before exfil.",
	// ICS (ATT&CK for ICS) — control-protocol activity.
	"T0814": "Denial of Service (ICS) — disrupting a control device's availability.",
	"T0888": "Remote System Information Discovery (ICS) — enumerating control devices/their info.",
	"T0830": "Adversary-in-the-Middle (ICS) — intercepting control-network traffic.",
	"T0831": "Manipulation of Control (ICS) — altering the physical control process.",
	"T0836": "Modify Parameter (ICS) — changing a device setpoint/parameter.",
	"T0846": "Remote System Discovery (ICS) — discovering control devices on the segment.",
	"T0843": "Program Download (ICS) — downloading new logic/firmware to a controller.",
	"T0858": "Change Operating Mode (ICS) — switching a controller's RUN/STOP/PROGRAM mode.",
	"T0855": "Unauthorized Command Message (ICS) — sending an unauthorized control command.",
	"T0801": "Monitor Process State (ICS) — reading the live process image / I/O of a controller.",
	"T0880": "Loss of Safety (ICS) — defeating or manipulating a safety-instrumented function.",
	"T0866": "Exploitation of Remote Services (ICS) — exploiting a remote service to reach control devices.",
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
	"T1595": {"D3-NTA", "D3-DNR", "D3-CAA"},         // active scanning
	"T1592": {"D3-NTA", "D3-DNR"},                   // gather victim host information
	"T1046": {"D3-NTA", "D3-DNR", "D3-CAA"},         // network service discovery
	"T1018": {"D3-DNR"},                             // remote system discovery
	"T1083": {"D3-DF", "D3-DO"},                     // file & directory discovery
	"T1190": {"D3-NTA", "D3-ITF", "D3-DE"},          // exploit public-facing app
	"T1210": {"D3-NTA", "D3-ITF", "D3-DE"},          // exploit remote services
	"T1110": {"D3-MFA", "D3-DUC", "D3-DE", "D3-CH"}, // brute force
	"T1078": {"D3-MFA", "D3-DUC", "D3-CH"},          // valid accounts
	"T1021": {"D3-MFA", "D3-NTA", "D3-RTSD"},        // remote services
	"T1071": {"D3-NTA", "D3-DNSTA"},                 // application-layer C2
	"T1105": {"D3-NTA", "D3-ITF", "D3-DA"},          // ingress tool transfer
	"T1027": {"D3-DA", "D3-FH"},                     // obfuscated files / information
	"T1557": {"D3-NTA"},                             // adversary-in-the-middle
	"T1558": {"D3-MFA", "D3-DUC"},                   // steal/forge Kerberos tickets
	"T1498": {"D3-ITF"},                             // network denial of service
	"T1499": {"D3-ITF", "D3-NTA"},                   // endpoint denial of service (LAND / sockstress / SACK-panic class)
	"T1657": {"D3-NTA", "D3-ITF"},                   // financial theft (VoIP toll fraud)
	"T1135": {"D3-DNR", "D3-DO"},                    // network share discovery
	"T1087": {"D3-DUC"},                             // account discovery
	"T1114": {"D3-NTA"},                             // email collection
	"T1610": {"D3-NTA", "D3-ITF"},                   // deploy container
	"T0814": {"D3-NTA", "D3-ITF", "D3-DE"},          // ICS: denial of service
	"T0888": {"D3-NTA", "D3-DNR"},                   // ICS: remote system info discovery
	"T0846": {"D3-NTA", "D3-DNR"},                   // ICS: remote system discovery (PROFINET-DCP)
	"T0830": {"D3-NTA"},                             // ICS: adversary-in-the-middle
	"T0836": {"D3-NTA", "D3-ITF", "D3-DE"},          // ICS: modify parameter
	"T0831": {"D3-NTA", "D3-DE"},                    // ICS: manipulation of control
	"T0843": {"D3-NTA", "D3-ITF", "D3-DE"},          // ICS: program download
	"T0858": {"D3-NTA", "D3-DE"},                    // ICS: change operating mode
	"T0855": {"D3-NTA", "D3-DE"},                    // ICS: unauthorized command message
	"T0801": {"D3-NTA", "D3-DE"},                    // ICS: monitor process state (data access)
	"T0880": {"D3-NTA", "D3-ITF", "D3-DE"},          // ICS: loss of safety
	"T0866": {"D3-NTA", "D3-ITF", "D3-DE"},          // ICS: exploitation of remote services
	"T1059": {"D3-NTA", "D3-DA"},                    // command & scripting interpreter
	"T1056": {"D3-NTA"},                             // input capture (keylogging via X11)
	"T1219": {"D3-NTA", "D3-OTF", "D3-RTSD"},        // remote access software
	"T1133": {"D3-MFA", "D3-NTA", "D3-RTSD"},        // external remote services
	"T1565": {"D3-NTA", "D3-DE"},                    // data manipulation (SNMP SET write)
	"T1590": {"D3-DNSTA", "D3-DNR"},                 // gather victim network info (DNS AXFR)
	"T1602": {"D3-NTA", "D3-DE"},                    // data from configuration repository (TFTP)
	"T1485": {"D3-NTA", "D3-DE"},                    // data destruction (PJL FSINIT format)
	"T1491": {"D3-NTA"},                             // defacement (printer panel message)
	"T1098": {"D3-MFA", "D3-DUC"},                   // account manipulation (printer password set)
	"T1552": {"D3-DUC", "D3-NTA"},                   // unsecured credentials (printer password read)
	"T1005": {"D3-DO", "D3-NTA"},                    // data from local system (PostScript file read)
	"T1601": {"D3-NTA", "D3-DE"},                    // modify system image (printer firmware upload)
	"T1583": {"D3-NTA", "D3-DNR"},                   // acquire infrastructure (botnet / ASN seen fleet-wide)
	"T1090": {"D3-NTA", "D3-OTF"},                   // proxy (SSRF / relay through the decoy; egress:denied)

	// --- credential-access / discovery / collection ---
	"T1003": {"D3-CH", "D3-DUC", "D3-NTA"}, // OS credential dumping
	"T1012": {"D3-PH", "D3-DO"},            // query registry
	"T1016": {"D3-DNR", "D3-NTA"},          // system network configuration discovery
	"T1036": {"D3-FA", "D3-DA"},            // masquerading
	"T1040": {"D3-NTA", "D3-NI"},           // network sniffing
	"T1048": {"D3-OTF", "D3-NTA"},          // exfiltration over alternative protocol
	"T1020": {"D3-OTF", "D3-NTA"},          // automated exfiltration
	"T1095": {"D3-NTA", "D3-OTF"},          // non-application-layer protocol (C2)
	"T1136": {"D3-CH", "D3-DUC"},           // create account
	"T1140": {"D3-FA", "D3-DA"},            // deobfuscate / decode files or information
	"T1213": {"D3-DO", "D3-NTA"},           // data from information repositories
	"T1482": {"D3-DNR", "D3-NTA"},          // domain trust discovery
	"T1555": {"D3-CH", "D3-DUC", "D3-NTA"}, // credentials from password stores (Vault)
	"T1528": {"D3-CH", "D3-DUC"},           // steal application access token (k8s / cloud)
	"T1560": {"D3-FA", "D3-NTA"},           // archive collected data

	// --- execution / persistence / privilege-escalation / evasion ---
	"T1053": {"D3-PSA", "D3-PH"},           // scheduled task / job
	"T1543": {"D3-PSA", "D3-PH"},           // create or modify system process
	"T1547": {"D3-PH", "D3-PSA"},           // boot or logon autostart execution
	"T1548": {"D3-PH", "D3-EAL"},           // abuse elevation control mechanism
	"T1068": {"D3-PH", "D3-EAL", "D3-NTA"}, // exploitation for privilege escalation
	"T1070": {"D3-PH", "D3-FA"},            // indicator removal
	"T1218": {"D3-EAL", "D3-PSA"},          // system binary proxy execution
	"T1562": {"D3-PH", "D3-NTA"},           // impair defenses
	"T1505": {"D3-FA", "D3-NTA", "D3-EAL"}, // server software component (web shell)

	// --- C2 / impact / supply-chain / containers ---
	"T1568": {"D3-DNSTA", "D3-NTA"},       // dynamic resolution (DGA)
	"T1572": {"D3-NTA", "D3-OTF"},         // protocol tunneling
	"T1486": {"D3-NTA", "D3-DE", "D3-FA"}, // data encrypted for impact (ransomware)
	"T1496": {"D3-NTA", "D3-OTF"},         // resource hijacking (cryptomining)
	"T1195": {"D3-FH", "D3-FA"},           // supply-chain compromise
	"T1609": {"D3-NTA", "D3-EAL"},         // container administration command
	"T1611": {"D3-PH", "D3-NTA"},          // escape to host (container escape)
}

// d3fendNames maps each D3FEND countermeasure id used in the d3fend map to
// its human-readable name, so the CLI / web UI can render "D3-MFA
// (Multi-factor Authentication)" instead of a bare id. Every id referenced
// by the d3fend map must have an entry (guarded by a test).
var d3fendNames = map[string]string{
	"D3-NTA":   "Network Traffic Analysis",
	"D3-DNR":   "Decoy Network Resource",
	"D3-DUC":   "Decoy User Credential",
	"D3-DO":    "Decoy Object",
	"D3-DE":    "Decoy Environment",
	"D3-DF":    "Decoy File",
	"D3-MFA":   "Multi-factor Authentication",
	"D3-DNSTA": "DNS Traffic Analysis",
	"D3-ITF":   "Inbound Traffic Filtering",
	"D3-OTF":   "Outbound Traffic Filtering",
	"D3-DA":    "Dynamic Analysis",
	"D3-FH":    "File Hashing",
	"D3-CH":    "Credential Hardening",
	"D3-PH":    "Platform Hardening",
	"D3-CAA":   "Connection Attempt Analysis",
	"D3-RTSD":  "Remote Terminal Session Detection",
	"D3-EAL":   "Executable Allowlisting",
	"D3-FA":    "File Analysis",
	"D3-NI":    "Network Isolation",
	"D3-PSA":   "Process Spawn Analysis",
}

// DefenseName returns the human-readable name for a D3FEND countermeasure id
// (e.g. "D3-MFA" -> "Multi-factor Authentication"), or "" if unknown.
func DefenseName(id string) string { return d3fendNames[id] }

// DefenseCatalog returns the D3FEND id->name catalog (a copy), for the CLI /
// UI to render a legend of the countermeasures the sensor maps to.
func DefenseCatalog() map[string]string {
	out := make(map[string]string, len(d3fendNames))
	for k, v := range d3fendNames {
		out[k] = v
	}
	return out
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
