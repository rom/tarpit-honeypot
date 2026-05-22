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
	// A profiled scan (nmap timing/scope/probe fingerprint) is active
	// scanning of the network from the adversary's recon phase, and
	// network-service discovery from ours.
	"scananalysis:profile":          {Techniques: []string{"T1595", "T1046"}, Tactics: []string{"reconnaissance", "discovery"}},
	"sniffer:arp_scan":              {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
	"sniffer:arp_reply_unsolicited": {Techniques: []string{"T1557.002"}, Tactics: []string{"credential-access"}},
	// Packet-capture scan-detection layer: stealth + volume TCP scans
	// observed on the wire that never establish a session.
	"sniffer:tcp_syn_scan":  {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"sniffer:tcp_null_scan": {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"sniffer:tcp_fin_scan":  {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"sniffer:tcp_xmas_scan": {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"sniffer:tcp_ack_scan":  {Techniques: []string{"T1046", "T1595.001"}, Tactics: []string{"discovery", "reconnaissance"}},
	"sniffer:ip_fragmented": {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
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
	// Harvested malware / shellcode / dropper = ingress tool transfer
	// (+ obfuscated payload when base64-wrapped).
	"malware:capture": {Techniques: []string{"T1105", "T1027"}, Tactics: []string{"command-and-control", "defense-evasion"}},
}

// handlerTags is the listener-handler -> ATT&CK lookup. Handlers
// shaped like authentication endpoints (ssh, ftp, telnet, ...) map to
// T1110/T1078 (brute force / valid accounts). Handlers shaped like
// vulnerability-scanner-target services (http, smb, rdp) map to
// T1190 (exploit public-facing application).
var handlerTags = map[string]Tag{
	// Auth / credential surface.
	"ssh":       {Techniques: []string{"T1110.001", "T1078"}, Tactics: []string{"credential-access", "initial-access"}},
	"telnet":    {Techniques: []string{"T1110.001", "T1078"}, Tactics: []string{"credential-access", "initial-access"}},
	"ftp":       {Techniques: []string{"T1110.001", "T1078"}, Tactics: []string{"credential-access", "initial-access"}},
	"smtp_recv": {Techniques: []string{"T1110.003", "T1114"}, Tactics: []string{"credential-access", "collection"}},
	"rdp":       {Techniques: []string{"T1021.001", "T1110.001"}, Tactics: []string{"lateral-movement", "credential-access"}},
	"vnc":       {Techniques: []string{"T1021.005", "T1110.001"}, Tactics: []string{"lateral-movement", "credential-access"}},
	"winrm":     {Techniques: []string{"T1021.006"}, Tactics: []string{"lateral-movement"}},
	"smb":       {Techniques: []string{"T1021.002", "T1135"}, Tactics: []string{"lateral-movement", "discovery"}},
	"postgres":  {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"mysql":     {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"redis":     {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"ldap":      {Techniques: []string{"T1110.003", "T1087.002"}, Tactics: []string{"credential-access", "discovery"}},
	"cldap":     {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
	"kerberos":  {Techniques: []string{"T1558"}, Tactics: []string{"credential-access"}},
	"dcerpc":    {Techniques: []string{"T1021.003"}, Tactics: []string{"lateral-movement"}},
	"xmpp":      {Techniques: []string{"T1071.001"}, Tactics: []string{"command-and-control"}},
	"amqp":      {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},

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
	"snmp-set-attempt":      {Techniques: []string{"T1565.001", "T0836"}, Tactics: []string{"impact"}},
	"smtp-open-relay-probe": {Techniques: []string{"T1071.003"}, Tactics: []string{"command-and-control"}},
	"smtp-user-enumeration": {Techniques: []string{"T1087"}, Tactics: []string{"discovery"}},
	// DNS zone-transfer (AXFR/IXFR) = bulk enumeration of internal hosts.
	"dns-zone-transfer": {Techniques: []string{"T1590.002", "T1018"}, Tactics: []string{"reconnaissance", "discovery"}},
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
	case strings.HasPrefix(a, "printer-"):
		// Generic printer/MFP recon + access (fs access, info query, job
		// received, nvram, dmcmd, ipp admin op, lpd command).
		return Tag{Techniques: []string{"T1083"}, Tactics: []string{"discovery"}}
	case a == "automation-client":
		return Tag{Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}}
	case strings.HasPrefix(a, "tool:"):
		// An identified scanning/attack tool — active scanning recon.
		return Tag{Techniques: []string{"T1595"}, Tactics: []string{"reconnaissance"}}
	}
	return Tag{}
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
