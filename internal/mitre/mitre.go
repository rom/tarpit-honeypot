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

import "strings"

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
	"correlate:port_scan":              {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"correlate:brute_force":            {Techniques: []string{"T1110"}, Tactics: []string{"credential-access"}},
	"correlate:slow_scan":              {Techniques: []string{"T1046"}, Tactics: []string{"discovery"}},
	"sniffer:arp_scan":                 {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
	"sniffer:arp_reply_unsolicited":    {Techniques: []string{"T1557.002"}, Tactics: []string{"credential-access"}},
	"dnscanary:hit":                    {Techniques: []string{"T1071.004"}, Tactics: []string{"command-and-control"}},
	"dnscanary:amplifier":              {Techniques: []string{"T1498.002"}, Tactics: []string{"impact"}},
	"protocol_anomaly":                 {Techniques: []string{"T1071"}, Tactics: []string{"command-and-control"}},
	// A previously-unseen host appearing on the segment maps to
	// network-service / remote-system discovery from the defender's
	// vantage (the device is doing the discovering).
	"device:new":      {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
	"correlate:icmp_sweep": {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
}

// handlerTags is the listener-handler -> ATT&CK lookup. Handlers
// shaped like authentication endpoints (ssh, ftp, telnet, ...) map to
// T1110/T1078 (brute force / valid accounts). Handlers shaped like
// vulnerability-scanner-target services (http, smb, rdp) map to
// T1190 (exploit public-facing application).
var handlerTags = map[string]Tag{
	// Auth / credential surface.
	"ssh":        {Techniques: []string{"T1110.001", "T1078"}, Tactics: []string{"credential-access", "initial-access"}},
	"telnet":     {Techniques: []string{"T1110.001", "T1078"}, Tactics: []string{"credential-access", "initial-access"}},
	"ftp":        {Techniques: []string{"T1110.001", "T1078"}, Tactics: []string{"credential-access", "initial-access"}},
	"smtp_recv":  {Techniques: []string{"T1110.003", "T1114"}, Tactics: []string{"credential-access", "collection"}},
	"rdp":        {Techniques: []string{"T1021.001", "T1110.001"}, Tactics: []string{"lateral-movement", "credential-access"}},
	"vnc":        {Techniques: []string{"T1021.005", "T1110.001"}, Tactics: []string{"lateral-movement", "credential-access"}},
	"winrm":      {Techniques: []string{"T1021.006"}, Tactics: []string{"lateral-movement"}},
	"smb":        {Techniques: []string{"T1021.002", "T1135"}, Tactics: []string{"lateral-movement", "discovery"}},
	"postgres":   {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"mysql":      {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"redis":      {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},
	"ldap":       {Techniques: []string{"T1110.003", "T1087.002"}, Tactics: []string{"credential-access", "discovery"}},
	"cldap":      {Techniques: []string{"T1018"}, Tactics: []string{"discovery"}},
	"kerberos":   {Techniques: []string{"T1558"}, Tactics: []string{"credential-access"}},
	"dcerpc":     {Techniques: []string{"T1021.003"}, Tactics: []string{"lateral-movement"}},
	"xmpp":       {Techniques: []string{"T1071.001"}, Tactics: []string{"command-and-control"}},
	"amqp":       {Techniques: []string{"T1110.001"}, Tactics: []string{"credential-access"}},

	// Vulnerability-scanner / publicly exposed application surface.
	"http":       {Techniques: []string{"T1190", "T1083"}, Tactics: []string{"initial-access", "discovery"}},
	"https":      {Techniques: []string{"T1190", "T1083"}, Tactics: []string{"initial-access", "discovery"}},
	"rtsp":       {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},
	"dockerapi":  {Techniques: []string{"T1190", "T1610"}, Tactics: []string{"initial-access", "execution"}},
	"ipp":        {Techniques: []string{"T1190"}, Tactics: []string{"initial-access"}},

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

	// ICS / OT surface — MITRE ATT&CK for ICS uses a separate
	// matrix (S0599 mapped techniques live there). We keep these
	// Enterprise-matrix equivalents for the SIEM that expects a
	// consistent ID space.
	"modbus":     {Techniques: []string{"T0814", "T0888"}, Tactics: []string{"impact", "discovery"}},
	"s7":         {Techniques: []string{"T0814", "T0888"}, Tactics: []string{"impact", "discovery"}},
	"iec104":     {Techniques: []string{"T0814"}, Tactics: []string{"impact"}},
	"mqtt":       {Techniques: []string{"T1110.001", "T0830"}, Tactics: []string{"credential-access", "lateral-movement"}},
	"opcua":      {Techniques: []string{"T0814"}, Tactics: []string{"impact"}},
	"ethernetip": {Techniques: []string{"T0814", "T0888"}, Tactics: []string{"impact", "discovery"}},
	"bacnet":     {Techniques: []string{"T0814"}, Tactics: []string{"impact"}},
	"fins":       {Techniques: []string{"T0814"}, Tactics: []string{"impact"}},
	"melsec":     {Techniques: []string{"T0814"}, Tactics: []string{"impact"}},
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
