package correlate

import (
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/mitre"
)

// storylineState tracks every distinct (rule_id, ATT&CK tactic, dest
// port, handler) tuple a single source IP has produced inside the
// storyline window. Once the source has touched StoryMinStages
// distinct ATT&CK tactics, the correlator emits a storyline:* event
// summarizing the path it walked (e.g.
// "discovery → credential-access → lateral-movement"). The summary
// is what makes a SOC triage tractable: instead of 47 individual
// "source touched port 22" lines, the analyst sees one
// "203.0.113.10 ran an attack from discovery to impact in 4 minutes"
// timeline.
type storylineState struct {
	firstSeen time.Time
	lastSeen  time.Time
	// stages preserves the order tactics first appeared. We re-render
	// it as a "->" arrow chain in the storyline event meta.
	stages           []string
	stageSeen        map[string]bool
	ruleHits         map[string]int
	techniques       map[string]bool
	destPorts        map[int]bool
	handlers         map[string]bool
	cveHits          map[string]bool // CVE ids exploited along the chain
	tools            map[string]bool // scanner/tool names fingerprinted
	anomalies        map[string]bool // anomaly markers seen along the chain
	hitCount         int
	malware          bool // a malware:capture fired for this source
	webshell         bool // a webshell rule/anomaly fired
	webAttack        bool // a web-attack-class (webapp:*) anomaly fired
	dnsTunnel        bool // a DNS tunneling / DGA / exfil anomaly fired
	tokenReuse       bool // replayed a planted honeytoken (canary:token_used)
	reachedObjective bool // chain touched impact / exfiltration / confirmed compromise
	lastEmittedSize  int
	lastEmittedSev   event.Severity
}

// StoryMinStages is the minimum number of distinct ATT&CK tactics a
// source must touch within StoryWindow before a storyline:* event
// fires. Two stages alone (e.g. just "discovery") is too low signal;
// at three the activity is clearly multi-step.
const StoryMinStages = 3

// StoryWindow is how long a source-IP storyline stays "open". Activity
// older than this is pruned and the source starts a fresh storyline
// on its next event.
const StoryWindow = 30 * time.Minute

// StoryReEmitEvery controls how many new stages can accumulate after
// an initial emission before we emit a refreshed storyline. Stops the
// router from re-emitting on every single follow-up event.
const StoryReEmitEvery = 2

// observeStoryline ingests an event and returns a storyline:* event
// if the source has crossed a new threshold. Must be called with
// c.mu held.
func (c *Correlator) observeStoryline(ev *event.Event, now time.Time) *event.Event {
	if ev.Source.IP == "" || len(ev.MitreTactics) == 0 {
		return nil
	}
	// Skip storyline-on-storyline recursion.
	if len(ev.RuleID) >= 10 && ev.RuleID[:10] == "storyline:" {
		return nil
	}
	st, ok := c.story[ev.Source.IP]
	if !ok || now.Sub(st.lastSeen) > StoryWindow {
		st = &storylineState{
			firstSeen:  now,
			stageSeen:  map[string]bool{},
			ruleHits:   map[string]int{},
			techniques: map[string]bool{},
			destPorts:  map[int]bool{},
			handlers:   map[string]bool{},
			cveHits:    map[string]bool{},
			tools:      map[string]bool{},
			anomalies:  map[string]bool{},
		}
		c.story[ev.Source.IP] = st
	}
	st.lastSeen = now
	st.hitCount++
	for _, t := range ev.MitreTactics {
		if !st.stageSeen[t] {
			st.stageSeen[t] = true
			st.stages = append(st.stages, t)
		}
		if t == "impact" || t == "exfiltration" {
			st.reachedObjective = true
		}
	}
	for _, tech := range ev.MitreTechniques {
		st.techniques[tech] = true
	}
	st.ruleHits[ev.RuleID]++
	if ev.Dest.Port > 0 {
		st.destPorts[ev.Dest.Port] = true
	}
	if ev.Handler != "" {
		st.handlers[ev.Handler] = true
	}
	// High-signal milestones: a CVE exploit attempt or captured malware
	// turns a noisy multi-stage chain into a confirmed intrusion.
	if strings.HasPrefix(ev.RuleID, "cve:") {
		st.cveHits[strings.TrimPrefix(ev.RuleID, "cve:")] = true
	}
	if ev.RuleID == "malware:capture" || ev.RuleID == "malware:detonation" {
		// A detonation verdict (AV hit / sandbox family) is strong confirmation
		// that captured loot is live malware.
		st.malware = true
	}
	// A replayed honeytoken/decoy credential is the strongest possible
	// milestone — proof the attacker used something they stole from us.
	if ev.RuleID == "canary:token_used" {
		st.tokenReuse = true
		st.reachedObjective = true
	}
	for _, a := range ev.Anomalies {
		st.anomalies[a] = true
		switch {
		case strings.HasPrefix(a, "cve:"):
			st.cveHits[strings.TrimPrefix(a, "cve:")] = true
		case strings.HasPrefix(a, "webshell-"):
			st.webshell = true
		case strings.HasPrefix(a, "webapp:"):
			st.webAttack = true
		case strings.HasPrefix(a, "dns-tunnel") || strings.HasPrefix(a, "dns-dga") ||
			a == "dns-qname-overlong" || a == "dns-txt-exfil":
			st.dnsTunnel = true
		}
	}
	if strings.HasPrefix(ev.RuleID, "webshell") {
		st.webshell = true
	}
	if tools, ok := ev.Meta["tools"].([]string); ok {
		for _, t := range tools {
			st.tools[t] = true
		}
	}

	if len(st.stages) < StoryMinStages {
		return nil
	}
	sev := storySeverity(st)
	// Re-emit when we've gained StoryReEmitEvery new stages since the
	// last emission, OR when the severity has escalated (e.g. a CVE
	// exploit / malware drop / objective reached after the first emit).
	escalated := st.lastEmittedSize > 0 && sev > st.lastEmittedSev
	if st.lastEmittedSize > 0 && len(st.stages)-st.lastEmittedSize < StoryReEmitEvery && !escalated {
		return nil
	}
	st.lastEmittedSize = len(st.stages)
	st.lastEmittedSev = sev

	techniques := setToSortedSlice(st.techniques)
	ports := setToSortedIntSlice(st.destPorts)
	handlers := setToSortedSlice(st.handlers)
	ordered := orderTacticsByRank(st.stages)

	meta := map[string]any{
		"stages":            ordered,
		"chain":             joinStages(ordered),
		"hit_count":         st.hitCount,
		"dest_ports":        ports,
		"handlers":          handlers,
		"first_seen_s":      int(now.Sub(st.firstSeen).Seconds()),
		"distinct_rules":    len(st.ruleHits),
		"objective_reached": st.reachedObjective,
	}
	if len(st.cveHits) > 0 {
		meta["cve_exploits"] = setToSortedSlice(st.cveHits)
	}
	if len(st.tools) > 0 {
		meta["tools"] = setToSortedSlice(st.tools)
	}
	if st.malware {
		meta["malware_captured"] = true
	}
	if st.tokenReuse {
		meta["token_reuse"] = true
	}
	if st.webshell {
		meta["webshell"] = true
	}
	// Name the recognizable attack pattern so a SOC sees "this is a ransomware
	// chain" rather than re-deriving it from the tactic list each time.
	if pb := storyPlaybook(st); pb != "" {
		meta["playbook"] = pb
	}

	return &event.Event{
		ID:              event.NewID(),
		Time:            now,
		Sensor:          ev.Sensor,
		RuleID:          "storyline:multi_stage",
		Severity:        sev,
		Source:          ev.Source,
		Proto:           "tcp",
		MitreTechniques: techniques,
		MitreTactics:    ordered,
		MitreDefenses:   mitre.DefensesFor(techniques),
		Meta:            meta,
	}
}

// storySeverity scales the storyline severity by how far the attacker
// got. A bare multi-stage chain is High; a chain that landed a CVE
// exploit, dropped malware, reached impact/exfiltration, or walked 5+
// distinct tactics is Critical — the SOC's "wake someone up" tier.
func storySeverity(st *storylineState) event.Severity {
	if st.malware || st.tokenReuse || st.webshell || len(st.cveHits) > 0 || st.reachedObjective || len(st.stages) >= 5 {
		return event.SeverityCritical
	}
	return event.SeverityHigh
}

// storyPlaybook names the recognizable attack pattern a storyline matches,
// from the accumulated handlers / tactics / milestones, or "" when the chain
// doesn't fit a known playbook. Checked most-specific first.
func storyPlaybook(st *storylineState) string {
	hasHandler := func(names ...string) bool {
		for _, n := range names {
			if st.handlers[n] {
				return true
			}
		}
		return false
	}
	anomPrefix := func(prefix string) bool {
		for a := range st.anomalies {
			if strings.HasPrefix(a, prefix) {
				return true
			}
		}
		return false
	}
	anom := func(name string) bool { return st.anomalies[name] }
	icsHandler := hasHandler("modbus", "s7", "s7comm_plus", "dnp3", "iec104", "ethernetip",
		"bacnet", "opcua", "codesys", "fins", "melsec", "mms", "ge_srtp", "hartip", "pcworx", "profinet")
	cloudHandler := hasHandler("cloud_metadata", "kubernetes_api", "vault", "etcd", "dockerapi")
	dbHandler := hasHandler("mysql", "mssql", "postgres", "redis", "mongodb", "oracle_tns", "elasticsearch")

	switch {
	case st.tokenReuse:
		// The attacker came back and used something they stole from the decoy.
		return "credential-replay-compromise"
	case anom("dcerpc-coerced-auth"):
		// MS-EFSRPC/RPRN/DFSNM/FSRVP coercion → forced auth → NTLM relay (AD CS).
		return "ad-coerced-authentication-relay"
	case anom("dcerpc-svcctl-access") && (anom("dcerpc-samr-enum") || anom("smb-null-session") || anom("dcerpc-lsarpc-enum")):
		// Enumerate the domain over MSRPC, then create a remote service (PsExec).
		return "ad-lateral-movement-psexec"
	case anom("redis-replication-takeover") && anom("redis-module-load"):
		// SLAVEOF a rogue master, then MODULE LOAD the malicious module = RCE.
		return "redis-rogue-replica-rce"
	case anomPrefix("smb-") && (st.cveHits["CVE-2017-0144"] || st.cveHits["CVE-2020-0796"] ||
		st.cveHits["CVE-2017-0143"] || st.cveHits["CVE-2020-1206"]):
		// Wormable SMB memory-corruption (EternalBlue / SMBGhost family).
		return "smb-wormable-exploit"
	case dbHandler && st.stageSeen["execution"] && (anom("mysql-udf-exec") || anom("mssql-xp-cmdshell") ||
		anom("postgres-copy-program") || anom("redis-lua-sandbox-escape") || anom("mongodb-server-side-js") ||
		anom("mssql-ole-automation") || anom("postgres-untrusted-plang") || anom("mssql-clr-assembly")):
		// Authenticated-then-RCE through a database's command/exec primitive.
		return "database-to-rce"
	case hasHandler("hl7", "dicom") && (anomPrefix("hl7-") || anomPrefix("dicom-")):
		// Medical-device / clinical-data-system interaction (HL7 v2 / DICOM):
		// PHI queries, DICOM image pull, or order/master-file tampering.
		return "medical-device-compromise"
	case hasHandler("bacnet", "knx") && (anom("bacnet-write-attempt") || anom("bacnet-write-multiple") ||
		anom("bacnet-priority-override") || anom("bacnet-reinitialize-device") || anom("bacnet-device-comm-control") ||
		anom("bacnet-file-write-attempt") || anom("knx-bus-write") || anom("knx-memory-write") ||
		anom("knx-programming") || anom("knx-device-restart") || anom("knx-routing-injection")):
		// Building-automation (BMS/BAS) manipulation: writing BACnet objects /
		// overriding priorities / reinitialising, or KNX bus/memory writes.
		return "building-automation-tampering"
	case hasHandler("s7", "codesys", "modbus", "melsec", "profinet", "ethernetip", "fins", "mms") &&
		(anom("ics-plc-write") || anom("ics-process-data-access") || anom("ics-field-device-probe")):
		// Direct PLC/field-device logic & process-data manipulation (the
		// write/program stage of an ICS intrusion).
		return "plc-logic-tampering"
	case hasHandler("mqtt", "coap", "opcua", "ocpp") && (anom("mqtt-sparkplug") || anom("ics-sparkplug-command") ||
		anom("ics-sparkplug-birth") || anomPrefix("ocpp-") || anom("mqtt-wildcard-subscribe") ||
		anom("coap-write-attempt") || anom("mqtt-acl-pattern-bypass")):
		// Industrial-IoT messaging abuse: MQTT/Sparkplug B command injection or
		// topic harvesting, CoAP resource writes, or OCPP EV-charger actuation.
		return "iiot-messaging-abuse"
	case hasHandler("sip") && anomPrefix("sip-"):
		// Telco/VoIP signaling abuse: SIP scanning, registration brute force, or
		// INVITE spraying (toll fraud / subscriber enumeration).
		return "telco-signaling-fraud"
	case icsHandler && (anomPrefix("ics-") || anomPrefix("modbus-") || anomPrefix("fins-") ||
		anomPrefix("pcom-") || st.stageSeen["impact"]):
		return "ot-kill-chain"
	case cloudHandler && st.stageSeen["credential-access"]:
		return "cloud-credential-takeover"
	case st.stageSeen["impact"] && (anomPrefix("redis-flush") || st.handlers["smb"]) && st.reachedObjective:
		return "ransomware-style-destruction"
	case st.dnsTunnel:
		// DNS used as a covert C2 / exfiltration channel.
		return "dns-tunneling"
	case st.stageSeen["exfiltration"]:
		// Data left the building (FTP download / DNS exfil / large response).
		return "data-exfiltration"
	case st.stageSeen["impact"] && (anomPrefix("tcp-") || anomPrefix("ip-") || anomPrefix("ntp-") ||
		anomPrefix("udp-") || anomPrefix("ssdp") || anomPrefix("dns-amplif")):
		// Volumetric / DoS / reflection-amplification abuse.
		return "dos-amplification"
	case st.webshell || ((len(st.cveHits) > 0 || st.webAttack) && st.stageSeen["execution"]):
		return "web-exploit-to-shell"
	case len(st.cveHits) > 0 && hasHandler("fortinet", "pulse", "citrix_gateway"):
		return "edge-appliance-exploitation"
	case st.malware && hasHandler("tr069", "upnp", "coap", "mqtt", "ocpp"):
		// Default-cred / exploit foothold on a consumer-IoT / CPE / router
		// surface followed by a second-stage dropper — Mirai-style botnet
		// recruitment of embedded devices.
		return "iot-botnet-recruitment"
	case st.malware:
		return "malware-delivery"
	case st.webAttack && !st.stageSeen["execution"] && len(st.cveHits) == 0:
		// Many web-attack classes thrown at the app but nothing landed yet.
		return "web-vuln-fuzzing"
	case st.stageSeen["credential-access"] && !st.stageSeen["execution"] && len(st.cveHits) == 0:
		return "credential-harvest"
	}
	return ""
}

// orderTacticsByRank sorts tactic names by their position in the
// reconnaissance-to-impact ordering from mitre.Tactics().
func orderTacticsByRank(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		ri := mitre.TacticRank(out[i])
		rj := mitre.TacticRank(out[j])
		if ri < 0 {
			return false
		}
		if rj < 0 {
			return true
		}
		return ri < rj
	})
	return out
}

func joinStages(stages []string) string {
	if len(stages) == 0 {
		return ""
	}
	out := stages[0]
	for i := 1; i < len(stages); i++ {
		out += " -> " + stages[i]
	}
	return out
}

func setToSortedSlice(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func setToSortedIntSlice(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
