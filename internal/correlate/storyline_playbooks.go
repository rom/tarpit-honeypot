package correlate

import "sort"

// Playbook is the human-facing description of a named attack pattern that the
// storyline correlator recognizes (see storyPlaybook). The UI links each
// playbook tag to its entry so an operator can read what the label means, why it
// fired, and what to do about it.
type Playbook struct {
	Name      string   // slug, as set in meta.playbook (storyPlaybook return value)
	Title     string   // human-readable title
	Short     string   // one-line summary (chip tooltip / list)
	Long      string   // full description: what the attacker is doing and why it matters
	Tactics   []string // ATT&CK tactics the pattern spans (kill-chain order)
	Triggers  []string // what the storyline must observe for this playbook to fire
	NextSteps string   // what an operator should do when they see it
}

// playbooks is the authoritative registry, in rough most-severe-first order. Keep
// in sync with storyPlaybook: every string it can return must have an entry here
// (enforced by TestPlaybookRegistryCoversStoryPlaybook).
var playbooks = []Playbook{
	{
		Name: "credential-replay-compromise", Title: "Credential replay / stolen-token reuse",
		Short:   "An attacker came back and used a credential or token they harvested from the decoy.",
		Long:    "The sensor served a decoy credential, API token, or canary secret, and later saw that exact value used to authenticate from somewhere. That closes the loop on an active compromise: the attacker has exfiltrated loot and is operationalising it. Because the secret only ever existed on the honeypot, any use of it is unambiguous malicious activity (there are no false positives).",
		Tactics: []string{"credential-access", "lateral-movement", "initial-access"}, Triggers: []string{"a served decoy/honeytoken secret is later presented back to any handler"},
		NextSteps: "Treat as a confirmed breach signal: hunt for the token/credential across real systems, rotate anything structurally similar, and pivot on the replaying source IP.",
	},
	{
		Name: "ad-coerced-authentication-relay", Title: "Active Directory coerced authentication → NTLM relay",
		Short:   "MS-EFSRPC / PrinterBug / DFSCoerce-style coercion forcing the decoy to authenticate elsewhere.",
		Long:    "The attacker invoked an MSRPC coercion primitive (EfsRpcOpenFileRaw, RpcRemoteFindFirstPrinterChangeNotification, NetrDfsRemoveStdRoot, or an FSRVP call) to force the machine account to authenticate to an attacker-controlled host. In a real environment that NTLM authentication is relayed — classically to AD CS (ESC8 / PetitPotam) to mint a certificate and take over the account/domain.",
		Tactics: []string{"credential-access", "lateral-movement"}, Triggers: []string{"dcerpc-coerced-auth anomaly (EFSRPC/RPRN/DFSNM/FSRVP)"},
		NextSteps: "Verify EPA / SMB signing / AD CS relay protections on real DCs and CAs; block the coercion interfaces where unused.",
	},
	{
		Name: "ad-lateral-movement-psexec", Title: "Active Directory lateral movement (PsExec-style)",
		Short:   "Domain enumeration over MSRPC followed by remote service creation.",
		Long:    "The attacker enumerated the domain over MSRPC (SAMR users/groups, LSARPC, or an SMB null session) and then reached the service-control manager (svcctl) to create or start a remote service — the mechanics behind PsExec and most hands-on-keyboard lateral movement. This is the 'spread' phase after an initial foothold.",
		Tactics: []string{"discovery", "lateral-movement", "execution"}, Triggers: []string{"dcerpc-svcctl-access with dcerpc-samr-enum / smb-null-session / dcerpc-lsarpc-enum"},
		NextSteps: "Audit which accounts can create remote services; alert on svcctl from non-admin hosts.",
	},
	{
		Name: "redis-rogue-replica-rce", Title: "Redis rogue-replica module-load RCE",
		Short:   "SLAVEOF a rogue master, then MODULE LOAD a malicious .so = remote code execution.",
		Long:    "An unauthenticated Redis instance is told to replicate from an attacker-controlled master (SLAVEOF / REPLICAOF), which ships a malicious module file, and then MODULE LOAD runs it — a reliable, widely-automated RCE chain against exposed Redis.",
		Tactics: []string{"initial-access", "execution"}, Triggers: []string{"redis-replication-takeover + redis-module-load"},
		NextSteps: "Never expose Redis; require auth, disable MODULE, and bind to localhost.",
	},
	{
		Name: "smb-wormable-exploit", Title: "Wormable SMB memory-corruption exploit",
		Short:   "EternalBlue / SMBGhost-class SMB exploitation.",
		Long:    "The attacker drove SMB into the memory-corruption primitives behind the wormable classics — EternalBlue (MS17-010: CVE-2017-0143/0144) or SMBGhost (CVE-2020-0796), and the SMBleed/-leed companions. These spread without user interaction and are a hallmark of worms and ransomware loaders.",
		Tactics: []string{"initial-access", "lateral-movement", "execution"}, Triggers: []string{"an smb-* anomaly together with a wormable SMB CVE hit"},
		NextSteps: "Confirm MS17-010 / SMBGhost patch level everywhere; disable SMBv1.",
	},
	{
		Name: "database-to-rce", Title: "Database-to-RCE via a command/exec primitive",
		Short:   "Authenticated database access escalated to OS code execution.",
		Long:    "After reaching a database the attacker used its built-in code/exec primitive to run OS commands — MSSQL xp_cmdshell / OLE automation / CLR assembly, MySQL UDF, PostgreSQL COPY ... PROGRAM / an untrusted procedural language, Redis Lua sandbox escape, or MongoDB server-side JavaScript. This is the standard pivot from 'DB creds' to 'shell on the DB server'.",
		Tactics: []string{"execution", "privilege-escalation"}, Triggers: []string{"a database handler reaching the execution stage via a DB exec primitive"},
		NextSteps: "Disable the exec primitives (xp_cmdshell, UDF loading, COPY PROGRAM); least-privilege the DB service account.",
	},
	{
		Name: "ot-kill-chain", Title: "ICS/OT kill chain",
		Short:   "Industrial-protocol reconnaissance progressing toward control or impact.",
		Long:    "The attacker spoke an ICS/OT protocol (Modbus, S7, DNP3, IEC-104, EtherNet/IP, BACnet, OPC UA, CODESYS, FINS, …) and moved past discovery toward control actions or impact — reading/writing registers and coils, changing a PLC mode, or issuing a stop. This is the ICS-specific kill chain (ATT&CK for ICS) where the objective is physical-process disruption, not data.",
		Tactics: []string{"discovery", "impair-process-control", "impact"}, Triggers: []string{"an OT handler with an ics-/modbus-/fins-/pcom- anomaly or the impact stage"},
		NextSteps: "Verify the real control network is segmented from this surface; alert on any write/mode-change from outside the engineering VLAN.",
	},
	{
		Name: "cloud-credential-takeover", Title: "Cloud credential takeover",
		Short:   "Cloud-metadata / Kubernetes / Vault / etcd / Docker access reaching for credentials.",
		Long:    "The attacker hit a cloud-native credential source — the instance-metadata service (IMDS), the Kubernetes API, Vault, etcd, or the Docker socket — and progressed into credential-access. These endpoints hand out IAM role tokens, service-account JWTs, and secrets that let an attacker expand from one workload into the whole cloud account.",
		Tactics: []string{"credential-access", "discovery", "lateral-movement"}, Triggers: []string{"a cloud handler (metadata/k8s/vault/etcd/docker) reaching credential-access"},
		NextSteps: "Enforce IMDSv2, restrict the Docker socket, and scope service-account tokens; alert on IMDS access from pods/containers that shouldn't need it.",
	},
	{
		Name: "ransomware-style-destruction", Title: "Ransomware-style destruction",
		Short:   "Reaching the objective with mass-delete / flush / encryption-style impact.",
		Long:    "The chain reached its objective in the impact stage with destructive actions — Redis FLUSHALL, SMB-based mass file operations, or equivalent wipe/encrypt behaviour. This is the end-state of a ransomware or wiper intrusion: data availability is the target.",
		Tactics: []string{"impact"}, Triggers: []string{"impact stage + redis-flush / smb handler + objective reached"},
		NextSteps: "Confirm offline backups and recovery runbooks; this pattern on a real host is an incident, not an alert.",
	},
	{
		Name: "dns-tunneling", Title: "DNS tunneling (covert C2 / exfil)",
		Short:   "DNS used as a covert command-and-control or data channel.",
		Long:    "The attacker encoded data into DNS queries/answers — long, high-entropy labels, excessive subdomains, or TXT abuse — to smuggle a command-and-control or exfiltration channel past egress controls that allow DNS. A classic low-and-slow technique for environments that block direct outbound.",
		Tactics: []string{"command-and-control", "exfiltration"}, Triggers: []string{"the DNS tunneling heuristic (entropy / label-rate / query-volume)"},
		NextSteps: "Inspect / proxy DNS; alert on high-entropy labels and anomalous query volume to a single zone.",
	},
	{
		Name: "data-exfiltration", Title: "Data exfiltration",
		Short:   "Data left the decoy — FTP download, DNS exfil, or a large outbound response.",
		Long:    "The storyline reached the exfiltration stage: the attacker pulled data out, whether by downloading files over FTP, smuggling it through DNS, or extracting it in large protocol responses. Exfiltration is typically the payoff stage of a data-theft intrusion.",
		Tactics: []string{"collection", "exfiltration"}, Triggers: []string{"the exfiltration stage is reached in the storyline"},
		NextSteps: "Trace what was taken and from where; check egress DLP and whether the same source touched real data stores.",
	},
	{
		Name: "dos-amplification", Title: "DoS / reflection-amplification abuse",
		Short:   "Volumetric, denial-of-service, or reflection-amplification behaviour.",
		Long:    "The decoy was used (or probed) for volumetric or reflection/amplification abuse — spoofed-source UDP requests to amplifiers (NTP monlist, DNS ANY, SSDP, memcached), or raw TCP/IP flood patterns. The honeypot's reflection-safe handlers refuse to amplify, so this is the attacker testing the box as a DDoS weapon.",
		Tactics: []string{"impact"}, Triggers: []string{"the impact stage with a tcp-/ip-/ntp-/udp-/ssdp-/dns-amplif- anomaly"},
		NextSteps: "Make sure the real equivalents aren't open reflectors; see the DDoS-backscatter signal for who the target may be.",
	},
	{
		Name: "web-exploit-to-shell", Title: "Web exploit to shell",
		Short:   "A web CVE / attack landed and reached code execution or dropped a webshell.",
		Long:    "A web application exploit succeeded far enough to reach the execution stage or to plant a webshell — the most common internet-facing intrusion path. Either a catalogued CVE matched and execution followed, or the handler recognized webshell-planting behaviour.",
		Tactics: []string{"initial-access", "execution", "persistence"}, Triggers: []string{"a webshell marker, or (a CVE hit / web-attack) plus the execution stage"},
		NextSteps: "Patch the matched CVE on the real app; hunt for webshells under the web root.",
	},
	{
		Name: "edge-appliance-exploitation", Title: "Edge-appliance exploitation",
		Short:   "A CVE hit against a VPN / gateway appliance (Fortinet, Pulse, Citrix, …).",
		Long:    "The attacker threw a known exploit at an internet-facing edge appliance — a Fortinet FortiGate SSL-VPN, Pulse/Ivanti Connect Secure, or Citrix Gateway. These devices are the top initial-access vector for ransomware affiliates and state actors because they sit in front of everything and are slow to patch.",
		Tactics: []string{"initial-access"}, Triggers: []string{"a CVE hit on a fortinet / pulse / citrix_gateway handler"},
		NextSteps: "Prioritise patching the matched appliance CVE; check for the vendor's known post-exploit IOCs and web-session artifacts.",
	},
	{
		Name: "malware-delivery", Title: "Malware delivery / staging",
		Short:   "A dropper staged a second-stage payload (wget/curl, uploaded artifact).",
		Long:    "The attacker staged malware — a wget/curl dropper fetching a second stage, or an uploaded binary/script artifact the sensor captured. This is the delivery phase; the captured artifacts and harvested URLs on the captures page are the loot.",
		Tactics: []string{"execution", "command-and-control"}, Triggers: []string{"a malware/dropper marker on the storyline"},
		NextSteps: "Analyse the captured artifact + harvested URLs in a sandbox; block the dropper infrastructure.",
	},
	{
		Name: "web-vuln-fuzzing", Title: "Web vulnerability fuzzing",
		Short:   "Many web-attack classes thrown at the app, but nothing landed yet.",
		Long:    "A broad spray of web-attack probes — SQLi, traversal, template injection, scanner payloads — without a confirmed exploit or execution. This is automated vulnerability scanning / fuzzing: reconnaissance for a foothold, not yet a compromise, but worth watching if it narrows onto one app.",
		Tactics: []string{"reconnaissance", "initial-access"}, Triggers: []string{"web-attack activity with no execution stage and no CVE hit"},
		NextSteps: "Usually background noise; escalate only if it concentrates on a specific real application or precedes a landed exploit.",
	},
	{
		Name: "credential-harvest", Title: "Credential harvesting / brute force",
		Short:   "Credential-access activity (login spray / brute force) without execution.",
		Long:    "The attacker focused on credentials — password spraying, brute force, or default-credential attempts across services — without reaching execution or landing a CVE. This is the access-seeking phase; the captured credentials are on the captures page.",
		Tactics: []string{"credential-access"}, Triggers: []string{"the credential-access stage with no execution stage and no CVE hit"},
		NextSteps: "Check whether the sprayed usernames/passwords match real accounts; enforce lockout/MFA on the real equivalents.",
	},
}

var playbookByName = func() map[string]Playbook {
	m := make(map[string]Playbook, len(playbooks))
	for _, p := range playbooks {
		m[p.Name] = p
	}
	return m
}()

// PlaybookInfo returns the description for a playbook name (meta.playbook value),
// or ok=false when the name isn't registered.
func PlaybookInfo(name string) (Playbook, bool) {
	p, ok := playbookByName[name]
	return p, ok
}

// AllPlaybooks returns every registered playbook in a stable (registry) order.
func AllPlaybooks() []Playbook {
	out := make([]Playbook, len(playbooks))
	copy(out, playbooks)
	return out
}

// PlaybookNames returns the registered playbook slugs, sorted.
func PlaybookNames() []string {
	out := make([]string, 0, len(playbooks))
	for _, p := range playbooks {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}
