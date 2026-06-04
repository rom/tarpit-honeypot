package ui

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/portsvc"
	"github.com/rom/tarpit-honeypot/internal/store"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// Attacker profiles: a per-source-IP dossier compiled from every event that
// source produced — behaviour (rules, targeted services/ports), tool +
// scanner fingerprinting (meta.tools, JA3/JA4/HASSH), credentials tried,
// ATT&CK techniques/tactics, anomalies, and CVEs. The list view (cheap
// GROUP BY) ranks actors by a severity-weighted threat score; the detail
// view scans that actor's events and builds the full dossier, which grows
// as the source keeps interacting.

// profileListWindow / profileDetailWindow bound how far back the list and
// the per-actor dossier look.
const (
	profileListWindow   = 30 * 24 * time.Hour
	profileDetailWindow = 90 * 24 * time.Hour
	profileDetailMax    = 2000 // events scanned per actor for the dossier
)

type countItem struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type credPair struct {
	// Kind classifies the captured secret: "password" (a user/pass login),
	// "token", "api-key", "snmp-community", "cookie", "authorization",
	// "kerberos-ticket" or "honeytoken". Empty renders as a plain login.
	Kind string `json:"kind,omitempty"`
	User string `json:"user,omitempty"`
	// Pass holds the secret value: the password for a login, else the token /
	// key / community / ticket material itself.
	Pass string `json:"pass,omitempty"`
	// Service is where the secret was captured (the handler/protocol,
	// e.g. "ssh", "http", "ftp"), so the operator can see the attack surface.
	Service string `json:"service,omitempty"`
}

// Profile is the compiled dossier for one source IP.
type Profile struct {
	IP          string         `json:"ip"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	Count       int            `json:"events"`
	Partial     bool           `json:"partial"` // true if more events exist than were scanned
	BySeverity  map[string]int `json:"by_severity"`
	MaxSeverity string         `json:"max_severity"`
	ThreatScore int            `json:"threat_score"`
	ThreatLevel string         `json:"threat_level"`
	// Classification is a synthesized higher-level label for this actor
	// (e.g. "C2 / red-team framework", "vulnerability scan", "credential
	// brute-force", "reconnaissance / scanning", "exploitation attempt").
	Classification string `json:"classification,omitempty"`
	// Summary is a one-line human-readable assessment of the actor.
	Summary    string   `json:"summary,omitempty"`
	Automation bool     `json:"automation"`
	Tools      []string `json:"tools,omitempty"`
	// Confidence is the highest tool-identification confidence (0-100) seen
	// across this source's events; ConfidenceLabel renders the coarse band.
	Confidence   int               `json:"confidence,omitempty"`
	Rules        []countItem       `json:"rules,omitempty"`
	Handlers     []string          `json:"handlers_targeted,omitempty"`
	Ports        []int             `json:"ports_targeted,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
	// FingerprintClients maps a fingerprint kind to the client / tool the
	// fingerprint DB attributes it to (e.g. ja4 -> "Chrome", ja3 -> "Cobalt
	// Strike"), when an offline fingerprint database is loaded.
	FingerprintClients map[string]string `json:"fingerprint_clients,omitempty"`
	Anomalies          []string          `json:"anomalies,omitempty"`
	Mitre              []string          `json:"mitre_techniques,omitempty"`
	Tactics            []string          `json:"mitre_tactics,omitempty"`
	CVEs               []string          `json:"cves,omitempty"`
	Credentials        []credPair        `json:"credentials,omitempty"`
	Sensors            []string          `json:"sensors,omitempty"`
	// Domains are DNS names and TLS SNIs this source asked for; URLs are
	// C2/dropper URLs harvested from its payloads; Artifacts are captured
	// malware-artifact descriptors (kind:sha256). These surface the forensic
	// observables that previously lived only in per-event meta.
	Domains   []string `json:"domains,omitempty"`
	URLs      []string `json:"harvested_urls,omitempty"`
	Artifacts []string `json:"artifacts,omitempty"`
	// SSHKeys are the SSH public-key fingerprints this source offered;
	// Emails are SMTP envelope senders it used; AttackClasses are the
	// distinct web-attack classes (webapp:*) it threw at the app.
	SSHKeys       []string `json:"ssh_keys,omitempty"`
	Emails        []string `json:"emails,omitempty"`
	AttackClasses []string `json:"attack_classes,omitempty"`
	// Playbooks are the named attack patterns the storyline correlator
	// recognized for this source (e.g. ransomware-style-destruction,
	// dns-tunneling, cloud-credential-takeover).
	Playbooks []string `json:"playbooks,omitempty"`
	// TokenReuse is set when this source replayed a honeytoken/decoy
	// credential the sensor had previously served — strong proof of
	// compromise (a closed canary loop).
	TokenReuse bool `json:"token_reuse,omitempty"`
	// Reputation is the merged enrichment meta for this source (threat-intel /
	// blacklist / Tor / known-scanner / external-intel labels) — sourceBadges
	// renders it so the dossier and the profiles list carry the IP's reputation.
	Reputation map[string]any `json:"reputation,omitempty"`
	// Origin / infrastructure enrichment (first non-empty across the actor's
	// events). These are already attached to events by internal/enrich but were
	// not surfaced on the dossier.
	Origin OriginInfo `json:"origin,omitempty"`
	// Proto is the protocol-stack intelligence observed from this actor (TLS
	// versions, negotiated SSH KEX, HTTP/2, QUIC/HTTP-3) — captured by the
	// handlers but not previously shown on the profile.
	Proto ProtoIntel `json:"proto_intel,omitempty"`
	// OPCItems are the OPC-DA / ICS item IDs / group names this source reached
	// for (from the dcerpc OPC-DA call layer).
	OPCItems []string       `json:"opc_items,omitempty"`
	Recent   []*event.Event `json:"-"`
}

// OriginInfo is the per-actor infrastructure/geo enrichment.
type OriginInfo struct {
	Country       string  `json:"country,omitempty"`
	CountryName   string  `json:"country_name,omitempty"`
	City          string  `json:"city,omitempty"`
	Lat           float64 `json:"lat,omitempty"`
	Lon           float64 `json:"lon,omitempty"`
	ASN           int     `json:"asn,omitempty"`
	ASNOrg        string  `json:"asn_org,omitempty"`
	RDNS          string  `json:"rdns,omitempty"`
	NetClass      string  `json:"net_class,omitempty"`
	CloudProvider string  `json:"cloud_provider,omitempty"`
	MACVendor     string  `json:"mac_vendor,omitempty"`
	OSGuess       string  `json:"os_guess,omitempty"`
	KnownScanner  string  `json:"known_scanner,omitempty"`
}

// Empty reports whether no origin enrichment was captured.
func (o OriginInfo) Empty() bool {
	return o.Country == "" && o.ASN == 0 && o.RDNS == "" && o.NetClass == "" &&
		o.CloudProvider == "" && o.MACVendor == "" && o.OSGuess == "" && o.KnownScanner == ""
}

// ProtoIntel is the per-actor protocol-stack intelligence.
type ProtoIntel struct {
	TLSVersions []string `json:"tls_versions,omitempty"`
	SSHKex      string   `json:"ssh_kex,omitempty"` // negotiated KEX
	SSHKexWeak  bool     `json:"ssh_kex_weak,omitempty"`
	HTTP2       bool     `json:"http2,omitempty"`
	HTTP3       bool     `json:"http3,omitempty"`
	QUICSNI     []string `json:"quic_sni,omitempty"`
	QUICALPN    []string `json:"quic_alpn,omitempty"`
}

// Empty reports whether no protocol intelligence was captured.
func (p ProtoIntel) Empty() bool {
	return len(p.TLSVersions) == 0 && p.SSHKex == "" && !p.HTTP2 && !p.HTTP3 &&
		len(p.QUICSNI) == 0 && len(p.QUICALPN) == 0
}

// buildProfile aggregates one source's events (expected newest-first) into a
// dossier.
func buildProfile(ip string, evs []*event.Event) Profile {
	p := Profile{IP: ip, BySeverity: map[string]int{}, Fingerprints: map[string]string{}}
	toolSet := map[string]struct{}{}
	anomSet := map[string]struct{}{}
	mitreSet := map[string]struct{}{}
	tacticSet := map[string]struct{}{}
	cveSet := map[string]struct{}{}
	handlerSet := map[string]struct{}{}
	sensorSet := map[string]struct{}{}
	portSet := map[int]struct{}{}
	ruleCount := map[string]int{}
	credSeen := map[string]struct{}{}
	domainSet := map[string]struct{}{}
	urlSet := map[string]struct{}{}
	artSet := map[string]struct{}{}
	sshKeySet := map[string]struct{}{}
	emailSet := map[string]struct{}{}
	attackClassSet := map[string]struct{}{}
	playbookSet := map[string]struct{}{}
	var maxSev event.Severity

	rep := map[string]any{}
	tlsSet := map[string]struct{}{}
	quicSNISet := map[string]struct{}{}
	quicALPNSet := map[string]struct{}{}
	opcSet := map[string]struct{}{}
	// firstStr records the first non-empty string value for an origin field.
	firstStr := func(dst *string, ev *event.Event, key string) {
		if *dst == "" {
			if v, _ := ev.Meta[key].(string); v != "" {
				*dst = v
			}
		}
	}
	for _, ev := range evs {
		p.Count++
		if p.FirstSeen.IsZero() || ev.Time.Before(p.FirstSeen) {
			p.FirstSeen = ev.Time
		}
		if ev.Time.After(p.LastSeen) {
			p.LastSeen = ev.Time
		}
		// Merge this source's reputation enrichment (first non-empty wins) so
		// the profile carries the same badges as the events views.
		for _, k := range []string{"threat_intel", "threat_intel_hit", "tor_exit",
			"external_intel", "fleet_intel", "known_scanner", "net_class", "tools"} {
			if _, ok := rep[k]; !ok {
				if v, present := ev.Meta[k]; present {
					rep[k] = v
				}
			}
		}
		p.BySeverity[ev.Severity.String()]++
		if ev.Severity > maxSev {
			maxSev = ev.Severity
		}
		p.ThreatScore += int(ev.Severity) * int(ev.Severity)
		ruleCount[ev.RuleID]++
		if ev.Handler != "" {
			handlerSet[ev.Handler] = struct{}{}
		}
		if ev.Dest.Port != 0 {
			portSet[ev.Dest.Port] = struct{}{}
		}
		if ev.Sensor != "" {
			sensorSet[ev.Sensor] = struct{}{}
		}
		if strings.HasPrefix(ev.RuleID, "cve:") {
			cveSet[strings.TrimPrefix(ev.RuleID, "cve:")] = struct{}{}
		}
		for _, a := range ev.Anomalies {
			anomSet[a] = struct{}{}
		}
		for _, m := range ev.MitreTechniques {
			mitreSet[m] = struct{}{}
		}
		for _, t := range ev.MitreTactics {
			tacticSet[t] = struct{}{}
		}
		for _, t := range metaStrings(ev.Meta, "tools") {
			toolSet[t] = struct{}{}
		}
		if b, ok := ev.Meta["automation"].(bool); ok && b {
			p.Automation = true
		}
		if c := metaInt(ev.Meta, "tool_confidence"); c > p.Confidence {
			p.Confidence = c
		}
		for _, fp := range []string{"ja3", "ja4", "ja4h", "ja4t", "ja3s", "hassh", "hassh_server"} {
			if v, ok := ev.Meta[fp].(string); ok && v != "" {
				if _, exists := p.Fingerprints[fp]; !exists {
					p.Fingerprints[fp] = v
				}
			}
			// Client/tool attribution from the offline fingerprint DB.
			if c, ok := ev.Meta[fp+"_client"].(string); ok && c != "" {
				if p.FingerprintClients == nil {
					p.FingerprintClients = map[string]string{}
				}
				if _, exists := p.FingerprintClients[fp]; !exists {
					p.FingerprintClients[fp] = c
				}
			}
		}
		// Forensic observables that used to live only in per-event meta.
		for _, k := range []string{"qname", "sni"} {
			if d, _ := ev.Meta[k].(string); d != "" {
				domainSet[d] = struct{}{}
			}
		}
		for _, u := range metaStrings(ev.Meta, "harvested_urls") {
			urlSet[u] = struct{}{}
		}
		for _, a := range metaStrings(ev.Meta, "payload_artifacts") {
			artSet[a] = struct{}{}
		}
		for _, k := range metaStrings(ev.Meta, "ssh_pubkey_fps") {
			sshKeySet[k] = struct{}{}
		}
		if mf, _ := ev.Meta["mail_from"].(string); mf != "" {
			if from := strings.Trim(mf, "<> "); strings.Contains(from, "@") {
				emailSet[from] = struct{}{}
			}
		}
		for _, a := range ev.Anomalies {
			if strings.HasPrefix(a, "webapp:") {
				attackClassSet[a] = struct{}{}
			}
		}
		if ev.RuleID == "canary:token_used" {
			p.TokenReuse = true
		}
		if ev.RuleID == "storyline:multi_stage" {
			if pb, _ := ev.Meta["playbook"].(string); pb != "" {
				playbookSet[pb] = struct{}{}
			}
		}
		for _, c := range extractCreds(ev) {
			key := c.Kind + "\x00" + c.User + "\x00" + c.Pass + "\x00" + c.Service
			if _, dup := credSeen[key]; !dup && len(p.Credentials) < 100 {
				credSeen[key] = struct{}{}
				p.Credentials = append(p.Credentials, c)
			}
		}
		// Origin / infrastructure enrichment (already attached by internal/enrich).
		firstStr(&p.Origin.Country, ev, "geo_country")
		firstStr(&p.Origin.CountryName, ev, "geo_country_name")
		firstStr(&p.Origin.City, ev, "geo_city")
		firstStr(&p.Origin.RDNS, ev, "rdns")
		firstStr(&p.Origin.NetClass, ev, "net_class")
		firstStr(&p.Origin.CloudProvider, ev, "cloud_provider")
		firstStr(&p.Origin.MACVendor, ev, "mac_vendor")
		// Prefer the precise p0f fingerprint over the coarse TTL bucket.
		firstStr(&p.Origin.OSGuess, ev, "os_fingerprint")
		firstStr(&p.Origin.OSGuess, ev, "os_guess")
		firstStr(&p.Origin.KnownScanner, ev, "known_scanner")
		firstStr(&p.Origin.ASNOrg, ev, "asn_org")
		if p.Origin.ASN == 0 {
			p.Origin.ASN = metaInt(ev.Meta, "asn")
		}
		if p.Origin.Lat == 0 {
			if f, ok := metaFloat(ev.Meta, "geo_lat"); ok {
				p.Origin.Lat = f
			}
		}
		if p.Origin.Lon == 0 {
			if f, ok := metaFloat(ev.Meta, "geo_lon"); ok {
				p.Origin.Lon = f
			}
		}
		// Protocol-stack intelligence.
		if v, _ := ev.Meta["tls_version"].(string); v != "" {
			tlsSet[v] = struct{}{}
		}
		if p.Proto.SSHKex == "" {
			firstStr(&p.Proto.SSHKex, ev, "ssh_kex_negotiated")
		}
		if b, _ := ev.Meta["http2"].(bool); b {
			p.Proto.HTTP2 = true
		}
		if b, _ := ev.Meta["http3"].(bool); b {
			p.Proto.HTTP3 = true
		}
		for _, s := range metaStrings(ev.Meta, "quic_sni") { // handles string + []string
			quicSNISet[s] = struct{}{}
		}
		for _, a := range metaStrings(ev.Meta, "quic_alpn") {
			quicALPNSet[a] = struct{}{}
		}
		for _, s := range metaStrings(ev.Meta, "opc_strings") {
			opcSet[s] = struct{}{}
		}
		if len(p.Recent) < 50 {
			p.Recent = append(p.Recent, ev)
		}
	}

	p.MaxSeverity = maxSev.String()
	p.ThreatLevel = threatLevel(p.ThreatScore)
	p.Tools = sortedSet(toolSet)
	p.Anomalies = sortedSet(anomSet)
	p.Mitre = sortedSet(mitreSet)
	p.Tactics = sortedSet(tacticSet)
	p.CVEs = sortedSet(cveSet)
	p.Handlers = sortedSet(handlerSet)
	p.Sensors = sortedSet(sensorSet)
	p.Domains = sortedSet(domainSet)
	p.URLs = sortedSet(urlSet)
	p.Artifacts = sortedSet(artSet)
	p.SSHKeys = sortedSet(sshKeySet)
	p.Emails = sortedSet(emailSet)
	p.AttackClasses = sortedSet(attackClassSet)
	p.Playbooks = sortedSet(playbookSet)
	p.Ports = sortedInts(portSet)
	for r, c := range ruleCount {
		p.Rules = append(p.Rules, countItem{Name: r, Count: c})
	}
	sort.Slice(p.Rules, func(i, j int) bool {
		if p.Rules[i].Count != p.Rules[j].Count {
			return p.Rules[i].Count > p.Rules[j].Count
		}
		return p.Rules[i].Name < p.Rules[j].Name
	})
	if len(rep) > 0 {
		p.Reputation = rep
	}
	p.Proto.TLSVersions = sortedSet(tlsSet)
	p.Proto.QUICSNI = sortedSet(quicSNISet)
	p.Proto.QUICALPN = sortedSet(quicALPNSet)
	p.OPCItems = sortedSet(opcSet)
	if _, weak := anomSet["ssh-kex-weak-primitive"]; weak {
		p.Proto.SSHKexWeak = true
	}
	p.synthesize()
	return p
}

// synthesize derives a higher-level classification + one-line assessment
// from the already-aggregated signals.
func (p *Profile) synthesize() {
	has := func(list []string, want string) bool {
		for _, x := range list {
			if x == want {
				return true
			}
		}
		return false
	}
	anomPrefix := func(prefix string) bool {
		for _, a := range p.Anomalies {
			if strings.HasPrefix(a, prefix) {
				return true
			}
		}
		return false
	}
	anyTool := func(pred func(string) bool) bool {
		for _, t := range p.Tools {
			if pred(t) {
				return true
			}
		}
		return false
	}
	ruleHas := func(sub string) bool {
		for _, r := range p.Rules {
			if strings.Contains(r.Name, sub) {
				return true
			}
		}
		return false
	}

	switch {
	case p.TokenReuse:
		p.Classification = "confirmed compromise — honeytoken reuse"
	case anyTool(toolfp.IsC2) || has(p.Anomalies, "c2-framework"):
		p.Classification = "C2 / red-team framework"
	case len(p.Artifacts) > 0 || has(p.Anomalies, "malware-capture"):
		p.Classification = "malware delivery / staging"
	case len(p.AttackClasses) >= 3:
		p.Classification = "web application attack"
	case len(p.CVEs) > 0 || anomPrefix("webapp:") || has(p.Anomalies, "printer-cups-rce") || has(p.Anomalies, "printer-ipp-cmd-injection"):
		p.Classification = "exploitation attempt"
	case anyTool(toolfp.IsVulnScanner) || has(p.Anomalies, "vulnerability-scanner"):
		p.Classification = "vulnerability scan"
	case ruleHas("brute_force") || ruleHas("password_spray") || len(p.Credentials) >= 5:
		p.Classification = "credential brute-force"
	case has(p.Tactics, "discovery") || has(p.Tactics, "reconnaissance") || len(p.Ports) >= 10 || ruleHas("port_scan") || ruleHas("scananalysis") || anyTool(toolfp.IsHeadless):
		p.Classification = "reconnaissance / scanning"
	case p.Automation:
		p.Classification = "automated client"
	default:
		p.Classification = "manual / unclassified"
	}

	// One-line assessment.
	span := "a single moment"
	if d := p.LastSeen.Sub(p.FirstSeen); d > time.Second {
		span = humanDur(d)
	}
	var extra []string
	if len(p.Tools) > 0 {
		extra = append(extra, "tools: "+strings.Join(p.Tools, ", "))
	}
	if len(p.Credentials) > 0 {
		extra = append(extra, fmt.Sprintf("%d credential(s) tried", len(p.Credentials)))
	}
	if len(p.CVEs) > 0 {
		extra = append(extra, fmt.Sprintf("%d CVE(s): %s", len(p.CVEs), strings.Join(p.CVEs, ", ")))
	}
	if len(p.Artifacts) > 0 {
		extra = append(extra, fmt.Sprintf("%d artifact(s) captured", len(p.Artifacts)))
	}
	if len(p.URLs) > 0 {
		extra = append(extra, fmt.Sprintf("%d C2/dropper URL(s)", len(p.URLs)))
	}
	if len(p.AttackClasses) > 0 {
		extra = append(extra, fmt.Sprintf("%d web-attack class(es)", len(p.AttackClasses)))
	}
	if len(p.SSHKeys) > 0 {
		extra = append(extra, fmt.Sprintf("%d SSH key(s) offered", len(p.SSHKeys)))
	}
	if p.TokenReuse {
		extra = append(extra, "replayed a planted honeytoken")
	}
	suffix := ""
	if len(extra) > 0 {
		suffix = " — " + strings.Join(extra, "; ")
	}
	p.Summary = fmt.Sprintf("%s: %d event(s) over %s, %d port(s) / %d service(s) touched, peak %s severity%s.",
		p.Classification, p.Count, span, len(p.Ports), len(p.Handlers), p.MaxSeverity, suffix)
}

// humanDur renders a duration compactly (e.g. "2h13m", "45s").
func humanDur(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if d >= 24*time.Hour {
		return fmt.Sprintf("%dd%dh", h/24, h%24)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}

// metaStrings coerces meta[key] (which may be a string, []string, or the
// []any JSON decodes to) into a []string.
func metaStrings(meta map[string]any, key string) []string {
	v, ok := meta[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{t}
	}
	return nil
}

// metaInt coerces meta[key] into an int. In-memory events carry an int;
// events round-tripped through the JSON store decode numbers as float64.
func metaInt(meta map[string]any, key string) int {
	switch t := meta[key].(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	}
	return 0
}

// extractCreds pulls every captured credential / secret out of an event's meta
// so it lands on the /captures page and the attacker profile — not just the
// handful of well-known login fields, but anything any handler or Lua persona
// records: passwords, hashes, tickets, tokens, JWTs, community strings, session
// keys, challenges, cookies, API keys, bind DNs, etc. It combines a curated
// pairing pass (for nice user/pass rows) with a generalized classifier over the
// meta key names, so new handlers/scripts are surfaced automatically as long as
// they name the field sensibly (…_user / …_pass / …_token / …_auth / …_hash …).
// metaMapList returns a meta value that is a list of maps, normalizing the two
// shapes it can take: a fresh in-memory []map[string]any, or — after a JSON
// round-trip through the store — a []any of map[string]any.
func metaMapList(meta map[string]any, key string) []map[string]any {
	switch v := meta[key].(type) {
	case []map[string]any:
		return v
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, e := range v {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// Cred is a captured credential surfaced for export (the export-creds CLI). It
// wraps the internal credPair with the originating source + time.
type Cred struct {
	Kind    string `json:"kind" yaml:"kind" xml:"kind"`
	User    string `json:"user,omitempty" yaml:"user,omitempty" xml:"user,omitempty"`
	Secret  string `json:"secret,omitempty" yaml:"secret,omitempty" xml:"secret,omitempty"`
	Service string `json:"service,omitempty" yaml:"service,omitempty" xml:"service,omitempty"`
	Source  string `json:"source,omitempty" yaml:"source,omitempty" xml:"source,omitempty"`
	Time    string `json:"time,omitempty" yaml:"time,omitempty" xml:"time,omitempty"`
}

// ExtractCreds returns the credentials captured in an event (the exported view
// of extractCreds), stamped with the event's source IP + UTC time.
func ExtractCreds(ev *event.Event) []Cred {
	if ev == nil {
		return nil
	}
	pairs := extractCreds(ev)
	if len(pairs) == 0 {
		return nil
	}
	out := make([]Cred, 0, len(pairs))
	for _, c := range pairs {
		out = append(out, Cred{
			Kind:    c.Kind,
			User:    c.User,
			Secret:  c.Pass,
			Service: c.Service,
			Source:  ev.Source.IP,
			Time:    ev.Time.UTC().Format(time.RFC3339),
		})
	}
	return out
}

func extractCreds(ev *event.Event) []credPair {
	meta := ev.Meta
	if len(meta) == 0 {
		return nil
	}
	seen := map[string]bool{} // meta keys already turned into a row
	get := func(keys ...string) string {
		for _, k := range keys {
			if s, ok := meta[k].(string); ok && s != "" {
				seen[k] = true
				return s
			}
		}
		return ""
	}
	// Where the secret came from: the handler/protocol, else the well-known
	// service name for the destination port.
	svc := ev.Handler
	if svc == "" && ev.Dest.Port > 0 {
		svc = portsvc.Name(ev.Dest.Port)
	}
	var out []credPair

	// 1) Curated username / password login pair (the common, non-suffix-shaped
	// field names) — rendered as a single tidy row.
	user := get("user_attempt", "http_login_user", "auth_user", "user_line",
		"basic_user", "form_user", "login_user", "client_user", "remote_user",
		"server_user", "local_user", "ntlm_user", "sip_user", "ami_username",
		"socks_userid", "username", "user", "user_name", "bind_dn", "vrfy_user",
		"accepted_user", "principal")
	pass := get("pass_attempt", "http_login_pass", "auth_pass", "pass_line",
		"basic_pass", "form_pass", "pjl_password", "ami_secret", "password",
		"pass", "bind_pw", "auth_password", "redis_auth")
	if user != "" || pass != "" {
		out = append(out, credPair{Kind: "password", User: user, Pass: pass, Service: svc})
	}

	// 1b) SSH (and other multi-attempt protocols) record each try in an
	// "auth_attempts" list of maps (method / user / password or key fp) rather
	// than flat string keys — surface every attempt as its own credential row so
	// they show on the captures page, not just buried in the event meta.
	for _, a := range metaMapList(meta, "auth_attempts") {
		seen["auth_attempts"] = true
		u, _ := a["user"].(string)
		if m, _ := a["method"].(string); m == "publickey" {
			kt, _ := a["key_type"].(string)
			fp, _ := a["key_fp_sha256"].(string)
			if u != "" || fp != "" {
				out = append(out, credPair{Kind: "ssh-pubkey", User: u, Pass: strings.TrimSpace(kt + " " + fp), Service: svc})
			}
			continue
		}
		p, _ := a["password"].(string)
		if u != "" || p != "" {
			out = append(out, credPair{Kind: "password", User: u, Pass: p, Service: svc})
		}
	}

	// 2) Generic prefix pairing: any "<p>_user(name)" + "<p>_pass(word)" the
	// many Lua personas use (adminer_username/adminer_password,
	// roundcube_user/roundcube_pass, irc_user/irc_pass, …).
	for _, p := range credPrefixPairs(meta, seen) {
		out = append(out, p)
		out[len(out)-1].Service = svc
	}

	// 3) Kerberos pre-auth: the encrypted timestamp is an offline-crackable
	// ticket, keyed to the principal it was minted for.
	if t := get("preauth_enc_timestamp_hex"); t != "" {
		s := svc
		if s == "" {
			s = "kerberos"
		}
		out = append(out, credPair{Kind: "kerberos-ticket", User: get("principal"), Pass: t, Service: s})
	}

	// 4) Everything else: classify each remaining string-valued meta key by its
	// name and emit it. This catches tokens, JWTs, hashes, challenges,
	// communities, cookies, API keys, session keys, and every vendor "*_auth"
	// blob — decoding Basic/Bearer Authorization values into user/pass/token.
	for k, v := range meta {
		if seen[k] {
			continue
		}
		s, ok := v.(string)
		if !ok || s == "" {
			continue
		}
		kind, isCred := classifyCredKey(k)
		if !isCred {
			continue
		}
		seen[k] = true
		if u, p, tok, decoded := decodeAuthValue(s); decoded {
			switch {
			case tok != "":
				out = append(out, credPair{Kind: "token", Pass: tok, Service: svc})
			default:
				out = append(out, credPair{Kind: "password", User: u, Pass: p, Service: svc})
			}
			continue
		}
		out = append(out, credPair{Kind: kind, Pass: s, Service: svc})
	}
	return out
}

// credPrefixPairs finds "<prefix>_user(name)" + "<prefix>_pass(word)" key pairs
// in meta and returns one password credPair per matched prefix, marking both
// keys consumed in seen.
func credPrefixPairs(meta map[string]any, seen map[string]bool) []credPair {
	userSuf := []string{"_username", "_userid", "_user"}
	passSuf := []string{"_password", "_passwd", "_pass", "_pwd"}
	type up struct{ uKey, pKey, u, p string }
	byPrefix := map[string]*up{}
	str := func(k string) (string, bool) {
		s, ok := meta[k].(string)
		return s, ok && s != ""
	}
	for k := range meta {
		if seen[k] {
			continue
		}
		lk := strings.ToLower(k)
		for _, suf := range userSuf {
			if strings.HasSuffix(lk, suf) {
				if s, ok := str(k); ok {
					pfx := lk[:len(lk)-len(suf)]
					if byPrefix[pfx] == nil {
						byPrefix[pfx] = &up{}
					}
					byPrefix[pfx].uKey, byPrefix[pfx].u = k, s
				}
				break
			}
		}
		for _, suf := range passSuf {
			if strings.HasSuffix(lk, suf) {
				if s, ok := str(k); ok {
					pfx := lk[:len(lk)-len(suf)]
					if byPrefix[pfx] == nil {
						byPrefix[pfx] = &up{}
					}
					byPrefix[pfx].pKey, byPrefix[pfx].p = k, s
				}
				break
			}
		}
	}
	var out []credPair
	for _, v := range byPrefix {
		if v.u == "" && v.p == "" {
			continue
		}
		// Only pair (and consume both) when both halves are present; a lone
		// half is left for the generic classifier to emit as a single row.
		if v.u != "" && v.p != "" {
			seen[v.uKey] = true
			seen[v.pKey] = true
			out = append(out, credPair{Kind: "password", User: v.u, Pass: v.p})
		}
	}
	return out
}

// classifyCredKey decides whether a meta key name denotes a credential/secret
// and, if so, what kind. It is conservative: a small exclusion set prevents
// obvious false positives (user_agent, auth_type, …).
func classifyCredKey(key string) (kind string, isCred bool) {
	k := strings.ToLower(key)
	switch k {
	case "user_agent", "auth_type", "auth_accepted", "auth_attempts", "auth_method",
		"automation", "automation_reason", "ntlm_domain", "x11_auth_name":
		return "", false
	}
	has := func(sub string) bool { return strings.Contains(k, sub) }
	suf := func(s string) bool { return strings.HasSuffix(k, s) }
	switch {
	case has("jwt"):
		return "jwt", true
	case has("honeytoken"):
		return "honeytoken", true
	case has("community"):
		return "snmp-community", true
	case has("cookie"):
		return "cookie", true
	case has("ticket") || has("preauth"):
		return "kerberos-ticket", true
	case has("ntlm_response") || has("auth_response") || has("response_hex") ||
		has("challenge_hex") || has("encrypted_hex") || suf("_hash") || has("_hash_"):
		return "hash", true
	case has("challenge") || suf("_nonce"):
		return "challenge", true
	case has("bearer") || suf("_token") || suf("_session") || has("session_key") || k == "token":
		return "token", true
	case has("api_key") || has("apikey") || suf("_secret") || has("session_key") ||
		has("passphrase") || suf("_psk") || has("private_key"):
		return "api-key", true
	case suf("_auth") || k == "authorization" || k == "proxy_authorization" || suf("_pam"):
		return "authorization", true
	case suf("_password") || suf("_passwd") || suf("_pass") || suf("_pwd"):
		return "password", true
	case suf("_user") || suf("_username") || suf("_userid"):
		return "username", true
	}
	return "", false
}

// decodeAuthValue decodes an HTTP Authorization-style value: "Basic <b64>" into
// user/pass, "Bearer <tok>" into a token, or a bare base64 "user:pass" blob.
// Returns decoded=false when the value isn't a recognizable auth blob.
func decodeAuthValue(v string) (user, pass, token string, decoded bool) {
	switch {
	case len(v) > 6 && strings.EqualFold(v[:6], "basic "):
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[6:])); err == nil {
			u, p, _ := strings.Cut(string(raw), ":")
			return u, p, "", true
		}
	case len(v) > 7 && strings.EqualFold(v[:7], "bearer "):
		return "", "", strings.TrimSpace(v[7:]), true
	}
	return "", "", "", false
}

func threatLevel(score int) string {
	switch {
	case score >= 200:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 15:
		return "elevated"
	default:
		return "low"
	}
}

func sortedSet(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedInts(m map[int]struct{}) []int {
	if len(m) == 0 {
		return nil
	}
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// ---- handlers ----

type profilesPage struct {
	Profiles []store.SourceAggregate
	SinceStr string
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	since := profileListWindow
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = d
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	aggs, err := s.store.SourceAggregates(ctx, time.Now().Add(-since), 200)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	aggs = s.visibleAggregates(aggs) // presentation hide list
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := profilesPage{Profiles: aggs, SinceStr: r.URL.Query().Get("since")}
	if err := s.tmpl.ExecuteTemplate(w, "profiles", page); err != nil {
		slog.Warn("ui: render profiles", "err", err)
	}
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/profiles/")
	if ip == "" || s.hides(ip) { // presentation hide list
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	evs, err := s.query(ctx, store.Filter{
		SourceIP: ip,
		Since:    time.Now().Add(-profileDetailWindow),
		Limit:    profileDetailMax,
	})
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	p := buildProfile(ip, evs)
	p.Partial = len(evs) >= profileDetailMax

	// The "triggered rules" table is sortable by rule name or count via
	// ?rsort=rule|count&rorder=asc|desc (server-side; the packaged app.js
	// can also sort client-side as progressive enhancement).
	rsort := r.URL.Query().Get("rsort")
	if rsort != "rule" {
		rsort = "count"
	}
	rorder := r.URL.Query().Get("rorder")
	if rorder != "asc" {
		rorder = "desc"
	}
	sortRules(p.Rules, rsort, rorder)

	view := profileView{
		Profile: p,
		RuleHeaders: ruleHeaders{
			Rule:  ruleSortHeader(ip, "rule", rsort, rorder),
			Count: ruleSortHeader(ip, "count", rsort, rorder),
		},
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "profile", view); err != nil {
		slog.Warn("ui: render profile", "err", err)
	}
}

// profileView wraps a Profile (embedded, so the template's field access is
// unchanged) with the triggered-rules sort header links.
type profileView struct {
	Profile
	RuleHeaders ruleHeaders
}

type ruleHeaders struct{ Rule, Count sortLink }

type sortLink struct {
	Href  string
	Arrow string
}

func sortRules(rules []countItem, by, order string) {
	asc := order == "asc"
	sort.Slice(rules, func(i, j int) bool {
		var less bool
		if by == "rule" {
			less = rules[i].Name < rules[j].Name
		} else {
			if rules[i].Count != rules[j].Count {
				less = rules[i].Count < rules[j].Count
			} else {
				less = rules[i].Name < rules[j].Name
			}
		}
		if asc {
			return less
		}
		return !less
	})
}

// ruleSortHeader builds the toggle link + arrow for a triggered-rules column.
func ruleSortHeader(ip, col, curSort, curOrder string) sortLink {
	next := "desc"
	arrow := ""
	if curSort == col {
		if curOrder == "desc" {
			next = "asc"
			arrow = " ▼"
		} else {
			arrow = " ▲"
		}
	}
	return sortLink{
		Href:  fmt.Sprintf("/profiles/%s?rsort=%s&rorder=%s", ip, col, next),
		Arrow: arrow,
	}
}

func (s *Server) handleAPIProfiles(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	aggs, err := s.store.SourceAggregates(ctx, time.Now().Add(-profileListWindow), 500)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	aggs = s.visibleAggregates(aggs) // presentation hide list
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(aggs)
}

func (s *Server) handleAPIProfile(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/api/profiles/")
	if ip == "" || s.hides(ip) { // presentation hide list
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	evs, err := s.query(ctx, store.Filter{
		SourceIP: ip,
		Since:    time.Now().Add(-profileDetailWindow),
		Limit:    profileDetailMax,
	})
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	p := buildProfile(ip, evs)
	p.Partial = len(evs) >= profileDetailMax
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}
