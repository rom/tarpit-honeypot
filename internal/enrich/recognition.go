package enrich

import (
	"sort"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// decorateRecognition adds the recognition rollup derived from everything the
// rest of the pipeline set: a single headline source_class and a compact,
// machine-readable labels[] tag set. labels flow to every sink (JSON / CEF /
// LEEF / OCSF / webhook); the web UI maps them to glyphs. source_class is set
// first so it can also appear as a label.
func decorateRecognition(ev *event.Event) {
	if ev == nil || len(ev.Meta) == 0 {
		return
	}
	if cls := sourceClass(ev); cls != "" {
		ev.Meta["source_class"] = cls
	}
	if labels := sourceLabels(ev); len(labels) > 0 {
		ev.Meta["labels"] = labels
	}
}

// sourceClass collapses the enrichment signals into one headline label for the
// source, most-severe first. "" when nothing notable is known.
func sourceClass(ev *event.Event) string {
	m := ev.Meta
	malicious := metaString(m, "threat_confidence") == "high" ||
		strings.HasPrefix(ev.RuleID, "malware:") || strings.HasPrefix(ev.RuleID, "cve:")
	switch {
	case malicious:
		return "malicious"
	case boolMeta(m, "spoofed_ptr"):
		return "spoofed"
	case metaString(m, "known_scanner") != "":
		return "scanner"
	case boolMeta(m, "anonymized") || boolMeta(m, "tor_exit"):
		return "anonymizer"
	case metaString(m, "cloud_provider") != "" ||
		metaString(m, "net_class") == "hosting" ||
		metaString(m, "conn_type") == "hosting":
		return "hosting"
	case metaString(m, "conn_type") == "residential":
		return "residential"
	case boolMeta(m, "threat_intel_hit"), hasAny(m, "asn_reputation"):
		return "suspect"
	}
	return ""
}

// hasAny reports whether meta key k holds a non-empty []string.
func hasAny(m map[string]any, k string) bool {
	v, ok := m[k].([]string)
	return ok && len(v) > 0
}

// sourceLabels builds the compact, deterministic (sorted) tag set carried to
// sinks. Each tag is a short "kind" or "kind:value" token the UI can render as
// a glyph and a SIEM can filter on.
func sourceLabels(ev *event.Event) []string {
	m := ev.Meta
	var out []string
	add := func(s string) { out = append(out, s) }

	if cc := metaString(m, "geo_country"); cc != "" {
		add("geo:" + cc)
	}
	if boolMeta(m, "geo_risk") {
		add("geo-risk")
	}
	if asn := metaASNKey(m); asn != "" {
		add(strings.ToLower(asn)) // e.g. "as13335"
	}
	if boolMeta(m, "tor_exit") {
		add("tor")
	}
	if boolMeta(m, "anonymized") {
		add("anonymized")
	}
	if a := metaString(m, "anonymizer"); a != "" {
		add("anon:" + a)
	}
	if reps, ok := m["asn_reputation"].([]string); ok {
		for _, r := range reps {
			add("asnrep:" + r)
		}
	}
	if cp := metaString(m, "cloud_provider"); cp != "" {
		add("cloud:" + cp)
	}
	if ks := metaString(m, "known_scanner"); ks != "" {
		add("scanner:" + ks)
	}
	if nc := metaString(m, "net_class"); nc != "" {
		add("netclass:" + nc)
	}
	if ct := metaString(m, "conn_type"); ct != "" {
		add("conn:" + ct)
	}
	if tc := metaString(m, "threat_confidence"); tc != "" {
		add("threat:" + tc)
	}
	if boolMeta(m, "spoofed_ptr") {
		add("spoofed-ptr")
	}
	if vc := metaString(m, "verified_crawler"); vc != "" {
		add("crawler:" + vc)
	}
	if t := metaString(m, "targeting"); t != "" {
		add("target:" + t)
	}
	if cc := metaString(m, "cred_class"); cc != "" {
		add("cred:" + cc)
	}
	if boolMeta(m, "dns_dga") {
		add("dns-dga")
	}
	if boolMeta(m, "domain_bad") {
		add("domain-bad")
	}
	if boolMeta(m, "asn_geo_mismatch") {
		add("asn-geo-mismatch")
	}
	if at := metaString(m, "asn_type"); at != "" {
		add("asntype:" + at)
	}
	if boolMeta(m, "novel_asn") {
		add("novel-asn")
	}
	if boolMeta(m, "novel_subnet") {
		add("novel-subnet")
	}
	if cls := metaString(m, "source_class"); cls != "" {
		add("class:" + cls)
	}
	// Composite "meta:" signals: cross-relate ≥2 independent enrichment signals
	// into higher-order triage labels that no single signal expresses.
	for _, s := range metaSignals(ev) {
		add(s)
	}
	sort.Strings(out)
	return out
}

// metaSignals cross-relates the per-event enrichment signals into composite
// "meta:*" labels — each requires two or more independent corroborating
// signals, so it carries more triage weight than any single label. These are
// the meta-level extractions: deliberate-deception, multi-feed corroboration,
// and hidden/rented-infra probing of high-value targets.
func metaSignals(ev *event.Event) []string {
	m := ev.Meta
	var out []string

	hidden := boolMeta(m, "anonymized") || boolMeta(m, "tor_exit") ||
		metaString(m, "anonymizer") != ""
	rented := metaString(m, "cloud_provider") != "" ||
		metaString(m, "net_class") == "hosting" ||
		metaString(m, "conn_type") == "hosting"

	// Deliberate misrepresentation of origin (spoofed crawler PTR, ASN↔geo
	// mismatch, or a residential PTR on a hosting net-class).
	if boolMeta(m, "spoofed_ptr") || boolMeta(m, "asn_geo_mismatch") ||
		(metaString(m, "conn_type") == "residential" && metaString(m, "net_class") == "hosting") {
		out = append(out, "meta:deceptive-origin")
	}

	// Multiple independent reputation signals agree this source is bad.
	corr := 0
	if metaString(m, "threat_confidence") == "high" {
		corr++
	}
	if boolMeta(m, "threat_intel_hit") || hasAny(m, "threat_intel") {
		corr++
	}
	if hasAny(m, "asn_reputation") {
		corr++
	}
	if boolMeta(m, "domain_bad") {
		corr++
	}
	if boolMeta(m, "spoofed_ptr") {
		corr++
	}
	if corr >= 2 {
		out = append(out, "meta:corroborated-threat")
	}

	// Unified OT umbrella: any event that reached an ICS/BAS/medtech handler
	// (set by decorateOTClass, handler-based + IP-independent) carries meta:ot.
	if boolMeta(m, "ot") {
		out = append(out, "meta:ot")
	}
	// Unified AI umbrella: any event that engaged an AI/LLM/agent decoy.
	if boolMeta(m, "ai") {
		out = append(out, "meta:ai")
	}

	// High-value target probed with any recon/hostile-origin signal — the OT /
	// database / remote-access recon pattern defenders most want surfaced. The
	// context is deliberately broad (not just hidden/rented infra): a scanner or
	// automation fingerprint, a reputation hit, or a never-seen-before ASN
	// touching an OT/DB/remote-access target is already reconnaissance worth the
	// label. A plain residential/direct touch with no such signal is not.
	scannerish := metaString(m, "known_scanner") != "" || hasAny(m, "tools") ||
		boolMeta(m, "fp_tool") || metaString(m, "tls_automation") != ""
	suspicious := boolMeta(m, "threat_intel_hit") || hasAny(m, "threat_intel") ||
		metaString(m, "threat_confidence") == "high" || hasAny(m, "asn_reputation") ||
		boolMeta(m, "domain_bad")
	novel := boolMeta(m, "novel_asn")
	reconCtx := hidden || rented || scannerish || suspicious || novel
	switch metaString(m, "targeting") {
	case "ics-ot", "database", "remote-access", "healthcare":
		if reconCtx {
			out = append(out, "meta:targeted-recon")
			switch metaString(m, "targeting") {
			case "ics-ot":
				out = append(out, "meta:ot-recon")
			case "healthcare":
				out = append(out, "meta:medtech-recon")
			}
		}
	}

	// A captured weak/default/breached login paired with a remote-access or
	// cloud/devops target: a credential-stuffing / spray foothold attempt.
	switch metaString(m, "cred_class") {
	case "default", "weak", "breach":
		switch metaString(m, "targeting") {
		case "remote-access", "cloud-devops":
			out = append(out, "meta:credential-foothold")
		}
	}
	return out
}
