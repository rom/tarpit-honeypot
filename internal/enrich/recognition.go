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
	case boolMeta(m, "threat_intel_hit"):
		return "suspect"
	}
	return ""
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
	if boolMeta(m, "novel_asn") {
		add("novel-asn")
	}
	if boolMeta(m, "novel_subnet") {
		add("novel-subnet")
	}
	if cls := metaString(m, "source_class"); cls != "" {
		add("class:" + cls)
	}
	sort.Strings(out)
	return out
}
