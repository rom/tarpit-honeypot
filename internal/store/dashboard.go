package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// Dashboard facets: the cross-cutting rollups the summary page needs that the
// plain Summary doesn't already cover (ATT&CK tactics/techniques, CVEs,
// attacks-by-service, geo city, ASN, network operator, tools, and per-port
// service-board activity).
//
// These used to be computed Go-side by pulling up to ui_scan_limit (default
// 20k) recent event rows — meta_json included — and counting them in a loop.
// That read dominated the summary build as the table grew, and it only ever
// *sampled* (newest N), so a long window was never fully accurate. DashboardFacets
// pushes the counting into SQL GROUP BY passes instead: the single-valued/array
// dimensions (city/ASN/operator/tools/port) are aggregated and top-N-trimmed in
// the engine, and the logic-bearing dimensions that need Go (ATT&CK
// augmentation, the multi-source CVE extraction, the attack predicate) are
// returned as a *grouped* set — one row per distinct (rule, handler, proto,
// severity, anomalies, meta-anomalies, emulated-CVEs) tuple with its count — so
// the UI applies the exact same Go logic once per distinct signature instead of
// once per event. Honeypot traffic is highly repetitive in those fields, so the
// grouped set is orders of magnitude smaller than the event count while giving
// full-window-accurate totals.

// AttackFacet is one distinct event "signature" and how many events share it.
// The UI reconstructs a minimal event from these fields and runs its existing
// ATT&CK / CVE / attack-classification helpers once per facet, scaled by Count.
type AttackFacet struct {
	RuleID        string
	Handler       string
	Proto         string
	Severity      int
	Anomalies     []string // the anomalies column
	MetaAnomalies []string // meta.anomalies (ATT&CK augmentation reads these)
	EmulatedCVEs  []string // meta.emulated_vuln_cves
	Count         int
}

// ASNFacet is a per-(AS number, operator) rollup; the UI formats the display
// label ("AS13335 Cloudflare") and the pivot link itself.
type ASNFacet struct {
	Num   int
	Org   string
	Count int
}

// DashboardFacets bundles the summary page's SQL-aggregated cross-cutting
// rollups. The map dimensions are already top-N trimmed (by count) to what the
// UI displays; Attacks is the grouped signature set (count-ordered, capped by
// the caller's limit); Ports is every destination port that saw an event.
type DashboardFacets struct {
	Attacks []AttackFacet
	Cities  map[string]int
	ASNOrgs map[string]int
	Tools   map[string]int
	ASNs    []ASNFacet
	Ports   map[int]int
}

// FacetTopN is how many rows each single/array meta dimension is trimmed to in
// SQL. The dashboard renders the top ~10 of each; the generous headroom keeps
// both the displayed ranking and its share-of-total denominator effectively
// identical to the old full-map count whenever a dimension has at most this
// many distinct values (the common case: a handful of countries / tools / ASNs).
const FacetTopN = 50

// DashboardFacets runs the summary page's cross-cutting GROUP BY passes. limit
// caps the returned attack-signature set (0 → a generous default); the
// single/array meta dimensions are always trimmed to FacetTopN in the engine.
func (s *Store) DashboardFacets(ctx context.Context, since time.Time, limit int) (DashboardFacets, error) {
	if limit <= 0 {
		limit = 20000
	}
	sinceNS := since.UTC().UnixNano()
	f := DashboardFacets{
		Cities:  map[string]int{},
		ASNOrgs: map[string]int{},
		Tools:   map[string]int{},
		Ports:   map[int]int{},
	}

	// Attack signatures: one row per distinct (rule, handler, proto, severity,
	// anomalies, meta.anomalies, meta.emulated_vuln_cves). The JSON columns are
	// grouped as their stored text; the UI parses them back and applies its
	// ATT&CK/CVE/attack logic per signature, scaled by count.
	attackRows, err := s.db.QueryContext(ctx, `
SELECT rule_id, handler, proto, severity,
       anomalies,
       CASE WHEN json_valid(meta_json) THEN json_extract(meta_json,'$.anomalies') END,
       CASE WHEN json_valid(meta_json) THEN json_extract(meta_json,'$.emulated_vuln_cves') END,
       COUNT(*) c
FROM events
WHERE time >= ?
GROUP BY rule_id, handler, proto, severity, anomalies, 6, 7
ORDER BY c DESC
LIMIT ?`, sinceNS, limit)
	if err != nil {
		return f, err
	}
	for attackRows.Next() {
		var (
			a                       AttackFacet
			handler, proto          sql.NullString
			anomJSON, metaAnom, cve sql.NullString
		)
		if err := attackRows.Scan(&a.RuleID, &handler, &proto, &a.Severity,
			&anomJSON, &metaAnom, &cve, &a.Count); err != nil {
			attackRows.Close()
			return f, err
		}
		a.Handler = handler.String
		a.Proto = proto.String
		a.Anomalies = ParseJSONStrings(anomJSON.String)
		a.MetaAnomalies = ParseJSONStrings(metaAnom.String)
		a.EmulatedCVEs = ParseJSONStrings(cve.String)
		f.Attacks = append(f.Attacks, a)
	}
	attackRows.Close()
	if err := attackRows.Err(); err != nil {
		return f, err
	}

	// Geo city + network operator (single-valued meta scalars).
	if f.Cities, err = s.metaScalarCounts(ctx, "$.geo_city", sinceNS, FacetTopN); err != nil {
		return f, err
	}
	if f.ASNOrgs, err = s.metaScalarCounts(ctx, "$.asn_org", sinceNS, FacetTopN); err != nil {
		return f, err
	}

	// ASN: grouped by (number, operator) so the UI can format the label + the
	// numeric pivot link exactly as the old per-event asnLabel did.
	asnRows, err := s.db.QueryContext(ctx, `
SELECT CASE WHEN json_valid(meta_json) THEN json_extract(meta_json,'$.asn') END num,
       CASE WHEN json_valid(meta_json) THEN json_extract(meta_json,'$.asn_org') END org,
       COUNT(*) c
FROM events
WHERE time >= ?
GROUP BY num, org
HAVING (num IS NOT NULL AND num <> 0) OR (org IS NOT NULL AND org <> '')
ORDER BY c DESC
LIMIT ?`, sinceNS, FacetTopN)
	if err != nil {
		return f, err
	}
	for asnRows.Next() {
		var (
			num sql.NullInt64
			org sql.NullString
			c   int
		)
		if err := asnRows.Scan(&num, &org, &c); err != nil {
			asnRows.Close()
			return f, err
		}
		f.ASNs = append(f.ASNs, ASNFacet{Num: int(num.Int64), Org: org.String, Count: c})
	}
	asnRows.Close()
	if err := asnRows.Err(); err != nil {
		return f, err
	}

	// Tools: the meta.tools array, unnested and counted.
	toolRows, err := s.db.QueryContext(ctx, `
SELECT je.value, COUNT(*) c
FROM events, json_each(CASE WHEN json_valid(meta_json) THEN json_extract(meta_json,'$.tools') END) je
WHERE time >= ? AND je.value <> ''
GROUP BY je.value
ORDER BY c DESC
LIMIT ?`, sinceNS, FacetTopN)
	if err != nil {
		return f, err
	}
	for toolRows.Next() {
		var k string
		var c int
		if err := toolRows.Scan(&k, &c); err != nil {
			toolRows.Close()
			return f, err
		}
		f.Tools[k] = c
	}
	toolRows.Close()
	if err := toolRows.Err(); err != nil {
		return f, err
	}

	// Per-destination-port activity for the service board. Few distinct ports
	// (one per listener), so no top-N trim beyond a safety cap.
	portRows, err := s.db.QueryContext(ctx, `
SELECT dst_port, COUNT(*) FROM events
WHERE time >= ? AND dst_port > 0
GROUP BY dst_port
ORDER BY 2 DESC
LIMIT 1000`, sinceNS)
	if err != nil {
		return f, err
	}
	for portRows.Next() {
		var port, c int
		if err := portRows.Scan(&port, &c); err != nil {
			portRows.Close()
			return f, err
		}
		f.Ports[port] = c
	}
	portRows.Close()
	if err := portRows.Err(); err != nil {
		return f, err
	}

	return f, nil
}

// metaScalarCounts is a GROUP BY over a single JSON scalar meta field, trimmed
// to the top-n by count. The json_valid guard skips rows with empty meta
// (stored as ” not NULL, which json_extract would reject).
func (s *Store) metaScalarCounts(ctx context.Context, path string, sinceNS int64, n int) (map[string]int, error) {
	out := map[string]int{}
	// path is a fixed caller-supplied literal (never user input), matching the
	// json_extract guard pattern used elsewhere in this package.
	val := "CASE WHEN json_valid(meta_json) THEN json_extract(meta_json,'" + path + "') END"
	rows, err := s.db.QueryContext(ctx, `
SELECT v, COUNT(*) c FROM (SELECT `+val+` v FROM events WHERE time >= ?)
WHERE v IS NOT NULL AND v <> ''
GROUP BY v ORDER BY c DESC LIMIT ?`, sinceNS, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var c int
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		out[k] = c
	}
	return out, rows.Err()
}

// ParseJSONStrings decodes a stored JSON string array ("" / "null" → nil).
// Exported so an alternate backend parses the grouped JSON-array columns
// (anomalies / meta.anomalies / meta.emulated_vuln_cves) exactly as the SQLite
// engine does.
func ParseJSONStrings(s string) []string {
	if s == "" || s == "null" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}
