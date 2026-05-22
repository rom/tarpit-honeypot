package store

import (
	"context"
	"strings"
	"time"
)

// Fingerprint reputation: roll up every event that carries a given network
// fingerprint (JA3 / JA4 / JA4H / JA3S / HASSH / HASSH-server) so an analyst
// can pivot from "which client TLS/SSH stack" to where it has been seen —
// across source IPs, ASNs, countries, protocols, ports, attack types,
// malware, and which sensors in the fleet observed it.

// fingerprintKinds is the allowlist of meta keys that hold a fingerprint,
// each mapped to its fixed JSON path. The kind is validated against this map
// so user-supplied input never reaches the SQL string — only the fingerprint
// VALUE is bound as a parameter.
var fingerprintKinds = map[string]string{
	"ja3":          "$.ja3",
	"ja4":          "$.ja4",
	"ja4h":         "$.ja4h",
	"ja3s":         "$.ja3s",
	"hassh":        "$.hassh",
	"hassh_server": "$.hassh_server",
}

// fingerprintKindOrder fixes the listing order (map iteration is random).
var fingerprintKindOrder = []string{"ja3", "ja4", "ja4h", "ja3s", "hassh", "hassh_server"}

// FingerprintKindKnown reports whether kind is an allowlisted fingerprint key.
func FingerprintKindKnown(kind string) bool {
	_, ok := fingerprintKinds[kind]
	return ok
}

// fingerprintPath returns the JSON path for an allowlisted kind, or "".
func fingerprintPath(kind string) string { return fingerprintKinds[kind] }

// FingerprintRow is one entry in the fingerprint index: a single fingerprint
// value of a given kind with cheap cross-cutting counts.
type FingerprintRow struct {
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	Count     int       `json:"events"`
	IPs       int       `json:"distinct_ips"`
	Sensors   int       `json:"distinct_sensors"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Fingerprints lists the most-seen fingerprints across all kinds since the
// given time, ordered by event count. One GROUP BY pass per kind, UNION'd.
func (s *Store) Fingerprints(ctx context.Context, since time.Time, limit int) ([]FingerprintRow, error) {
	sinceNS := since.UTC().UnixNano()
	var (
		selects []string
		args    []any
	)
	for _, kind := range fingerprintKindOrder {
		path := fingerprintKinds[kind]
		// Guard json_extract with json_valid: events stored with no meta have
		// meta_json = '' (not NULL), and json_extract('', …) raises "malformed
		// JSON" — which would fail the whole query. The CASE makes json_extract
		// run only on valid-JSON rows, regardless of WHERE-term ordering.
		val := "CASE WHEN json_valid(meta_json) THEN json_extract(meta_json,'" + path + "') END"
		selects = append(selects, `
SELECT '`+kind+`' AS kind, `+val+` AS val,
       COUNT(*) AS c, COUNT(DISTINCT src_ip) AS ips, COUNT(DISTINCT sensor) AS sensors,
       MIN(time) AS firstns, MAX(time) AS lastns
FROM events
WHERE time >= ? AND `+val+` IS NOT NULL AND `+val+` <> ''
GROUP BY val`)
		args = append(args, sinceNS)
	}
	q := "SELECT kind, val, c, ips, sensors, firstns, lastns FROM (" +
		strings.Join(selects, " UNION ALL ") + ") ORDER BY c DESC, lastns DESC"
	if limit > 0 {
		q += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FingerprintRow
	for rows.Next() {
		var (
			r               FingerprintRow
			firstNS, lastNS int64
		)
		if err := rows.Scan(&r.Kind, &r.Value, &r.Count, &r.IPs, &r.Sensors, &firstNS, &lastNS); err != nil {
			return nil, err
		}
		r.FirstSeen = time.Unix(0, firstNS).UTC()
		r.LastSeen = time.Unix(0, lastNS).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}
