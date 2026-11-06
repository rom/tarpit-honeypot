package enrich

import (
	"bufio"
	"os"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// asnInfoRec is the operator-supplied metadata for one ASN.
type asnInfoRec struct {
	country  string // ISO 3166-1 alpha-2 (registered country of the ASN)
	category string // free-form class: hosting / isp / mobile / edu / gov / cdn
}

// loadASNInfo reads an "ASN,country[,category]" file (comma- or tab-separated;
// the ASN may be "AS<n>" or "<n>"; '#' comments and blanks ignored) into a map.
// This powers asn_country / asn_type and the asn_geo_mismatch flag. There is no
// bundled no-auth default for this data, so it is operator-supplied (e.g. from
// iptoasn.com or an IPinfo/MaxMind export reshaped to this form).
func loadASNInfo(path string) (map[uint32]asnInfoRec, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	out := map[uint32]asnInfoRec{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == '\t' })
		if len(fields) < 2 {
			continue
		}
		asn := extractASN(strings.TrimSpace(fields[0]))
		if asn == 0 {
			continue
		}
		rec := asnInfoRec{country: strings.ToUpper(strings.TrimSpace(fields[1]))}
		if len(fields) >= 3 {
			rec.category = strings.ToLower(strings.TrimSpace(fields[2]))
		}
		out[asn] = rec
	}
	if serr := sc.Err(); serr != nil {
		return nil, 0, serr
	}
	return out, len(out), nil
}

// decorateASNInfo tags asn_country / asn_type from the operator ASN-info map
// and flags asn_geo_mismatch when the ASN's registered country differs from
// the IP's GeoIP country — a sign of leased / hijacked / anycast space.
func (e *Enricher) decorateASNInfo(ev *event.Event) {
	if len(e.asnInfo) == 0 {
		return
	}
	asn, ok := ev.Meta["asn"].(uint32)
	if !ok || asn == 0 {
		return
	}
	rec, ok := e.asnInfo[asn]
	if !ok {
		return
	}
	if rec.country != "" {
		ev.Meta["asn_country"] = rec.country
		if gc := metaString(ev.Meta, "geo_country"); gc != "" && gc != rec.country {
			ev.Meta["asn_geo_mismatch"] = true
		}
	}
	if rec.category != "" {
		ev.Meta["asn_type"] = rec.category
	}
}
