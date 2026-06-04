package enrich

import (
	"bufio"
	"os"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Fingerprint→client/tool attribution. The handlers compute JA3 / JA4 / JA4H /
// HASSH fingerprints; on their own those are opaque hashes. A fingerprint
// database (FoxIO's JA4DB, the community JA3 corpus, a HASSH list) maps each to
// the client application / library / malware that produces it. When a loaded DB
// recognizes an event's fingerprint, Decorate tags it `<kind>_client` (e.g.
// ja4_client = "Chrome", ja3_client = "Cobalt Strike") — turning a raw hash
// into named attribution.
//
// Each source file is one fingerprint per line: "<fingerprint><sep><label>"
// where sep is a comma or tab (label may contain spaces). Blank lines and
// '#' comments are ignored. The fetch-enrichment.sh helper converts the
// upstream JA4DB JSON / JA3 CSV into this normalized form.

// FingerprintSource is one labeled fingerprint file for a given kind.
type FingerprintSource struct {
	Kind string // ja3 | ja4 | ja4h | hassh | hassh_server | ja3s
	File string
}

// fpDB maps fingerprint kind -> fingerprint value -> client/tool label.
type fpDB map[string]map[string]string

// loadFingerprintDB builds the fingerprint→label lookup from the configured
// sources. Missing/unreadable files are logged by the caller and skipped.
func loadFingerprintDB(srcs []FingerprintSource) (fpDB, int, []error) {
	db := fpDB{}
	var errs []error
	total := 0
	for _, s := range srcs {
		if s.Kind == "" || s.File == "" {
			continue
		}
		m, err := loadFingerprintFile(s.File)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if db[s.Kind] == nil {
			db[s.Kind] = map[string]string{}
		}
		for fp, label := range m {
			db[s.Kind][fp] = label
		}
		total += len(m)
	}
	return db, total, errs
}

func loadFingerprintFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fp, label := splitFingerprintLine(line)
		if fp != "" && label != "" {
			out[fp] = label
		}
	}
	return out, sc.Err()
}

// splitFingerprintLine splits "<fingerprint><comma|tab><label>".
func splitFingerprintLine(line string) (fp, label string) {
	sep := strings.IndexAny(line, ",\t")
	if sep < 0 {
		return "", ""
	}
	return strings.TrimSpace(line[:sep]), strings.TrimSpace(line[sep+1:])
}

// lookup returns the client/tool label for a fingerprint of the given kind.
func (db fpDB) lookup(kind, fp string) string {
	if db == nil || fp == "" {
		return ""
	}
	if m := db[kind]; m != nil {
		return m[fp]
	}
	return ""
}

// fpKinds is the set of fingerprint meta keys checked against the DB.
var fpKinds = []string{"ja3", "ja4", "ja4h", "ja3s", "hassh", "hassh_server"}

// decorateFingerprints tags an event with the client/tool behind each of its
// fingerprints, when a loaded DB recognizes them.
func (e *Enricher) decorateFingerprints(ev *event.Event) {
	if len(e.fpdb) == 0 {
		return
	}
	for _, kind := range fpKinds {
		fp, _ := ev.Meta[kind].(string)
		if fp == "" {
			continue
		}
		if label := e.fpdb.lookup(kind, fp); label != "" {
			ev.Meta[kind+"_client"] = label
		}
	}
}
