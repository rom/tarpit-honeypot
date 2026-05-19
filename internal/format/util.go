package format

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/rom/tarpit-honeypot/internal/safe"
)

// sortedMetaKeys returns the meta map's keys in stable order so the same
// event renders to identical bytes on every Format() call. Important for
// downstream dedup and for our own tests.
func sortedMetaKeys(m map[string]any) []string {
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

// metaToString collapses an arbitrary meta value to a single-line string
// suitable for CEF/LEEF extension values. Maps and slices get rendered
// as compact JSON. All string-typed leaves are passed through
// safe.SanitizeForLog so attacker-supplied control characters / ANSI
// escapes / log-injection newlines can't impersonate trusted log lines
// once the event reaches a syslog or webhook sink.
func metaToString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return safe.SanitizeForLog(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int, int32, int64, uint, uint32, uint64, float32, float64:
		return fmt.Sprintf("%v", t)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	// JSON-marshalled compounds are safe by construction (json.Marshal
	// escapes control chars) but truncate so a single huge value
	// doesn't fill the SIEM record.
	return safe.SanitizeForLog(string(b))
}
