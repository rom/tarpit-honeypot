package mitre

import (
	"sort"
	"strings"
	"testing"
)

// TestCoverageWellFormed: every flattened mapping must carry at least one
// technique + tactic, and the list must be sorted by (kind, key) so the
// CLI `list-techniques` output is stable.
func TestCoverageWellFormed(t *testing.T) {
	cov := Coverage()
	if len(cov) == 0 {
		t.Fatal("Coverage() is empty")
	}
	var keys []string
	for _, e := range cov {
		if e.Kind == "" || e.Key == "" {
			t.Errorf("entry with empty kind/key: %+v", e)
		}
		if len(e.Techniques) == 0 || len(e.Tactics) == 0 {
			t.Errorf("%s/%s has no techniques/tactics", e.Kind, e.Key)
		}
		keys = append(keys, e.Kind+"\x00"+e.Key)
	}
	if !sort.StringsAreSorted(keys) {
		t.Error("Coverage() not sorted by (kind,key)")
	}
}

// TestCoverageHasPrinterAndProtocolMisuse spot-checks that the v2.0
// detections are represented in the coverage map.
func TestCoverageHasPrinterAndProtocolMisuse(t *testing.T) {
	want := []string{"printer-cups-rce", "snmp-set-attempt", "dns-zone-transfer", "tftp-write-attempt"}
	have := map[string]bool{}
	for _, e := range Coverage() {
		have[e.Key] = true
	}
	for _, k := range want {
		if !have[k] {
			t.Errorf("coverage map missing %q", k)
		}
	}
}

// TestAnomalyTagPrinterPrefix: unmapped printer- markers fall back to the
// discovery prefix rule rather than returning an empty tag.
func TestAnomalyTagPrinterPrefix(t *testing.T) {
	tag := AnomalyTag("printer-something-new")
	if len(tag.Techniques) == 0 || !strings.HasPrefix(tag.Techniques[0], "T") {
		t.Errorf("printer- prefix fallback missing: %+v", tag)
	}
}
