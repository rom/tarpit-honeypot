package sensor

import "testing"

// enrichmentRiskBonus maps the enricher's high-signal source tags to extra
// per-event risk weight: a spoofed-crawler PTR and the cross-feed
// threat_confidence (additively).
func TestEnrichmentRiskBonus(t *testing.T) {
	cases := []struct {
		name string
		meta map[string]any
		want float64
	}{
		{"nil", nil, 0},
		{"clean", map[string]any{"geo_country": "US"}, 0},
		{"conf-low", map[string]any{"threat_confidence": "low"}, riskBonusThreatConfLow},
		{"conf-medium", map[string]any{"threat_confidence": "medium"}, riskBonusThreatConfMed},
		{"conf-high", map[string]any{"threat_confidence": "high"}, riskBonusThreatConfHigh},
		{"spoofed-only", map[string]any{"spoofed_ptr": true}, riskBonusSpoofedPTR},
		{"spoofed-false", map[string]any{"spoofed_ptr": false}, 0},
		{
			"spoofed+high", // additive
			map[string]any{"spoofed_ptr": true, "threat_confidence": "high"},
			riskBonusSpoofedPTR + riskBonusThreatConfHigh,
		},
		{"unknown-conf", map[string]any{"threat_confidence": "bogus"}, 0},
	}
	for _, c := range cases {
		if got := enrichmentRiskBonus(c.meta); got != c.want {
			t.Errorf("%s: enrichmentRiskBonus = %v; want %v", c.name, got, c.want)
		}
	}
}
