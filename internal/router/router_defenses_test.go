package router

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// Dispatch is the single chokepoint that stamps ATT&CK techniques AND
// D3FEND defenses, so events synthesized outside the sensor bus loop
// (device:new, malware:capture, scananalysis:profile, test-alert) get
// both. Regression test for the centralization fix.
func TestDispatchStampsMitreDefenses(t *testing.T) {
	r, err := New(&config.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{"malware:capture", "scananalysis:profile", "device:new"} {
		ev := &event.Event{RuleID: rule, Source: event.Endpoint{IP: "9.9.9.9"}}
		r.Dispatch(ev)
		if len(ev.MitreTechniques) == 0 {
			t.Errorf("%s: techniques not stamped", rule)
		}
		if len(ev.MitreDefenses) == 0 {
			t.Errorf("%s: D3FEND defenses not stamped", rule)
		}
	}
}

// An already-tagged event keeps its techniques but still gets defenses
// computed from them.
func TestDispatchDefensesFromExistingTechniques(t *testing.T) {
	r, _ := New(&config.Config{}, nil)
	ev := &event.Event{RuleID: "custom", MitreTechniques: []string{"T1110"}}
	r.Dispatch(ev)
	if len(ev.MitreDefenses) == 0 {
		t.Error("defenses should be derived from pre-set techniques")
	}
}
