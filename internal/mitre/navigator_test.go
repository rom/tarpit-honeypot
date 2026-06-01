package mitre

import (
	"encoding/json"
	"testing"
)

func TestNavigatorStaticCoverage(t *testing.T) {
	layer := Navigator(nil)
	if layer.Domain != "enterprise-attack" {
		t.Errorf("domain = %q, want enterprise-attack", layer.Domain)
	}
	if len(layer.Techniques) == 0 {
		t.Fatal("static layer has no techniques")
	}
	// Every static technique scores 1 and is enabled.
	for _, tq := range layer.Techniques {
		if tq.Score != 1 {
			t.Errorf("static technique %s score = %d, want 1", tq.TechniqueID, tq.Score)
		}
		if !tq.Enabled {
			t.Errorf("technique %s should be enabled", tq.TechniqueID)
		}
	}
	// A technique we know the catalog maps (T1190 initial-access) must appear.
	if !navHasTechnique(layer, "T1190") {
		t.Errorf("expected T1190 in static coverage")
	}
}

func TestNavigatorObservedScoresByCount(t *testing.T) {
	observed := map[string]int{"T1190": 7, "T9999": 3} // T9999 is not in the catalog
	layer := Navigator(observed)
	byID := map[string]NavTechnique{}
	for _, tq := range layer.Techniques {
		byID[tq.TechniqueID] = tq
	}
	if byID["T1190"].Score != 7 {
		t.Errorf("T1190 observed score = %d, want 7", byID["T1190"].Score)
	}
	// An observed technique outside the static catalog must still be included.
	if _, ok := byID["T9999"]; !ok {
		t.Errorf("observed-only technique T9999 was dropped")
	}
	if byID["T9999"].Score != 3 {
		t.Errorf("T9999 score = %d, want 3", byID["T9999"].Score)
	}
	// Gradient max should track the largest count.
	if layer.Gradient.MaxValue != 7 {
		t.Errorf("gradient max = %d, want 7", layer.Gradient.MaxValue)
	}
}

func TestNavigatorJSONValid(t *testing.T) {
	b, err := NavigatorJSON(map[string]int{"T1059": 2})
	if err != nil {
		t.Fatal(err)
	}
	var round NavigatorLayer
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("emitted Navigator JSON does not round-trip: %v", err)
	}
	if round.Name == "" || len(round.Techniques) == 0 {
		t.Errorf("round-tripped layer is empty")
	}
}

func navHasTechnique(l NavigatorLayer, id string) bool {
	for _, tq := range l.Techniques {
		if tq.TechniqueID == id {
			return true
		}
	}
	return false
}
