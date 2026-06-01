package mitre

import (
	"encoding/json"
	"fmt"
	"sort"
)

// NavigatorLayer is the subset of the MITRE ATT&CK Navigator layer schema
// (https://github.com/mitre-attack/attack-navigator) we emit. An analyst loads
// the produced JSON at https://mitre-attack.github.io/attack-navigator/ to see
// a heatmap of the techniques this sensor covers (or has observed).
type NavigatorLayer struct {
	Name         string          `json:"name"`
	Versions     NavVersions     `json:"versions"`
	Domain       string          `json:"domain"`
	Description  string          `json:"description"`
	Techniques   []NavTechnique  `json:"techniques"`
	Gradient     NavGradient     `json:"gradient"`
	LegendItems  []NavLegendItem `json:"legendItems,omitempty"`
	SortMode     int             `json:"sorting"`
	HideDisabled bool            `json:"hideDisabledTechniques"`
}

type NavVersions struct {
	Layer     string `json:"layer"`
	Attack    string `json:"attack"`
	Navigator string `json:"navigator"`
}

type NavTechnique struct {
	TechniqueID string `json:"techniqueID"`
	Score       int    `json:"score"`
	Color       string `json:"color,omitempty"`
	Comment     string `json:"comment,omitempty"`
	Enabled     bool   `json:"enabled"`
}

type NavGradient struct {
	Colors   []string `json:"colors"`
	MinValue int      `json:"minValue"`
	MaxValue int      `json:"maxValue"`
}

type NavLegendItem struct {
	Label string `json:"label"`
	Color string `json:"color"`
}

// Navigator builds an ATT&CK Navigator layer. When observed is non-nil it is a
// map of technique-id -> hit count from the event store, and each technique's
// score is its observed count (an "what actually fired, and how often" heatmap);
// the comment notes the count. When observed is nil the layer reflects static
// coverage — every technique this sensor can attribute scores 1 (a "what we can
// detect" map). A technique present in observed but not in the static catalog
// (e.g. a sub-technique rolled up) is still included so nothing fired is hidden.
func Navigator(observed map[string]int) NavigatorLayer {
	// Collect the static set of techniques this sensor can attribute.
	static := map[string]struct{}{}
	for _, e := range Coverage() {
		for _, t := range e.Techniques {
			static[t] = struct{}{}
		}
	}

	// Union of static + observed so an observed technique is never dropped.
	all := map[string]struct{}{}
	for t := range static {
		all[t] = struct{}{}
	}
	for t := range observed {
		all[t] = struct{}{}
	}
	ids := make([]string, 0, len(all))
	for t := range all {
		ids = append(ids, t)
	}
	sort.Strings(ids)

	maxScore := 1
	techs := make([]NavTechnique, 0, len(ids))
	for _, id := range ids {
		nt := NavTechnique{TechniqueID: id, Enabled: true}
		if observed != nil {
			n := observed[id]
			nt.Score = n
			if n > 0 {
				nt.Comment = fmt.Sprintf("%d event(s) observed", n)
			}
			if n > maxScore {
				maxScore = n
			}
		} else {
			nt.Score = 1 // static coverage: present = 1
		}
		techs = append(techs, nt)
	}

	name := "tarpit-honeypot coverage"
	desc := "Techniques this sensor can attribute (static coverage)."
	if observed != nil {
		name = "tarpit-honeypot observed"
		desc = "Techniques observed in this sensor's events, scored by hit count."
	}
	return NavigatorLayer{
		Name:         name,
		Versions:     NavVersions{Layer: "4.5", Attack: "14", Navigator: "4.9.1"},
		Domain:       "enterprise-attack",
		Description:  desc,
		Techniques:   techs,
		SortMode:     3, // descending by score
		HideDisabled: false,
		Gradient: NavGradient{
			Colors:   []string{"#dddddd", "#fde725", "#d62728"},
			MinValue: 0,
			MaxValue: maxScore,
		},
		LegendItems: []NavLegendItem{
			{Label: "covered / observed", Color: "#fde725"},
		},
	}
}

// NavigatorJSON renders the layer as indented JSON ready to drop into the
// ATT&CK Navigator.
func NavigatorJSON(observed map[string]int) ([]byte, error) {
	return json.MarshalIndent(Navigator(observed), "", "  ")
}
