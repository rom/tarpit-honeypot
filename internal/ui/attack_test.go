package ui

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestBuildTechniqueView(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{RuleID: "listener:web", Handler: "http", Time: now, Source: event.Endpoint{IP: "2.2.2.2"},
			Meta: map[string]any{"anomalies": []any{"webapp:sqli"}}},
		{RuleID: "listener:web", Handler: "http", Time: now, Source: event.Endpoint{IP: "2.2.2.2"}},
		{RuleID: "listener:ssh", Handler: "ssh", Time: now, Source: event.Endpoint{IP: "9.9.9.9"}}, // no T1190
	}
	v := buildTechniqueView("T1190", now.Add(-time.Hour), evs)
	if v.ID != "T1190" || v.Description == "" {
		t.Fatalf("technique view missing id/description: %+v", v)
	}
	if v.Events != 2 {
		t.Errorf("events = %d; want 2 (the two http events)", v.Events)
	}
	// 2.2.2.2 must appear as a source; 9.9.9.9 (ssh, no T1190) must not.
	var has222, has999 bool
	for _, b := range v.Sources {
		if b.Label == "2.2.2.2" {
			has222 = true
		}
		if b.Label == "9.9.9.9" {
			has999 = true
		}
	}
	if !has222 || has999 {
		t.Errorf("sources wrong: %+v (want 2.2.2.2, not 9.9.9.9)", v.Sources)
	}
	if len(v.Sources) > 0 && v.Sources[0].Href != "/profiles/2.2.2.2" {
		t.Errorf("source href = %q; want /profiles/2.2.2.2", v.Sources[0].Href)
	}
}

func TestValidTechniqueID(t *testing.T) {
	for _, ok := range []string{"T1190", "T1110.001", "T0814"} {
		if !validTechniqueID(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "X1190", "T", "T1190;DROP", "1190", "T11.9.9", "../etc"} {
		if validTechniqueID(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestExtractCredsCarriesService(t *testing.T) {
	ev := &event.Event{Handler: "ssh", Meta: map[string]any{"username": "root", "password": "toor"}}
	got := extractCreds(ev)
	if len(got) != 1 || got[0].Service != "ssh" || got[0].User != "root" {
		t.Errorf("extractCreds = %+v; want one {root, toor, ssh}", got)
	}
	// Falls back to the port's service name when handler is empty.
	ev2 := &event.Event{Dest: event.Endpoint{Port: 21}, Meta: map[string]any{"user_line": "anonymous"}}
	if g := extractCreds(ev2); len(g) != 1 || g[0].Service != "ftp" {
		t.Errorf("port-fallback service = %+v; want ftp", g)
	}
}

func TestBuildAttackView(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		// ssh handler → T1110.001 (credential-access) + T1078 (initial-access)
		{RuleID: "listener:ssh", Handler: "ssh", Time: now, Source: event.Endpoint{IP: "1.1.1.1"}},
		// http handler → T1190/T1083, augmented by a webapp:sqli anomaly (T1190).
		{RuleID: "listener:web", Handler: "http", Time: now, Source: event.Endpoint{IP: "2.2.2.2"},
			Meta: map[string]any{"anomalies": []any{"webapp:sqli"}}},
		// a storyline chain
		{RuleID: "storyline:multi_stage", Handler: "", Time: now, Source: event.Endpoint{IP: "3.3.3.3"},
			Meta: map[string]any{"chain": "discovery -> credential-access -> lateral-movement"}},
	}
	v := buildAttackView(now.Add(-time.Hour), evs)

	if v.Events < 2 {
		t.Fatalf("expected >=2 attributed events, got %d", v.Events)
	}
	// credential-access tactic should be present (from ssh).
	var hasCred bool
	for _, tac := range v.Tactics {
		if tac.Tactic == "credential-access" {
			hasCred = true
		}
	}
	if !hasCred {
		t.Errorf("credential-access tactic missing: %+v", v.Tactics)
	}
	// T1190 technique should rank in the heatmap (http + sqli).
	var hasT1190 bool
	for _, b := range v.TopTech {
		if b.Label == "T1190" {
			hasT1190 = true
		}
	}
	if !hasT1190 {
		t.Errorf("T1190 missing from technique heatmap: %+v", v.TopTech)
	}
	if len(v.Chains) != 1 || !strings.Contains(v.Chains[0].Chain, "lateral-movement") {
		t.Errorf("storyline chain not captured: %+v", v.Chains)
	}
	// Native ATT&CK matrix: at least one tactic column with technique cells.
	if len(v.Matrix) == 0 {
		t.Fatalf("ATT&CK matrix empty: %+v", v.Matrix)
	}
	var matrixHasCell bool
	for _, col := range v.Matrix {
		for _, c := range col.Cells {
			if c.ID != "" && c.Count > 0 && c.Level >= 0 && c.Level <= 4 {
				matrixHasCell = true
			}
		}
	}
	if !matrixHasCell {
		t.Errorf("matrix has no valid technique cells: %+v", v.Matrix)
	}

	// Template renders.
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "attack", v); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"ATT&amp;CK mapping", "tactic timeline", "credential-access", "technique heatmap"} {
		if !strings.Contains(html, want) {
			t.Errorf("attack page missing %q", want)
		}
	}
}

func TestBuildPunchcard(t *testing.T) {
	// Two events on the same weekday/hour, one on another hour.
	base := time.Date(2026, 1, 5, 14, 0, 0, 0, time.UTC) // Monday 14:00 UTC
	evs := []*event.Event{
		{Time: base}, {Time: base.Add(20 * time.Minute)}, {Time: base.Add(3 * time.Hour)},
	}
	fig := buildPunchcard(evs)
	if fig.Type != "heatmap" || fig.B64 == "" {
		t.Fatalf("punchcard figure malformed: %+v", fig)
	}
	raw, err := base64.StdEncoding.DecodeString(fig.B64)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Rows  []string `json:"rows"`
		Cols  []string `json:"cols"`
		Cells [][]int  `json:"cells"`
		Max   int      `json:"max"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Rows) != 7 || len(data.Cols) != 24 || len(data.Cells) != 7 {
		t.Fatalf("grid shape wrong: %d rows, %d cols, %d cell-rows", len(data.Rows), len(data.Cols), len(data.Cells))
	}
	// Monday (row 0) hour 14 should have 2 events; max should be 2.
	if data.Cells[0][14] != 2 || data.Max != 2 {
		t.Errorf("Mon 14:00 = %d (max %d), want 2/2", data.Cells[0][14], data.Max)
	}
}

func TestAttackViewTacticsKillChainOrder(t *testing.T) {
	now := time.Now()
	// Mix: impact (modbus T0814) + initial-access (http) + credential-access (ssh).
	evs := []*event.Event{
		{RuleID: "listener:a", Handler: "ssh", Time: now},
		{RuleID: "listener:b", Handler: "http", Time: now},
		{RuleID: "listener:c", Handler: "modbus", Time: now},
	}
	v := buildAttackView(now.Add(-time.Hour), evs)
	// Tactics must come back in reconnaissance→impact rank order.
	for i := 1; i < len(v.Tactics); i++ {
		if v.Tactics[i-1].Rank > v.Tactics[i].Rank {
			t.Fatalf("tactics not in kill-chain order: %+v", v.Tactics)
		}
	}
}
