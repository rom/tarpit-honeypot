package mitre

import "testing"

func TestLookupListenerByHandler(t *testing.T) {
	cases := map[string][]string{
		"ssh":    {"T1110.001", "T1078"},
		"http":   {"T1190", "T1083"},
		"smb":    {"T1021.002", "T1135"},
		"snmp":   {"T1018", "T1110.001"},
		"modbus": {"T0814", "T0888"},
	}
	for handler, want := range cases {
		got := Lookup("listener:bait", handler)
		if len(got.Techniques) != len(want) {
			t.Errorf("%s: got %v, want %v", handler, got.Techniques, want)
			continue
		}
		for i, w := range want {
			if got.Techniques[i] != w {
				t.Errorf("%s: techniques[%d] = %s; want %s", handler, i, got.Techniques[i], w)
			}
		}
	}
}

func TestLookupUnknownHandlerStillTagsInitialAccess(t *testing.T) {
	got := Lookup("listener:bait", "does-not-exist")
	if len(got.Techniques) == 0 {
		t.Errorf("unknown handler should still get T1190 fallback")
	}
}

func TestLookupExactRules(t *testing.T) {
	t1 := Lookup("correlate:port_scan", "")
	if len(t1.Techniques) != 1 || t1.Techniques[0] != "T1046" {
		t.Errorf("port_scan = %v; want [T1046]", t1.Techniques)
	}
	t2 := Lookup("correlate:brute_force", "")
	if len(t2.Techniques) != 1 || t2.Techniques[0] != "T1110" {
		t.Errorf("brute_force = %v; want [T1110]", t2.Techniques)
	}
}

func TestLookupCanaries(t *testing.T) {
	if got := Lookup("canary:url:abc", "http"); len(got.Techniques) == 0 {
		t.Errorf("URL canary should tag T1083/T1190")
	}
	if got := Lookup("canary:dns:xyz", ""); len(got.Techniques) == 0 {
		t.Errorf("DNS canary should tag T1071.004")
	}
}

func TestLookupStorylineNoDoubleTag(t *testing.T) {
	got := Lookup("storyline:multi_stage", "")
	if len(got.Techniques) != 0 {
		t.Errorf("storyline events should not double-tag")
	}
}

func TestTacticRankOrdering(t *testing.T) {
	// discovery comes after credential-access in the kill chain
	// position but logically before lateral-movement.
	rDisc := TacticRank("discovery")
	rCred := TacticRank("credential-access")
	rLat := TacticRank("lateral-movement")
	rImp := TacticRank("impact")
	if !(rCred < rDisc && rDisc < rLat && rLat < rImp) {
		t.Errorf("kill-chain order wrong: cred=%d disc=%d lat=%d imp=%d",
			rCred, rDisc, rLat, rImp)
	}
	if TacticRank("nonexistent") != -1 {
		t.Errorf("unknown tactic should return -1")
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestAugmentAnomalies(t *testing.T) {
	// http handler base tag (T1190/T1083) + a SQLi + command-injection
	// anomaly should union T1190 (already) + T1059.
	base := Lookup("listener:web", "http")
	tag := Augment(base, []string{"webapp:cmdi", "default-credential-attempt"})
	if !contains(tag.Techniques, "T1059") {
		t.Errorf("cmdi anomaly should add T1059: %v", tag.Techniques)
	}
	if !contains(tag.Techniques, "T1078.001") {
		t.Errorf("default-cred anomaly should add T1078.001: %v", tag.Techniques)
	}
	// No duplicate base technique.
	n := 0
	for _, x := range tag.Techniques {
		if x == "T1190" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("T1190 duplicated: %v", tag.Techniques)
	}
}

func TestAnomalyTagPrefixes(t *testing.T) {
	if !contains(AnomalyTag("modbus-write-attempt").Techniques, "T0836") {
		t.Error("modbus-write-attempt should map to T0836")
	}
	if !contains(AnomalyTag("uri-path-traversal").Techniques, "T1083") {
		t.Error("uri- prefix should map to discovery")
	}
	if !contains(AnomalyTag("ics-atg-command").Techniques, "T0888") {
		t.Error("ics- prefix should map to T0888")
	}
	if len(AnomalyTag("ssh-id-overlong").Techniques) != 0 {
		t.Error("noise anomaly should map to nothing")
	}
}

func TestNewHandlerTags(t *testing.T) {
	for _, h := range []string{"atg", "fox", "hartip", "pcworx", "redfish", "x11", "rlogin", "vmware_authd"} {
		if len(Lookup("listener:x", h).Techniques) == 0 {
			t.Errorf("handler %q has no ATT&CK mapping", h)
		}
	}
}

func TestDefensesForNewTechniques(t *testing.T) {
	if len(DefensesFor([]string{"T1059", "T1219", "T0836"})) == 0 {
		t.Error("new techniques should have D3FEND mappings")
	}
}
