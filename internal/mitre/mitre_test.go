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
	if !contains(AnomalyTag("ssh-id-overlong").Techniques, "T1595") {
		t.Error("ssh-id-overlong should map to active-scanning T1595")
	}
	if len(AnomalyTag("totally-unknown-marker-xyz").Techniques) != 0 {
		t.Error("an unmapped anomaly should map to nothing")
	}
}

// TestTCPStackCoverage guards the userspace-TCP-stack ATT&CK mappings: the
// rule_ids, the explicit packet anomalies, the tcp-/ip- prefix fallback,
// and the LAND -> endpoint-DoS attribution.
func TestTCPStackCoverage(t *testing.T) {
	if got := Lookup("honeynet:tcp_malformed", "").Techniques; !contains(got, "T1046") || !contains(got, "T1595.001") {
		t.Errorf("tcp_malformed = %v; want T1046 + T1595.001", got)
	}
	if got := Lookup("honeynet:tcp_land", "").Techniques; len(got) != 1 || got[0] != "T1499" {
		t.Errorf("tcp_land = %v; want [T1499]", got)
	}
	for _, m := range []string{"tcp-null", "tcp-fin-scan", "tcp-xmas", "tcp-syn-fin", "ip-fragmented"} {
		if !contains(AnomalyTag(m).Techniques, "T1595.001") {
			t.Errorf("%q should map to active-scanning T1595.001: %v", m, AnomalyTag(m).Techniques)
		}
	}
	if !contains(AnomalyTag("tcp-land").Techniques, "T1499") {
		t.Errorf("tcp-land should map to endpoint DoS T1499")
	}
	// Prefix fallback for any future tcp-/ip- marker.
	if !contains(AnomalyTag("tcp-future-marker").Techniques, "T1046") {
		t.Errorf("tcp- prefix fallback missing")
	}
	if !contains(AnomalyTag("ip-future-marker").Techniques, "T1595.001") {
		t.Errorf("ip- prefix fallback missing")
	}
	// LAND maps to an endpoint-DoS D3FEND control.
	if d := DefensesFor([]string{"T1499"}); len(d) == 0 {
		t.Errorf("T1499 should have a D3FEND mapping")
	}
}

// TestShellAndInteractiveCoverage guards the post-login TTP capture: every
// shell-* marker must carry an ATT&CK technique (explicit or via the shell-
// prefix fallback), and ssh_interactive must map like ssh (not the T1190
// listener default).
func TestShellAndInteractiveCoverage(t *testing.T) {
	if got := Lookup("listener:s", "ssh_interactive").Techniques; len(got) == 0 || got[0] != "T1110.001" {
		t.Errorf("ssh_interactive = %v; want ssh-like T1110.001", got)
	}
	shellMarkers := []string{
		"shell-reverse-shell", "shell-credential-dump", "shell-passwd-read",
		"shell-persistence-cron", "shell-persistence-systemd", "shell-priv-esc-suid",
		"shell-defender-tamper", "shell-coin-miner", "shell-ad-recon",
		"shell-ps-encoded", "shell-download-tool", "shell-future-unmapped-marker",
	}
	for _, m := range shellMarkers {
		if len(AnomalyTag(m).Techniques) == 0 {
			t.Errorf("shell marker %q has no ATT&CK technique", m)
		}
	}
	for _, m := range []string{"bacnet-write-attempt", "udp-amplifier-probe", "honeyfile-download"} {
		if len(AnomalyTag(m).Techniques) == 0 {
			t.Errorf("%q has no ATT&CK technique", m)
		}
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

func TestDescribe(t *testing.T) {
	if d := Describe("T1190"); d == "" {
		t.Error("T1190 should have a description")
	}
	// Sub-technique falls back to its base.
	if d := Describe("T1110.001"); d == "" || d != Describe("T1110") {
		t.Errorf("T1110.001 should fall back to T1110 description, got %q", d)
	}
	if d := Describe("T9999"); d != "" {
		t.Errorf("unknown technique should return empty, got %q", d)
	}
}
