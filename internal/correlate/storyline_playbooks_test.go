package correlate

import "testing"

// Every name storyPlaybook can return must have a human-facing registry entry,
// so a playbook tag in the UI is never a dead link. (The list is the exhaustive
// set of return values in storyPlaybook.)
func TestPlaybookRegistryCoversStoryPlaybook(t *testing.T) {
	names := []string{
		"credential-replay-compromise", "ad-coerced-authentication-relay",
		"ad-lateral-movement-psexec", "redis-rogue-replica-rce", "smb-wormable-exploit",
		"database-to-rce", "ot-kill-chain", "cloud-credential-takeover",
		"ransomware-style-destruction", "dns-tunneling", "data-exfiltration",
		"dos-amplification", "web-exploit-to-shell", "edge-appliance-exploitation",
		"malware-delivery", "web-vuln-fuzzing", "credential-harvest",
	}
	for _, n := range names {
		p, ok := PlaybookInfo(n)
		if !ok {
			t.Errorf("storyPlaybook name %q has no registry entry", n)
			continue
		}
		if p.Title == "" || p.Short == "" || p.Long == "" || len(p.Tactics) == 0 || p.NextSteps == "" {
			t.Errorf("playbook %q has an incomplete entry: %+v", n, p)
		}
	}
	if len(AllPlaybooks()) != len(names) {
		t.Errorf("registry has %d entries; the known storyPlaybook set has %d", len(AllPlaybooks()), len(names))
	}
}
