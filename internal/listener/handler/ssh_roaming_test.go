package handler

import "testing"

func TestOpenSSHRoamingVulnerable(t *testing.T) {
	vuln := []string{
		"SSH-2.0-OpenSSH_5.4",
		"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2",
		"SSH-2.0-OpenSSH_7.1p2 Debian-2",
		"SSH-2.0-OpenSSH_7.0",
	}
	safe := []string{
		"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10",
		"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1",
		"SSH-2.0-OpenSSH_5.3",
		"SSH-2.0-OpenSSH_9.6",
		"SSH-2.0-libssh2_1.10",
		"SSH-2.0-PuTTY_Release_0.76",
		"",
	}
	for _, b := range vuln {
		if _, ok := openSSHRoamingVulnerable(b); !ok {
			t.Errorf("%q: expected roaming-vulnerable", b)
		}
	}
	for _, b := range safe {
		if _, ok := openSSHRoamingVulnerable(b); ok {
			t.Errorf("%q: should not be flagged roaming-vulnerable", b)
		}
	}

	// flagSSHRoaming stamps the CVE hits + anomaly + version meta.
	res := &Result{Meta: map[string]any{}}
	flagSSHRoaming(res, "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2")
	if !appendUniqueContains(res.CVEHits, "CVE-2016-0777") || !appendUniqueContains(res.CVEHits, "CVE-2016-0778") {
		t.Errorf("CVE hits not recorded: %v", res.CVEHits)
	}
	if !hasAnom(*res, "ssh-roaming-vulnerable-client") {
		t.Errorf("roaming anomaly not flagged: %v", res.Meta["anomalies"])
	}
	if res.Meta["ssh_client_openssh_version"] != "6.6" {
		t.Errorf("version meta = %v, want 6.6", res.Meta["ssh_client_openssh_version"])
	}

	// A patched client is left untouched.
	clean := &Result{Meta: map[string]any{}}
	flagSSHRoaming(clean, "SSH-2.0-OpenSSH_9.6")
	if len(clean.CVEHits) != 0 {
		t.Errorf("patched client wrongly flagged: %v", clean.CVEHits)
	}
}

func appendUniqueContains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}
