package handler

import "testing"

// TestPHP2ShellDetection locks in recognition of the PHP2Shell request
// artifacts (CVE-2026-109618 / -109619 / -115560) and the WordPress core
// upgrade-race staged-installer probe (CVE-2026-119977). Detection only.
func TestPHP2ShellDetection(t *testing.T) {
	cases := []struct {
		name, line string
		body       string
		wantAnom   string
		wantCVE    string
	}{
		{
			"session-upload-progress",
			"POST /index.php HTTP/1.1",
			"PHP_SESSION_UPLOAD_PROGRESS=probe",
			"webapp:php2shell-session-upload-progress", "CVE-2026-109619",
		},
		{
			"session-deserialize",
			"POST /index.php HTTP/1.1",
			`PHP_SESSION_UPLOAD_PROGRESS=|O:8:"Evil":1:{}`,
			"webapp:php2shell-session-deserialize", "CVE-2026-115560",
		},
		{
			"oom-nested-param",
			"GET /index.php?x[0][0][0][0][0][0]=1 HTTP/1.1",
			"",
			"webapp:php2shell-oom-trigger", "CVE-2026-109618",
		},
		{
			"wp-upgrade-staged",
			"GET /wp-content/upgrade/wordpress/wp-admin/setup-config.php HTTP/1.1",
			"",
			"webapp:wordpress-core-upgrade-rce", "CVE-2026-119977",
		},
		{
			"wp-installer-step",
			"GET /wp-admin/setup-config.php?step=1 HTTP/1.1",
			"",
			"webapp:wordpress-core-upgrade-rce", "CVE-2026-119977",
		},
	}
	for _, c := range cases {
		anoms, cves := phpAnoms(c.line, []byte(c.body))
		if !containsStr(anoms, c.wantAnom) {
			t.Errorf("%s: expected anomaly %q; got %v", c.name, c.wantAnom, anoms)
		}
		if !containsStr(cves, c.wantCVE) {
			t.Errorf("%s: expected CVE %q; got %v", c.name, c.wantCVE, cves)
		}
	}
}

// TestPHP2ShellNoFalsePositive guards the conservative heuristics: an ordinary
// shallow array param and a bare installer path (no staging / no step) must not
// trip the PHP2Shell / WordPress-upgrade detectors.
func TestPHP2ShellNoFalsePositive(t *testing.T) {
	anoms, cves := phpAnoms("GET /index.php?tags[0]=a&tags[1]=b HTTP/1.1", nil)
	if containsStr(anoms, "webapp:php2shell-oom-trigger") {
		t.Errorf("shallow array param wrongly flagged as OOM trigger: %v", anoms)
	}
	anoms, cves = phpAnoms("GET /wp-admin/setup-config.php HTTP/1.1", nil)
	if containsStr(anoms, "webapp:wordpress-core-upgrade-rce") {
		t.Errorf("bare installer path wrongly flagged as upgrade-race: %v", anoms)
	}
	_ = cves
}
