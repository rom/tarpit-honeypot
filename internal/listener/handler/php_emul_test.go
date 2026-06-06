package handler

import "testing"

func phpAnoms(line string, body []byte) ([]string, []string) {
	res := Result{Meta: map[string]any{}}
	_ = serveWebapp(line, body, "nginx", nil, &res)
	anoms, _ := res.Meta["anomalies"].([]string)
	return anoms, res.CVEHits
}

func TestPHPVulnEmulation(t *testing.T) {
	cases := []struct {
		name, line string
		body       []byte
		want       string
	}{
		{"php-filter", "GET /download.php?file=php://filter/convert.base64-encode/resource=config.php HTTP/1.1", nil, "webapp:php-filter-wrapper"},
		{"php-input", "GET /index.php?page=php://input HTTP/1.1", nil, "webapp:php-wrapper-rce"},
		{"phar", "GET /download.php?file=phar://uploads/evil.phar/x HTTP/1.1", nil, "webapp:php-phar-deserialize"},
		{"log-poison", "GET /download.php?file=/proc/self/environ HTTP/1.1", nil, "webapp:lfi-log-poison"},
		{"source-backup", "GET /config.inc.php.bak HTTP/1.1", nil, "webapp:php-source-disclosure"},
		{"eval-stdin", "POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1", []byte("<?php system('id'); ?>"), "webapp:php-eval-stdin"},
		{"php-cgi-2012", "GET /index.php?-d+allow_url_include%3don+-d+auto_prepend_file%3dphp://input HTTP/1.1", nil, "webapp:php-cgi-arg-injection"},
	}
	for _, c := range cases {
		anoms, _ := phpAnoms(c.line, c.body)
		if !containsStr(anoms, c.want) {
			t.Errorf("%s: expected %q; anomalies=%v", c.name, c.want, anoms)
		}
	}
}

func TestPHPCGICVEMapping(t *testing.T) {
	// Classic CVE-2012-1823.
	_, cves := phpAnoms("GET /index.php?-dallow_url_include=1 HTTP/1.1", nil)
	if !containsStr(cves, "CVE-2012-1823") {
		t.Errorf("CVE-2012-1823 not flagged; cves=%v", cves)
	}
	// Windows best-fit soft-hyphen variant CVE-2024-4577.
	_, cves = phpAnoms("GET /index.php?%ADd+allow_url_include%3D1 HTTP/1.1", nil)
	if !containsStr(cves, "CVE-2024-4577") {
		t.Errorf("CVE-2024-4577 not flagged; cves=%v", cves)
	}
	// PHPUnit eval-stdin RCE.
	_, cves = phpAnoms("POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1", []byte("<?php phpinfo();"))
	if !containsStr(cves, "CVE-2017-9841") {
		t.Errorf("CVE-2017-9841 not flagged; cves=%v", cves)
	}
}
