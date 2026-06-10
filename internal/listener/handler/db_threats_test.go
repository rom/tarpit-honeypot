package handler

import "testing"

func TestMySQLQueryClassifier(t *testing.T) {
	cases := []struct {
		q, anom string
	}{
		{"select sys_exec('id')", "mysql-udf-exec"},
		{"select '<?php system($_GET[0]);?>' into outfile '/var/www/x.php'", "mysql-outfile-write"},
		{"select * from mysql.user", "mysql-credential-dump"},
		{"select * from users where id=1 union select 1,2,3", "mysql-sqli-probe"},
	}
	for _, c := range cases {
		res := Result{Meta: map[string]any{}}
		classifyMySQLQuery(&res, c.q)
		if !hasAnom(res, c.anom) {
			t.Errorf("query %q: missing %s (%v)", c.q, c.anom, res.Meta["anomalies"])
		}
	}
	// my.cnf injection via OUTFILE -> CVE.
	res := Result{Meta: map[string]any{}}
	classifyMySQLQuery(&res, "select '[mysqld]\\nmalloc_lib=/tmp/x.so' into outfile '/etc/my.cnf'")
	if !hasAnom(res, "cve:CVE-2016-6662") {
		t.Errorf("my.cnf injection not flagged: %v", res.Meta["anomalies"])
	}
}

func TestRedisClassifyExtra(t *testing.T) {
	mk := func(cmds ...[]string) Result {
		res := Result{Meta: map[string]any{}}
		auth := false
		for _, c := range cmds {
			redisClassifyExtra(&res, c, &auth)
		}
		return res
	}
	if r := mk([]string{"EVAL", "local f = package.loadlib('/lib/x.so','x'); f()", "0"}); !hasAnom(r, "redis-lua-sandbox-escape") || !hasAnom(r, "cve:CVE-2022-0543") {
		t.Errorf("Lua escape not flagged: %v", r.Meta["anomalies"])
	}
	if r := mk([]string{"CONFIG", "SET", "dir", "/var/www/html"}); !hasAnom(r, "redis-rce-persistence") {
		t.Errorf("CONFIG SET dir not flagged: %v", r.Meta["anomalies"])
	}
	if r := mk([]string{"KEYS", "*"}); !hasAnom(r, "redis-bulk-dump") || !hasAnom(r, "redis-unauthenticated-access") {
		t.Errorf("bulk dump / unauth not flagged: %v", r.Meta["anomalies"])
	}
	// After AUTH, a later command must not be flagged unauthenticated.
	if r := mk([]string{"AUTH", "p"}, []string{"CONFIG", "SET", "x", "y"}); hasAnom(r, "redis-unauthenticated-access") {
		t.Errorf("post-AUTH command wrongly flagged unauthenticated: %v", r.Meta["anomalies"])
	}
}

func TestMongoAbuseExtended(t *testing.T) {
	cases := map[string]string{
		"drop":         "mongodb-write-or-ransom",
		"insert":       "mongodb-write-or-ransom",
		"usersInfo":    "mongodb-admin-enum",
		"serverStatus": "mongodb-admin-enum",
		"mapReduce":    "mongodb-server-side-js",
		"find":         "mongodb-data-access",
	}
	for cmd, want := range cases {
		if got := mongoAbuse(cmd); got != want {
			t.Errorf("mongoAbuse(%q) = %q; want %q", cmd, got, want)
		}
	}
}
