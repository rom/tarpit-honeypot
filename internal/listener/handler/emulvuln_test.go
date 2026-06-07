package handler

import (
	"slices"
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/identity"
)

// The 20+ new emulated-vulnerability endpoints must each return believable loot
// and flag the probe (a secret-file-probe for leaked files, or a specific
// exposure anomaly for management/debug endpoints).
func TestWebappEmulatedVulnEndpoints(t *testing.T) {
	id := identity.New("emulvuln-test")
	type tc struct {
		path     string
		wantBody string // substring expected in the response body
		anomaly  string // anomaly that must be flagged
	}
	cases := []tc{
		{"/.git/HEAD", "refs/heads/main", "webapp:secret-file-probe"},
		{"/.svn/entries", "svn.example.internal", "webapp:secret-file-probe"},
		{"/.htpasswd", "admin:$apr1$", "webapp:secret-file-probe"},
		{"/web.config", "connectionString", "webapp:secret-file-probe"},
		{"/WEB-INF/web.xml", "jdbc:mysql", "webapp:secret-file-probe"},
		{"/.aws/credentials", "aws_secret_access_key", "webapp:secret-file-probe"},
		{"/.ssh/id_rsa", "OPENSSH PRIVATE KEY", "webapp:secret-file-probe"},
		{"/docker-compose.yml", "MYSQL_ROOT_PASSWORD", "webapp:secret-file-probe"},
		{"/.env.production", "DB_PASSWORD", "webapp:secret-file-probe"},
		{"/server-status", "Apache Server Status", "webapp:apache-status-exposed"},
		{"/server-info", "Apache Server Information", "webapp:apache-info-exposed"},
		{"/actuator/env", "datasource.password", "webapp:spring-actuator-exposed"},
		{"/jolokia/version", "\"agent\"", "webapp:jolokia-exposed"},
		{"/solr/admin/cores", "instanceDir", "webapp:solr-admin-exposed"},
		{"/debug/pprof/", "/debug/pprof/", "webapp:pprof-exposed"},
		{"/metrics", "go_goroutines", "webapp:metrics-exposed"},
		{"/telescope/requests", "Telescope", "webapp:laravel-telescope-exposed"},
		{"/_profiler/abc", "Symfony Profiler", "webapp:symfony-profiler-exposed"},
		{"/manager/html", "", "webapp:tomcat-manager-probe"},
		{"/.env.local", "APP_KEY", "webapp:secret-file-probe"},
	}
	if len(cases) < 20 {
		t.Fatalf("expected >=20 emulated-vuln endpoints, have %d", len(cases))
	}
	for _, c := range cases {
		res := Result{Meta: map[string]any{}}
		out := serveWebapp("GET "+c.path+" HTTP/1.1", nil, "nginx", id, &res)
		if c.wantBody != "" && !strings.Contains(out, c.wantBody) {
			t.Errorf("%s: body missing %q", c.path, c.wantBody)
		}
		if !slices.Contains(anomaliesOf(res), c.anomaly) {
			t.Errorf("%s: anomalies=%v, want %q", c.path, anomaliesOf(res), c.anomaly)
		}
	}
}
